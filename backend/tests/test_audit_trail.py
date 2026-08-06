"""GET /credentials/{id}/audit-trail — access scoping (org_user own-org
only, buyer_auditor/platform_admin cross-org) and content correctness."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import storage
from _issuance_helpers import issue_via_api, make_issuer_key
from db import SCHEMA

MTR_TEXT = (
    "CERTIFICATE OF CONFORMANCE / MILL TEST REPORT\n"
    "Supplier: Test Recycler, LLC\n"
    "Heat Number: TR-0001\n"
    "Material: Sintered NdFeB Magnet Alloy (N42)\n"
    "Country of Origin: United States\n"
    "Batch Mass: 50.0 kg\n"
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(storage, "OBJECTS_DIR", tmp_path / "objects")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.executescript(SCHEMA)
    yield c
    c.close()


@pytest.fixture
def client(conn):
    def override_get_db():
        yield conn

    main.app.dependency_overrides[main.get_db] = override_get_db
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def make_issuer(conn, name="Test Org"):
    issuer_id = "issuer-" + name.lower().replace(" ", "-")
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, name, public_key_b64, private_key_path, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return issuer_id


def make_user(conn, email, password, role, org_id=None):
    user_id = "user-" + email.split("@")[0]
    conn.execute(
        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, org_id, email, auth.hash_password(password), role, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return user_id


def _issue_bare_credential(client, conn, org_id):
    key_id, private_key = make_issuer_key(conn, org_id)
    return issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
        sources=[],
    ).json()


def test_requires_login(client):
    resp = client.get("/credentials/does-not-matter/audit-trail")
    assert resp.status_code == 401


def test_404_for_unknown_credential(client, conn):
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    client.post("/auth/login", json={"email": "admin@example.com", "password": "pw"})
    resp = client.get("/credentials/does-not-exist/audit-trail")
    assert resp.status_code == 404


def test_org_user_cannot_see_other_orgs_trail(client, conn):
    org_a = make_issuer(conn, "Org A")
    org_b = make_issuer(conn, "Org B")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    make_user(conn, "b@example.com", "pw", "org_user", org_b)

    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    cred = _issue_bare_credential(client, conn, org_a)
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "b@example.com", "password": "pw"})
    resp = client.get(f"/credentials/{cred['id']}/audit-trail")
    assert resp.status_code == 403


def test_org_user_sees_own_trail(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    cred = _issue_bare_credential(client, conn, org_id)

    resp = client.get(f"/credentials/{cred['id']}/audit-trail")
    assert resp.status_code == 200
    body = resp.json()
    actions = [e["action"] for e in body["audit_log"]]
    assert "issued" in actions


@pytest.mark.parametrize("role,org_id", [("buyer_auditor", None), ("platform_admin", None)])
def test_cross_org_roles_see_any_trail(client, conn, role, org_id):
    org_a = make_issuer(conn, "Org A")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    make_user(conn, f"reader-{role}@example.com", "pw", role, org_id)

    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    cred = _issue_bare_credential(client, conn, org_a)
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": f"reader-{role}@example.com", "password": "pw"})
    resp = client.get(f"/credentials/{cred['id']}/audit-trail")
    assert resp.status_code == 200


def test_document_history_and_heat_provenance(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    key_id, private_key = make_issuer_key(conn, org_id)

    upload = client.post(
        "/documents/upload",
        files={"file": ("mtr.txt", MTR_TEXT.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    ).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0},
            "mass_kg": 50.0,
            "sublots": [
                {"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}
            ],
        },
    )

    cred = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        heat_id=heat_id,
        subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
        sources=[],
    ).json()

    resp = client.get(f"/credentials/{cred['id']}/audit-trail")
    assert resp.status_code == 200
    body = resp.json()

    doc_actions = [e["action"] for e in body["document_audit_log"]]
    assert doc_actions == ["uploaded", "extracted"]

    heat = body["heat"]
    assert heat["reviewed"] is True
    assert heat["source"] == "human"
    assert heat["extraction_source"] == "regex"
    assert heat["alloy_composition"] == {"Nd": 29.5, "Fe": 68.2, "B": 1.0}
    assert heat["sublots"][0]["origin_country"] == "United States"
    assert heat["sublots"][0]["flagged"] is False
