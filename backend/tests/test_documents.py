"""Upload pipeline integration: object storage + extraction wiring, via the
same TestClient + dependency-override pattern as test_auth.py. No API key
is present in this environment, so extraction runs the deterministic regex
fallback — this is what keeps the suite offline and free.
"""
import hashlib
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import storage
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


def _upload(client, filename="mtr.txt"):
    return client.post(
        "/documents/upload",
        files={"file": (filename, MTR_TEXT.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    )


def test_upload_stores_object_and_content_hash(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})

    resp = _upload(client)
    assert resp.status_code == 200
    doc_id = resp.json()["id"]

    row = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    assert row["object_key"] == f"{doc_id}/mtr.txt"
    assert row["content_hash"] == hashlib.sha256(MTR_TEXT.encode()).hexdigest()
    assert storage.read_object(row["object_key"]) == MTR_TEXT.encode()


def test_upload_extraction_falls_back_to_regex_without_api_key(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})

    resp = _upload(client)
    fields = resp.json()["extracted_fields"]
    supplier = next(f for f in fields if f["field_name"] == "supplier_name")
    assert supplier["field_value"] == "Test Recycler, LLC"
    assert supplier["source"] == "regex"

    row = conn.execute(
        "SELECT extraction_source FROM extracted_fields WHERE document_id = ? AND field_name = 'supplier_name'",
        (resp.json()["id"],),
    ).fetchone()
    assert row["extraction_source"] == "regex"


def test_extraction_stats_reflects_overrides(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    make_user(conn, "u@example.com", "pw", "org_user", org_id)

    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    upload = _upload(client).json()

    fields = [{"field_name": f["field_name"], "field_value": f["field_value"]} for f in upload["extracted_fields"]]
    for f in fields:
        if f["field_name"] == "supplier_name":
            f["field_value"] = "Corrected Name, LLC"
    client.post(f"/documents/{upload['id']}/review", json={"fields": fields})
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "admin@example.com", "password": "pw"})
    stats = client.get("/admin/extraction-stats").json()

    regex_overall = next(r for r in stats["overall"] if r["extraction_source"] == "regex")
    assert regex_overall["total"] >= 5
    assert regex_overall["overridden"] >= 1

    supplier_stat = next(
        r for r in stats["by_field"] if r["field_name"] == "supplier_name" and r["extraction_source"] == "regex"
    )
    assert supplier_stat["overridden"] == 1


def test_extraction_stats_requires_platform_admin(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})

    resp = client.get("/admin/extraction-stats")
    assert resp.status_code == 403
