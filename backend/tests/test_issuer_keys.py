"""Regression coverage for POST /issuers/{id}/keys (Stage 2 of the
client-side key custody + versioned keys redesign): the first-key
platform_admin gate, self-service rotation after that, malformed-key
rejection, the step-up re-auth requirement, and the audit trail.
"""
import base64
import sqlite3

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import storage
from db import SCHEMA


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(storage, "OBJECTS_DIR", tmp_path / "objects")
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
    """A freshly-made issuer via a fresh SCHEMA, not init_db() -- no
    _migrate_issuer_keys ever runs against this in-memory test DB, so
    this issuer genuinely has zero issuer_keys rows, exactly like a
    brand-new org onboarded after this redesign (as opposed to an
    existing org migrated from the old platform-held-key model)."""
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


def fresh_public_key_b64() -> str:
    """A real, valid Ed25519 public key -- simulates what a browser's
    SubtleCrypto.exportKey("raw", ...) would hand the server, minus the
    browser (no non-extractable/persistence semantics to fake here,
    only the wire format: base64 of the raw 32-byte point)."""
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")


def login(client, email, password):
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200, resp.text


def test_first_key_registration_requires_platform_admin_not_org_user(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "org@example.com", "pw", "org_user", issuer_id)
    login(client, "org@example.com", "pw")

    resp = client.post(
        f"/issuers/{issuer_id}/keys",
        json={"public_key": fresh_public_key_b64(), "password": "pw"},
    )
    assert resp.status_code == 403
    assert "platform_admin" in resp.json()["detail"]

    # confirm nothing was written
    assert conn.execute("SELECT 1 FROM issuer_keys WHERE issuer_id = ?", (issuer_id,)).fetchone() is None


def test_first_key_registration_succeeds_for_platform_admin(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "adminpw", "platform_admin")
    login(client, "admin@example.com", "adminpw")

    public_key = fresh_public_key_b64()
    resp = client.post(
        f"/issuers/{issuer_id}/keys",
        json={"public_key": public_key, "password": "adminpw"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["issuer_id"] == issuer_id
    assert body["public_key"] == public_key
    assert body["key_id"]

    row = conn.execute(
        "SELECT * FROM issuer_keys WHERE issuer_id = ? AND key_id = ?", (issuer_id, body["key_id"])
    ).fetchone()
    assert row is not None
    assert row["valid_to"] is None
    assert row["revoked_at"] is None
    assert row["registered_by"] == "admin@example.com"


def test_rotation_after_first_key_is_self_service_org_user_not_platform_admin(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "adminpw", "platform_admin")
    make_user(conn, "org@example.com", "pw", "org_user", issuer_id)

    login(client, "admin@example.com", "adminpw")
    first_key = fresh_public_key_b64()
    first_resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": first_key, "password": "adminpw"})
    assert first_resp.status_code == 200
    first_key_id = first_resp.json()["key_id"]
    client.post("/auth/logout")

    # platform_admin cannot perform a SECOND registration for this issuer
    login(client, "admin@example.com", "adminpw")
    resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": fresh_public_key_b64(), "password": "adminpw"})
    assert resp.status_code == 403
    assert "self-service" in resp.json()["detail"]
    client.post("/auth/logout")

    # org_user CAN rotate, self-service, no admin involvement
    login(client, "org@example.com", "pw")
    second_key = fresh_public_key_b64()
    rotate_resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": second_key, "password": "pw"})
    assert rotate_resp.status_code == 200, rotate_resp.text
    second_key_id = rotate_resp.json()["key_id"]

    # exactly one active key afterward, and it's the new one
    active_rows = conn.execute(
        "SELECT key_id FROM issuer_keys WHERE issuer_id = ? AND valid_to IS NULL", (issuer_id,)
    ).fetchall()
    assert [r["key_id"] for r in active_rows] == [second_key_id]

    old_row = conn.execute("SELECT valid_to FROM issuer_keys WHERE issuer_id = ? AND key_id = ?", (issuer_id, first_key_id)).fetchone()
    assert old_row["valid_to"] is not None, "the superseded key must be closed out, not left dangling"


def test_org_user_cannot_register_a_key_for_another_orgs_issuer(client, conn):
    issuer_id = make_issuer(conn, "Target Org")
    other_issuer_id = make_issuer(conn, "Attacker Org")
    make_user(conn, "org@example.com", "pw", "org_user", other_issuer_id)
    login(client, "org@example.com", "pw")

    resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": fresh_public_key_b64(), "password": "pw"})
    assert resp.status_code == 403
    assert conn.execute("SELECT 1 FROM issuer_keys WHERE issuer_id = ?", (issuer_id,)).fetchone() is None


def test_malformed_public_key_is_rejected(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "adminpw", "platform_admin")
    login(client, "admin@example.com", "adminpw")

    for bad_key in ["not-valid-base64!!!", base64.b64encode(b"too short").decode("ascii"), ""]:
        resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": bad_key, "password": "adminpw"})
        assert resp.status_code == 400, f"expected 400 for {bad_key!r}, got {resp.status_code}"

    assert conn.execute("SELECT 1 FROM issuer_keys WHERE issuer_id = ?", (issuer_id,)).fetchone() is None


def test_step_up_reauth_wrong_password_rejected(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "adminpw", "platform_admin")
    login(client, "admin@example.com", "adminpw")

    resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": fresh_public_key_b64(), "password": "wrong-password"})
    assert resp.status_code == 401
    assert conn.execute("SELECT 1 FROM issuer_keys WHERE issuer_id = ?", (issuer_id,)).fetchone() is None


def test_registration_writes_an_audit_log_entry(client, conn):
    issuer_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "adminpw", "platform_admin")
    login(client, "admin@example.com", "adminpw")

    resp = client.post(f"/issuers/{issuer_id}/keys", json={"public_key": fresh_public_key_b64(), "password": "adminpw"})
    key_id = resp.json()["key_id"]

    entry = conn.execute(
        "SELECT * FROM audit_log WHERE entity_type = 'issuer_key' AND entity_id = ?", (key_id,)
    ).fetchone()
    assert entry is not None
    assert entry["action"] == "registered"
    assert entry["actor"] == "admin@example.com"
    assert '"is_first": true' in entry["detail_json"]
