"""Stage 3 of the client-side key custody redesign: two-phase issuance
(POST /credentials/issue/prepare then POST /credentials/issue).

Covers what's specific to this stage: prepare persists nothing, submit
re-derives the payload independently rather than trusting the client's
echo of credential_id/issued_at, and a client that tampers with either
between prepare and submit gets a signature that fails to verify
against the server's own reconstruction -- not silently accepted.
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
from _issuance_helpers import issue_via_api, make_issuer_key
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


def _login_org_user(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    return org_id


BASE_ISSUE_BODY = dict(
    credential_type="collected_scrap_lot",
    subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
    sources=[],
)


def test_prepare_persists_nothing(client, conn):
    org_id = _login_org_user(client, conn)
    make_issuer_key(conn, org_id)

    resp = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["credential_id"]
    assert body["issued_at"]
    assert body["signable_bytes_b64"]

    assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM uii_bindings").fetchone()["n"] == 0


def test_full_round_trip_succeeds_and_records_key_id(client, conn):
    org_id = _login_org_user(client, conn)
    key_id, private_key = make_issuer_key(conn, org_id)

    resp = issue_via_api(client, private_key, key_id, **BASE_ISSUE_BODY)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["key_id"] == key_id

    row = conn.execute("SELECT key_id FROM credentials WHERE id = ?", (body["id"],)).fetchone()
    assert row["key_id"] == key_id


def test_tampering_with_credential_id_between_prepare_and_submit_fails(client, conn):
    """The client signs prepare's original bytes, then submits a
    different credential_id than the one baked into what it signed --
    the server reconstructs the payload using the SUBMITTED id, so the
    signature (computed over the original id) can't verify against it."""
    org_id = _login_org_user(client, conn)
    key_id, private_key = make_issuer_key(conn, org_id)

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(private_key.sign(signable_bytes)).decode("ascii")

    tampered_body = {
        **BASE_ISSUE_BODY,
        "credential_id": "attacker-chosen-id-not-what-was-signed",
        "issued_at": prep_body["issued_at"],
        "key_id": key_id,
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=tampered_body)
    assert resp.status_code == 400, resp.text
    assert "signature" in resp.json()["detail"].lower()
    assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 0


def test_tampering_with_issued_at_between_prepare_and_submit_fails(client, conn):
    org_id = _login_org_user(client, conn)
    key_id, private_key = make_issuer_key(conn, org_id)

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(private_key.sign(signable_bytes)).decode("ascii")

    tampered_body = {
        **BASE_ISSUE_BODY,
        "credential_id": prep_body["credential_id"],
        "issued_at": "2099-01-01T00:00:00+00:00",  # backdated/postdated, not what was signed
        "key_id": key_id,
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=tampered_body)
    assert resp.status_code == 400, resp.text
    assert "signature" in resp.json()["detail"].lower()
    assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 0


def test_tampering_with_subject_between_prepare_and_submit_fails(client, conn):
    """Same principle, a field the client legitimately controls (unlike
    credential_id/issued_at) -- but changing it after signing still
    invalidates the signature, since it's part of the signed payload."""
    org_id = _login_org_user(client, conn)
    key_id, private_key = make_issuer_key(conn, org_id)

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(private_key.sign(signable_bytes)).decode("ascii")

    tampered_body = {
        **BASE_ISSUE_BODY,
        "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "China"},
        "credential_id": prep_body["credential_id"],
        "issued_at": prep_body["issued_at"],
        "key_id": key_id,
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=tampered_body)
    assert resp.status_code == 400, resp.text
    assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 0


def test_signature_from_wrong_key_is_rejected(client, conn):
    """A signature that's internally valid Ed25519 (real key, real
    private key holder) but not the key_id claimed -- proves submit
    verifies against the specific key_id's own public key, not just
    "some" registered key for this issuer."""
    org_id = _login_org_user(client, conn)
    key_id, _real_private_key = make_issuer_key(conn, org_id)
    impostor_private_key = Ed25519PrivateKey.generate()

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(impostor_private_key.sign(signable_bytes)).decode("ascii")

    submit_body = {
        **BASE_ISSUE_BODY,
        "credential_id": prep_body["credential_id"],
        "issued_at": prep_body["issued_at"],
        "key_id": key_id,
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=submit_body)
    assert resp.status_code == 400, resp.text


def test_submit_rejects_superseded_key(client, conn):
    """Issuing NEW credentials must use the issuer's CURRENT active key
    -- a key_id that's still a real, valid entry in issuer_keys but has
    since been rotated away from (valid_to set) must be rejected at
    issuance, distinct from verification's own, more permissive
    "was this key valid at the time" check (Stage 4)."""
    org_id = _login_org_user(client, conn)
    old_key_id, old_private_key = make_issuer_key(conn, org_id, key_id="old-key")
    conn.execute("UPDATE issuer_keys SET valid_to = datetime('now') WHERE issuer_id = ? AND key_id = ?", (org_id, old_key_id))
    conn.commit()
    make_issuer_key(conn, org_id, key_id="new-key")  # the org's real current key

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(old_private_key.sign(signable_bytes)).decode("ascii")

    submit_body = {
        **BASE_ISSUE_BODY,
        "credential_id": prep_body["credential_id"],
        "issued_at": prep_body["issued_at"],
        "key_id": old_key_id,
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=submit_body)
    assert resp.status_code == 400, resp.text
    assert "current active key" in resp.json()["detail"]


def test_submit_rejects_unknown_key_id(client, conn):
    org_id = _login_org_user(client, conn)
    _key_id, private_key = make_issuer_key(conn, org_id)

    prep = client.post("/credentials/issue/prepare", json=BASE_ISSUE_BODY)
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(private_key.sign(signable_bytes)).decode("ascii")

    submit_body = {
        **BASE_ISSUE_BODY,
        "credential_id": prep_body["credential_id"],
        "issued_at": prep_body["issued_at"],
        "key_id": "totally-made-up-key-id",
        "signature_b64": signature_b64,
    }
    resp = client.post("/credentials/issue", json=submit_body)
    assert resp.status_code == 400, resp.text
    assert "unknown key_id" in resp.json()["detail"].lower()
