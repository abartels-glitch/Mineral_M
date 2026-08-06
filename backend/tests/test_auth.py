"""Auth tests: password hashing, sessions, login/logout, and the
authorization rules on top of the existing document/credential routes.

Uses FastAPI's TestClient against an in-memory DB swapped in via
`app.dependency_overrides[db.get_db]` — the same shared dependency
`auth.get_current_user` uses, so overriding it once covers every route.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
from _issuance_helpers import issue_via_api, make_issuer_key
from db import SCHEMA


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
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


# --- password hashing / sessions (unit-level, no HTTP) ----------------------


def test_password_hash_roundtrip():
    hashed = auth.hash_password("correct horse battery staple")
    assert auth.verify_password("correct horse battery staple", hashed)
    assert not auth.verify_password("wrong password", hashed)


def test_expired_session_is_rejected(conn):
    org_id = make_issuer(conn)
    user_id = make_user(conn, "expired@example.com", "pw", "org_user", org_id)
    raw_token = auth.create_session(conn, user_id)
    # Force it into the past.
    conn.execute(
        "UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE user_id = ?", (user_id,)
    )
    conn.commit()
    assert auth.get_session_user(conn, raw_token) is None


def test_unknown_token_returns_none(conn):
    assert auth.get_session_user(conn, "not-a-real-token") is None


# --- login / logout / me -----------------------------------------------------


def test_login_success_sets_cookie_and_me_reflects_user(client, conn):
    org_id = make_issuer(conn, "Rio Grande Magnetics")
    make_user(conn, "maria@example.com", "hunter2", "org_user", org_id)

    resp = client.post("/auth/login", json={"email": "maria@example.com", "password": "hunter2"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "maria@example.com"
    assert body["role"] == "org_user"
    assert body["org_name"] == "Rio Grande Magnetics"
    assert "session_token" in resp.cookies

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "maria@example.com"


def test_login_wrong_password_rejected(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "maria@example.com", "hunter2", "org_user", org_id)

    resp = client.post("/auth/login", json={"email": "maria@example.com", "password": "wrong"})
    assert resp.status_code == 401
    assert "session_token" not in resp.cookies


def test_me_without_cookie_is_401(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_logout_clears_session(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "maria@example.com", "hunter2", "org_user", org_id)
    client.post("/auth/login", json={"email": "maria@example.com", "password": "hunter2"})
    assert client.get("/auth/me").status_code == 200

    logout = client.post("/auth/logout")
    assert logout.status_code == 200
    assert client.get("/auth/me").status_code == 401


# --- authorization on document/credential routes -----------------------------


def test_upload_requires_login(client):
    resp = client.post(
        "/documents/upload",
        files={"file": ("t.txt", b"Supplier: X\n", "text/plain")},
        data={"document_type": "mtr_coc"},
    )
    assert resp.status_code == 401


def test_buyer_auditor_cannot_upload(client, conn):
    make_user(conn, "auditor@example.com", "pw", "buyer_auditor", org_id=None)
    client.post("/auth/login", json={"email": "auditor@example.com", "password": "pw"})

    resp = client.post(
        "/documents/upload",
        files={"file": ("t.txt", b"Supplier: X\n", "text/plain")},
        data={"document_type": "mtr_coc"},
    )
    assert resp.status_code == 403


def test_org_user_cannot_read_another_orgs_document(client, conn):
    org_a = make_issuer(conn, "Org A")
    org_b = make_issuer(conn, "Org B")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    make_user(conn, "b@example.com", "pw", "org_user", org_b)

    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    upload = client.post(
        "/documents/upload",
        files={"file": ("t.txt", b"Supplier: A Corp\nMaterial: NdFeB\nCountry of Origin: United States\n", "text/plain")},
        data={"document_type": "mtr_coc"},
    )
    assert upload.status_code == 200
    doc_id = upload.json()["id"]
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "b@example.com", "password": "pw"})
    resp = client.get(f"/documents/{doc_id}")
    assert resp.status_code == 403

    doc_list = client.get("/documents").json()
    assert all(d["id"] != doc_id for d in doc_list)


def test_credential_issue_uses_session_org_not_client_supplied(client, conn):
    org_id = make_issuer(conn, "Rio Grande Magnetics")
    make_user(conn, "maria@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "maria@example.com", "password": "pw"})
    key_id, private_key = make_issuer_key(conn, org_id)

    resp = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
        sources=[],
    )
    assert resp.status_code == 200
    assert resp.json()["issuer_id"] == org_id


def test_admin_can_create_user_org_user_cannot(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    make_user(conn, "user@example.com", "pw", "org_user", org_id)

    client.post("/auth/login", json={"email": "user@example.com", "password": "pw"})
    denied = client.post(
        "/admin/users", json={"email": "new@example.com", "password": "pw2", "role": "org_user", "org_id": org_id}
    )
    assert denied.status_code == 403
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "admin@example.com", "password": "pw"})
    allowed = client.post(
        "/admin/users", json={"email": "new@example.com", "password": "pw2", "role": "org_user", "org_id": org_id}
    )
    assert allowed.status_code == 200
    assert allowed.json()["email"] == "new@example.com"


def test_passport_lookup_requires_no_auth(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "maria@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "maria@example.com", "password": "pw"})
    key_id, private_key = make_issuer_key(conn, org_id)
    issued = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
        sources=[],
    ).json()
    client.post("/auth/logout")

    resp = client.get(f"/passport/{issued['id']}")
    assert resp.status_code == 200
    # Not asserting verdict == "pass" here: passport.py's verification
    # (_evaluate_node) is unchanged until Stage 4, so it still checks a
    # credential's signature against issuers.public_key -- not the
    # issuer_keys row this credential was actually signed with. That's
    # the exact, expected, temporary gap the plan calls out (Stage 4
    # "must not go live until both Stage 2 and Stage 3 are confirmed
    # working"); this test's real subject is auth, not signature
    # freshness, so it only needs the lookup to succeed without a
    # session.
    assert "verdict" in resp.json()
