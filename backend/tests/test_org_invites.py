"""Invite-based org onboarding: POST /admin/invites, GET /invite/{token},
POST /invite/{token}/accept. Same TestClient + dependency-override
pattern as test_auth.py/test_heats.py.
"""
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
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


def make_issuer(conn, name="Existing Org"):
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


def _login_admin(client, conn):
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    resp = client.post("/auth/login", json={"email": "admin@example.com", "password": "pw"})
    assert resp.status_code == 200
    return resp


def test_non_admin_cannot_create_invite(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    resp = client.post("/admin/invites", json={"email": "new@supplier.com", "new_org_name": "New Supplier Co"})
    assert resp.status_code == 403


def test_invite_requires_exactly_one_of_org_id_or_new_org_name(client, conn):
    _login_admin(client, conn)
    resp = client.post("/admin/invites", json={"email": "a@b.com"})
    assert resp.status_code == 400
    org_id = make_issuer(conn)
    resp = client.post("/admin/invites", json={"email": "a@b.com", "org_id": org_id, "new_org_name": "X"})
    assert resp.status_code == 400


def test_new_org_invite_creates_issuer_with_zero_active_keys(client, conn):
    """The org must start with no issuer_keys rows -- register_issuer_key's
    existing "first key needs platform_admin" check (main.py) depends on
    that to fire correctly for a brand-new org, same as any other org."""
    _login_admin(client, conn)
    resp = client.post("/admin/invites", json={"email": "maria@newco.com", "new_org_name": "New Supplier Co"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["org_name"] == "New Supplier Co"
    assert body["invite_url"].startswith("/accept-invite.html?token=")

    org_row = conn.execute("SELECT * FROM issuers WHERE id = ?", (body["org_id"],)).fetchone()
    assert org_row is not None
    key_count = conn.execute(
        "SELECT COUNT(*) AS n FROM issuer_keys WHERE issuer_id = ?", (body["org_id"],)
    ).fetchone()["n"]
    assert key_count == 0


def test_invite_for_existing_org(client, conn):
    org_id = make_issuer(conn, "Rio Grande Magnetics")
    _login_admin(client, conn)
    resp = client.post("/admin/invites", json={"email": "second@riograndemagnetics.example", "org_id": org_id})
    assert resp.status_code == 200
    assert resp.json()["org_id"] == org_id
    assert resp.json()["org_name"] == "Rio Grande Magnetics"


def test_invite_for_nonexistent_org_404s(client, conn):
    _login_admin(client, conn)
    resp = client.post("/admin/invites", json={"email": "a@b.com", "org_id": "does-not-exist"})
    assert resp.status_code == 404


def _extract_token(invite_url: str) -> str:
    return invite_url.split("token=", 1)[1]


def test_preview_and_accept_invite_end_to_end(client, conn):
    _login_admin(client, conn)
    create_resp = client.post("/admin/invites", json={"email": "maria@newco.com", "new_org_name": "New Supplier Co"})
    token = _extract_token(create_resp.json()["invite_url"])
    org_id = create_resp.json()["org_id"]

    # Preview is public -- a fresh, logged-out client.
    anon = TestClient(main.app)
    preview = anon.get(f"/invite/{token}")
    assert preview.status_code == 200
    assert preview.json() == {
        "org_name": "New Supplier Co",
        "email": "maria@newco.com",
        "expires_at": create_resp.json()["expires_at"],
    }

    accept = anon.post(f"/invite/{token}/accept", json={"password": "a-real-password"})
    assert accept.status_code == 200
    assert accept.json()["org_id"] == org_id
    assert accept.json()["role"] == "org_user"
    assert accept.json()["email"] == "maria@newco.com"
    assert "session_token" in accept.cookies

    # The new account can actually log in with the password it set.
    login_resp = TestClient(main.app).post("/auth/login", json={"email": "maria@newco.com", "password": "a-real-password"})
    assert login_resp.status_code == 200
    assert login_resp.json()["org_id"] == org_id


def test_accept_invite_is_single_use(client, conn):
    _login_admin(client, conn)
    create_resp = client.post("/admin/invites", json={"email": "maria@newco.com", "new_org_name": "New Supplier Co"})
    token = _extract_token(create_resp.json()["invite_url"])

    anon = TestClient(main.app)
    first = anon.post(f"/invite/{token}/accept", json={"password": "pw-one"})
    assert first.status_code == 200

    second = TestClient(main.app).post(f"/invite/{token}/accept", json={"password": "pw-two"})
    assert second.status_code == 400


def test_expired_invite_is_rejected(client, conn):
    """Directly seeds an already-expired org_invites row -- bypassing the
    HTTP endpoint to simulate time passing, same spirit as
    _issuance_helpers.make_issuer_key bypassing key registration."""
    org_id = make_issuer(conn)
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    conn.execute(
        """
        INSERT INTO org_invites (id, org_id, email, role, token_hash, invited_by, created_at, expires_at)
        VALUES ('inv-1', ?, 'late@example.com', 'org_user', ?, 'admin@example.com', ?, ?)
        """,
        (org_id, auth.hash_invite_token("expired-raw-token"), past, past),
    )
    conn.commit()

    anon = TestClient(main.app)
    preview = anon.get("/invite/expired-raw-token")
    assert preview.status_code == 400

    accept = anon.post("/invite/expired-raw-token/accept", json={"password": "pw"})
    assert accept.status_code == 400


def test_accept_invite_for_email_that_already_has_an_account_conflicts(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "maria@newco.com", "existing-pw", "org_user", org_id)
    _login_admin(client, conn)
    create_resp = client.post("/admin/invites", json={"email": "maria@newco.com", "org_id": org_id})
    token = _extract_token(create_resp.json()["invite_url"])

    anon = TestClient(main.app)
    resp = anon.post(f"/invite/{token}/accept", json={"password": "new-pw"})
    assert resp.status_code == 409


def test_unknown_invite_token_404s(client, conn):
    anon = TestClient(main.app)
    assert anon.get("/invite/not-a-real-token").status_code == 404
    assert anon.post("/invite/not-a-real-token/accept", json={"password": "pw"}).status_code == 404
