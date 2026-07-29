"""UII / Data Matrix generation and the binding routes."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import storage
import uii
from db import SCHEMA


def test_generate_datamatrix_png_produces_valid_png():
    png_bytes = uii.generate_datamatrix_png("https://example.com/passport.html?id=abc123")
    assert png_bytes[:8] == b"\x89PNG\r\n\x1a\n"
    assert len(png_bytes) > 100


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


def _issue_credential(client):
    return client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    ).json()


def test_uii_binding_created_at_issuance_and_routes_work(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})

    cred = _issue_credential(client)

    binding_row = conn.execute("SELECT * FROM uii_bindings WHERE credential_id = ?", (cred["id"],)).fetchone()
    assert binding_row is not None
    assert binding_row["uii_code"] == cred["id"]

    binding_resp = client.get(f"/credentials/{cred['id']}/uii")
    assert binding_resp.status_code == 200
    body = binding_resp.json()
    assert body["uii_code"] == cred["id"]
    assert body["passport_url"].endswith(f"/passport.html?id={cred['id']}")

    image_resp = client.get(f"/credentials/{cred['id']}/uii/image")
    assert image_resp.status_code == 200
    assert image_resp.headers["content-type"] == "image/png"
    assert image_resp.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_uii_routes_are_public_no_login_required(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    cred = _issue_credential(client)
    client.post("/auth/logout")

    assert client.get(f"/credentials/{cred['id']}/uii").status_code == 200
    assert client.get(f"/credentials/{cred['id']}/uii/image").status_code == 200


def test_uii_binding_404_for_unknown_credential(client):
    assert client.get("/credentials/does-not-exist/uii").status_code == 404
    assert client.get("/credentials/does-not-exist/uii/image").status_code == 404
