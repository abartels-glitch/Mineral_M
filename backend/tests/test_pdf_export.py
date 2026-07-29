"""PDF export — unit test of the renderer plus a route-level round trip
that re-opens the generated PDF with PyMuPDF (already a dependency) to
confirm the actual content, not just that *a* PDF came back."""
import sqlite3

import fitz
import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import pdf_export
import storage
from db import SCHEMA


def test_render_passport_pdf_contains_key_content():
    result = {
        "credential_id": "abc123",
        "verdict": "pass",
        "reasons": ["all credentials in the graph passed every check"],
        "nodes": [
            {
                "credential_id": "abc123",
                "credential_type": "sintered_ndfeb_batch",
                "material_type": "Sintered NdFeB Magnet Alloy (N42)",
                "origin_country": "United States",
                "node_status": "pass",
                "reasons": ["all checks passed"],
            }
        ],
    }
    pdf_bytes = pdf_export.render_passport_pdf(result)

    assert pdf_bytes[:5] == b"%PDF-"
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        # Long cell text legitimately wraps across lines now that cells are
        # Paragraphs (the whole point of the earlier overflow fix) — collapse
        # whitespace so wrapped text still matches as one contiguous string.
        text = " ".join(" ".join(page.get_text().split()) for page in doc)
    assert "abc123" in text
    assert "PASS" in text
    assert "Sintered NdFeB Magnet Alloy (N42)" in text


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


def test_passport_pdf_route_returns_valid_pdf(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    cred = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    ).json()
    client.post("/auth/logout")

    resp = client.get(f"/passport/{cred['id']}/pdf")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content[:5] == b"%PDF-"

    with fitz.open(stream=resp.content, filetype="pdf") as doc:
        text = "\n".join(page.get_text() for page in doc)
    assert cred["id"] in text
    assert "PASS" in text


def test_passport_pdf_404_for_unknown_credential(client):
    resp = client.get("/passport/does-not-exist/pdf")
    assert resp.status_code == 404
