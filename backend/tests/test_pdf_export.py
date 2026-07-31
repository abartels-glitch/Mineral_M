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


def make_issuer(conn, name="Test Org", iac=None, enterprise_id=None):
    issuer_id = "issuer-" + name.lower().replace(" ", "-")
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        """
        INSERT INTO issuers (id, name, public_key, private_key_path, iac, enterprise_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (issuer_id, name, public_key_b64, private_key_path, iac, enterprise_id, "2026-01-01T00:00:00Z"),
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


# --- Chain-of-custody section (issuer identity, issuance, revocation chain) -

MTR_TEXT = (
    "CERTIFICATE OF CONFORMANCE / MILL TEST REPORT\n"
    "Supplier: Test Recycler, LLC\n"
    "Heat Number: TR-0001\n"
    "Material: Sintered NdFeB Magnet Alloy (N42)\n"
    "Country of Origin: United States\n"
    "Batch Mass: 50.0 kg\n"
)


def _pdf_text(pdf_bytes: bytes) -> str:
    with fitz.open(stream=pdf_bytes, filetype="pdf") as doc:
        return " ".join(" ".join(page.get_text().split()) for page in doc)


def _upload_review_issue(client, filename="mtr.txt", mass_kg=50.0):
    """Upload -> review -> issue a single-heat credential. Returns
    (document_id, heat_id, credential_id) — same shape as
    test_revocation.py's helper, so the source heat can be corrected
    afterward to trigger auto-revocation."""
    upload = client.post(
        "/documents/upload",
        files={"file": (filename, MTR_TEXT.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    ).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]
    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": mass_kg,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    issued = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {
                "material_type": "Sintered NdFeB Magnet Alloy (N42)",
                "origin_country": "United States",
                "mass_kg": mass_kg,
                "heat_number": "TR-0001",
            },
            "sources": [],
        },
    )
    assert issued.status_code == 200, issued.text
    return doc_id, heat_id, issued.json()["id"]


def test_pdf_normal_pass_shows_issuer_identity_and_issuance_no_revocation(client, conn):
    org_id = make_issuer(conn, iac="UN", enterprise_id="123456789")
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

    resp = client.get(f"/passport/{cred['id']}/pdf")
    text = _pdf_text(resp.content)

    assert "Issued by Test Org (IAC UN, Enterprise ID 123456789) on" in text
    assert cred["issued_at"] in text
    assert "REVOKED" not in text
    assert "superseding credential" not in text


def test_pdf_revoked_no_successor_shows_revoked_block(client, conn):
    org_id = make_issuer(conn, iac="UN", enterprise_id="123456789")
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )

    resp = client.get(f"/passport/{cred_id}/pdf")
    text = _pdf_text(resp.content)

    assert "REVOKED on" in text
    assert "source heat data corrected: heat field 'mass_kg'" in text
    assert "No superseding credential has been issued yet." in text


def test_pdf_revoked_with_successor_shows_successor_id_and_uii(client, conn):
    org_id = make_issuer(conn, iac="UN", enterprise_id="123456789")
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    reissued = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {
                "material_type": "Sintered NdFeB Magnet Alloy (N42)",
                "origin_country": "United States",
                "mass_kg": 55.0,
                "heat_number": "TR-0001",
            },
            "sources": [],
        },
    )
    successor_id = reissued.json()["id"]
    successor_uii = client.get(f"/credentials/{successor_id}/uii").json()["uii_code"]

    resp = client.get(f"/passport/{cred_id}/pdf")
    text = _pdf_text(resp.content)

    assert f"Superseded by credential {successor_id[:12]}" in text
    assert successor_uii in text
    assert "see that credential for the current valid record" in text


def test_pdf_footer_includes_passport_url_for_this_credential(client, conn):
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

    resp = client.get(f"/passport/{cred['id']}/pdf")
    text = _pdf_text(resp.content)

    assert "Full audit history, including reviewer actions and field corrections, is available via passport lookup at" in text
    assert f"passport.html?id={cred['id']}" in text


def test_pdf_excludes_reviewer_identity_and_field_level_correction_detail(client, conn):
    """Regression for the explicit exclusion list: reviewer identity and
    individual correction history (previous/corrected values) must not
    leak into the PDF, even though the revocation *reason* text (which
    names the corrected field, not who corrected it or what the values
    were) legitimately does appear. Checked against actual rendered
    text, not just the manually-reviewed sample from before."""
    org_id = make_issuer(conn, iac="UN", enterprise_id="123456789")
    make_user(conn, "maria.alvarez@riograndemagnetics.example", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "maria.alvarez@riograndemagnetics.example", "password": "pw"})
    doc_id, heat_id, cred_id = _upload_review_issue(client, mass_kg=410.0)

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "405.0"},
    )

    resp = client.get(f"/passport/{cred_id}/pdf")
    text = _pdf_text(resp.content)

    # sanity: this really is the revoked-credential PDF we think it is
    assert "REVOKED on" in text
    # the field name in the reason text is fine/expected — the reviewer
    # identity and the specific before/after values are not
    assert "maria" not in text.lower()
    assert "riograndemagnetics" not in text.lower()
    assert "410.0" not in text
    assert "405.0" not in text
