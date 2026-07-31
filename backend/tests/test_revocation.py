"""Revoke/reissue lifecycle: a field correction landing on a heat that
already has an issued credential auto-revokes that credential (any
field — see the design note in main.py's _revoke_stale_credential),
the passport verdict for a revoked credential reads 'revoked' rather
than a stale 'pass' or a generic 'fail', reissuing via the existing
/credentials/issue endpoint wires superseded_by both directions, and a
revoked credential remains fully auditable (including its originating
heat) after it's been superseded. Also covers the live-graph-walk
cascade: a composite credential sourcing a revoked one reflects that
without any dedicated cascade logic.

Same TestClient + dependency-override pattern as test_heats.py /
test_corrections.py.
"""
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


def _login_org_user(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    return org_id


def _upload_review_issue(client, filename="mtr.txt", mass_kg=50.0, origin_country="United States"):
    """Upload -> review (clean, high-confidence sublot) -> issue.
    Returns (document_id, heat_id, credential_id)."""
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
            "sublots": [{"origin_country": origin_country, "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    issued = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {
                "material_type": "Sintered NdFeB Magnet Alloy (N42)",
                "origin_country": origin_country,
                "mass_kg": mass_kg,
                "heat_number": "TR-0001",
            },
            "sources": [],
        },
    )
    assert issued.status_code == 200, issued.text
    return doc_id, heat_id, issued.json()["id"]


# --- auto-revoke on correction ------------------------------------------------


def test_correcting_heat_field_on_credentialed_heat_revokes_credential(client, conn):
    _login_org_user(client, conn)
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    assert resp.status_code == 200

    trail = client.get(f"/credentials/{cred_id}/audit-trail").json()
    assert trail["revoked_at"] is not None
    revoked_entry = next(e for e in trail["audit_log"] if e["action"] == "revoked")
    assert revoked_entry["actor"] == "u@example.com"
    assert "mass_kg" in revoked_entry["detail"]["reason"]


def test_correcting_sublot_field_on_credentialed_heat_revokes_credential(client, conn):
    """Any field, not just ones that map onto the credential's signed
    subject — the deliberate design choice (subject is free-typed at
    issuance, not schema-validated against heat/sub-lot fields, so
    there's no reliable way to know which corrections 'mattered')."""
    _login_org_user(client, conn)
    doc_id, heat_id, cred_id = _upload_review_issue(client)
    heat = client.get(f"/documents/{doc_id}").json()["heats"][0]
    sublot_id = heat["sublots"][0]["id"]

    # `notes` has no analogue in the credential's subject dict at all —
    # still revokes, per the "any correction" policy.
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "sublot", "sublot_id": sublot_id, "field_name": "notes", "corrected_value": "re-weighed on 2026-07-30"},
    )
    assert resp.status_code == 200

    trail = client.get(f"/credentials/{cred_id}/audit-trail").json()
    assert trail["revoked_at"] is not None


def test_correction_revocation_is_idempotent(client, conn):
    _login_org_user(client, conn)
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    first_trail = client.get(f"/credentials/{cred_id}/audit-trail").json()
    first_revoked_at = first_trail["revoked_at"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "60.0"},
    )
    second_trail = client.get(f"/credentials/{cred_id}/audit-trail").json()

    assert second_trail["revoked_at"] == first_revoked_at
    revoked_entries = [e for e in second_trail["audit_log"] if e["action"] == "revoked"]
    assert len(revoked_entries) == 1


def test_correction_on_uncredentialed_heat_does_not_touch_credentials(client, conn):
    _login_org_user(client, conn)
    upload = client.post(
        "/documents/upload",
        files={"file": ("mtr.txt", MTR_TEXT.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    ).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    assert resp.status_code == 200
    assert conn.execute("SELECT COUNT(*) AS n FROM credentials").fetchone()["n"] == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM audit_log WHERE entity_type = 'credential'").fetchone()["n"] == 0


# --- passport verdict for a revoked credential --------------------------------


def test_revoked_credential_passport_shows_revoked_not_stale_pass(client, conn):
    _login_org_user(client, conn)
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    before = client.get(f"/passport/{cred_id}").json()
    assert before["verdict"] == "pass"

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )

    after = client.get(f"/passport/{cred_id}").json()
    assert after["verdict"] == "revoked"
    assert after["nodes"][0]["node_status"] == "revoked"
    assert any("revoked" in r for r in after["reasons"])


# --- reissue via /credentials/issue -------------------------------------------


def test_reissue_blocked_while_credential_still_active(client, conn):
    _login_org_user(client, conn)
    doc_id, heat_id, cred_id = _upload_review_issue(client)

    resp = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert resp.status_code == 409


def test_reissue_allowed_after_revocation_and_wires_supersession(client, conn):
    _login_org_user(client, conn)
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
    assert reissued.status_code == 200
    new_cred_id = reissued.json()["id"]
    assert reissued.json()["heat_id"] == heat_id
    assert new_cred_id != cred_id

    old_row = conn.execute("SELECT superseded_by, revoked_at FROM credentials WHERE id = ?", (cred_id,)).fetchone()
    assert old_row["superseded_by"] == new_cred_id

    heat_row = conn.execute("SELECT credential_id FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    assert heat_row["credential_id"] == new_cred_id

    # the new credential is active — issuing a third time is blocked
    # exactly like the very first re-issue attempt would have been
    third = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert third.status_code == 409


def test_old_credential_audit_trail_survives_supersession(client, conn):
    """credentials.heat_id (permanent) is what makes this work — the
    heat's document_heats.credential_id now points at the new
    credential, so a lookup keyed off that column would have lost the
    old credential's provenance the moment it was superseded."""
    _login_org_user(client, conn)
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
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States", "mass_kg": 55.0},
            "sources": [],
        },
    )
    new_cred_id = reissued.json()["id"]

    old_trail = client.get(f"/credentials/{cred_id}/audit-trail").json()
    assert old_trail["heat"] is not None
    assert old_trail["heat"]["id"] == heat_id
    assert old_trail["superseded_by"] == new_cred_id
    heat_actions = [e["action"] for e in old_trail["heat_audit_log"]]
    assert "field_corrected" in heat_actions
    assert "reviewed" in heat_actions

    new_trail = client.get(f"/credentials/{new_cred_id}/audit-trail").json()
    assert new_trail["supersedes"]["id"] == cred_id
    assert new_trail["supersedes"]["revoked_at"] is not None
    issued_entry = next(e for e in new_trail["audit_log"] if e["action"] == "issued")
    assert issued_entry["detail"]["supersedes"] == cred_id


def test_reissue_requires_org_match(client, conn):
    org_a = make_issuer(conn, "Org A")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    org_b = make_issuer(conn, "Org B")
    make_user(conn, "b@example.com", "pw", "org_user", org_b)

    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    doc_id, heat_id, cred_id = _upload_review_issue(client)
    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "b@example.com", "password": "pw"})
    resp = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert resp.status_code == 403


# --- graph cascade: no dedicated logic needed, the live walk handles it -------


def test_composite_credential_sourcing_revoked_credential_shows_revoked(client, conn):
    _login_org_user(client, conn)
    doc_id, heat_id, component_id = _upload_review_issue(client)

    composite = client.post(
        "/credentials/issue",
        json={
            "credential_type": "sintered_ndfeb_batch",
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [component_id],
        },
    )
    assert composite.status_code == 200
    composite_id = composite.json()["id"]

    before = client.get(f"/passport/{composite_id}").json()
    assert before["verdict"] == "pass"

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )

    after = client.get(f"/passport/{composite_id}").json()
    assert after["verdict"] == "revoked"
    component_node = next(n for n in after["nodes"] if n["credential_id"] == component_id)
    assert component_node["node_status"] == "revoked"
    composite_node = next(n for n in after["nodes"] if n["credential_id"] == composite_id)
    assert composite_node["node_status"] == "pass"  # the composite itself was never touched
