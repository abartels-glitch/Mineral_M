"""Regression coverage for correcting the two object-typed heat fields,
alloy_composition and test_results, via POST .../correct.

Before this fix, a flag targeting either field could never actually be
corrected in place: _HEAT_CORRECTABLE_FIELDS only listed heat_id/mass_kg,
so the endpoint 400'd unconditionally, and the frontend's correction
panel rendered a read-only view with a "redirect to the Found section"
note instead of a working save path -- the practical shape of the
[object Object] bug this session already partially fixed at the display
layer only. This is the backend half: a real, working, atomic correction
for these two fields.

Same TestClient + dependency-override pattern as test_corrections.py.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import llm_extractor
import main
import storage
from _issuance_helpers import issue_via_api, make_issuer_key
from db import SCHEMA


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


def _upload_mocked(client, monkeypatch, heats):
    def fake_extract_structured(raw_text, org_cfg=None):
        return {"certificate_id": "CERT-1", "supplier_id": "Rio Grande Magnetics, LLC", "signatures": [], "heats": heats}

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    return client.post(
        "/documents/upload",
        files={"file": ("complex.txt", b"irrelevant, extraction is mocked", "text/plain")},
        data={"document_type": "mtr_coc"},
    )


def _ambiguous_composition_heat():
    return {
        "heat_id": "H-1",
        "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": None, "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 182.5,
        "confidence": 0.8,
        "flags": [
            {
                "issue_type": "ambiguous_field",
                "field_name": "alloy_composition",
                "severity": "needs_review",
                "human_readable_reason": "Dysprosium content is hedged in the source text.",
                "source": "extraction",
            }
        ],
        "source": "llm",
    }


def _missing_test_results_heat():
    return {
        "heat_id": "H-2",
        "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": None, "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 60.0,
        "confidence": 0.8,
        "flags": [
            {
                "issue_type": "missing_field",
                "field_name": "test_results",
                "severity": "needs_review",
                "human_readable_reason": "No test results reported on the certificate.",
                "source": "extraction",
            }
        ],
        "source": "llm",
    }


# --- alloy_composition --------------------------------------------------


def test_correct_alloy_composition_resolves_matching_flag(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_ambiguous_composition_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    flag = next(f for f in heat["flags"] if f["field_name"] == "alloy_composition")
    assert flag["status"] == "open"

    corrected = {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.4}
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "heat", "field_name": "alloy_composition", "corrected_value": corrected},
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["alloy_composition"] == corrected
    assert updated["source"] == "human"

    resolved = next(f for f in updated["flags"] if f["field_name"] == "alloy_composition")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_by"] == "u@example.com"
    assert len(updated["flags"]) == len(heat["flags"])  # kept, not deleted
    assert updated["fully_addressed"] is True

    trail = client.get(f"/documents/{doc_id}/heats/{heat['id']}/audit-trail").json()
    entry = next(e for e in trail if e["action"] == "field_corrected")
    assert entry["detail"]["previous_value"] == {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3}
    assert entry["detail"]["corrected_value"] == corrected


def test_correct_alloy_composition_rejects_non_object_value(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_ambiguous_composition_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "alloy_composition", "corrected_value": "not an object"},
    )
    assert resp.status_code == 400


# --- test_results ---------------------------------------------------------


def test_correct_test_results_resolves_matching_flag(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_test_results_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    assert heat["test_results"] is None
    flag = next(f for f in heat["flags"] if f["field_name"] == "test_results")
    assert flag["status"] == "open"

    corrected = {"Br_kG": {"value": 13.2, "result": "pass"}, "Hci_kOe": {"value": 11.5, "result": "pass"}}
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "heat", "field_name": "test_results", "corrected_value": corrected},
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    assert updated["test_results"] == corrected

    resolved = next(f for f in updated["flags"] if f["field_name"] == "test_results")
    assert resolved["status"] == "resolved"
    assert updated["fully_addressed"] is True


def test_correct_test_results_revokes_issued_credential(client, conn, monkeypatch):
    """Same auto-revoke guarantee every other heat-field correction
    already has (_revoke_stale_credential fires unconditionally on
    field_name, not a hardcoded scalar-fields list)."""
    org_id = _login_org_user(client, conn)
    key_id, private_key = make_issuer_key(conn, org_id)
    upload = _upload_mocked(client, monkeypatch, [_missing_test_results_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "H-2",
            "mass_kg": 60.0,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    issued = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        heat_id=heat_id,
        subject={"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States", "mass_kg": 60.0},
        sources=[],
    )
    assert issued.status_code == 200, issued.text
    cred_id = issued.json()["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "test_results", "corrected_value": {"Br_kG": {"value": 13.2, "result": "pass"}}},
    )
    assert resp.status_code == 200, resp.text

    passport = client.get(f"/passport/{cred_id}").json()
    assert passport["verdict"] == "revoked"
