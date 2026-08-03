"""Upload -> per-heat review -> credential issuance, via the same
TestClient + dependency-override pattern as test_auth.py. No API key is
present in this environment, so extraction runs the deterministic regex
fallback (one flagged heat) unless a test monkeypatches
llm_extractor.extract_structured directly to exercise the multi-heat/
sub-lot path without a live network call.
"""
import hashlib
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import llm_extractor
import main
import review_flags
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


def _login_org_user(client, conn):
    org_id = make_issuer(conn)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    return org_id


def test_upload_stores_object_and_content_hash(client, conn):
    _login_org_user(client, conn)
    resp = _upload(client)
    assert resp.status_code == 200
    doc_id = resp.json()["id"]

    row = conn.execute("SELECT * FROM documents WHERE id = ?", (doc_id,)).fetchone()
    assert row["object_key"] == f"{doc_id}/mtr.txt"
    assert row["content_hash"] == hashlib.sha256(MTR_TEXT.encode()).hexdigest()
    assert storage.read_object(row["object_key"]) == MTR_TEXT.encode()


def test_upload_extraction_falls_back_to_one_flagged_heat(client, conn):
    _login_org_user(client, conn)
    resp = _upload(client)
    body = resp.json()

    assert body["supplier_id"] == "Test Recycler, LLC"
    assert len(body["heats"]) == 1
    heat = body["heats"][0]
    assert heat["heat_id"] == "TR-0001"
    assert heat["source"] == "regex"
    assert heat["extraction_source"] == "regex"
    assert heat["flagged_for_review"] is True
    assert heat["reviewed"] is False
    # One flag from the regex fallback itself (source='extraction'), one
    # from the deterministic sub-lot check on its always-low-confidence
    # origin note (source='compliance_engine') — the two layers agree
    # independently rather than one just echoing the other.
    assert len(heat["flags"]) == 2
    assert {f["source"] for f in heat["flags"]} == {"extraction", "compliance_engine"}
    extraction_flag = next(f for f in heat["flags"] if f["source"] == "extraction")
    assert extraction_flag["issue_type"] == "low_confidence_extraction"
    assert len(heat["sublots"]) == 1
    assert heat["sublots"][0]["origin_country"] == "United States"


def test_upload_with_mocked_multi_heat_flagged_sublot(client, conn, monkeypatch):
    """Exercises the real main.py write path (heats + sub-lots + flag
    evaluation) against a controlled multi-heat extraction result,
    without needing a live LLM call."""

    def fake_extract_structured(raw_text):
        return {
            "certificate_id": "RGM-CERT-2026-0498",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": "H-1",
                    "alloy_composition": {"Nd": 29.8, "Fe": 67.9, "B": 1.1},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {"sublot_id": "A1", "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated line.",
                    "mass_kg": 210.0,
                    "confidence": 0.9,
                    "flags": [],
                    "source": "llm",
                },
                {
                    "heat_id": "H-2",
                    "alloy_composition": {"Nd": 30.1, "Fe": 67.5, "B": 1.0},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {"sublot_id": "C1", "blend_pct": 80.0, "origin_country": "United States", "origin_confidence": "high", "notes": None},
                        {"sublot_id": "C2", "blend_pct": 20.0, "origin_country": "China", "origin_confidence": "high", "notes": "broker-sourced"},
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated line; broker addition per C2.",
                    "mass_kg": 120.0,
                    "confidence": 0.9,
                    "flags": [],
                    "source": "llm",
                },
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    body = _upload(client, filename="complex.txt").json()

    assert body["certificate_id"] == "RGM-CERT-2026-0498"
    assert len(body["heats"]) == 2

    heat1 = next(h for h in body["heats"] if h["heat_id"] == "H-1")
    heat2 = next(h for h in body["heats"] if h["heat_id"] == "H-2")

    assert heat1["flagged_for_review"] is False
    assert heat1["flags"] == []
    # H-2 wasn't flagged by the (mocked) LLM, but its China sub-lot is
    # covered — main.py's deterministic per-sub-lot check must catch it
    # even when the model's own judgment doesn't.
    assert heat2["flagged_for_review"] is True
    china_flag = next(f for f in heat2["flags"] if f["issue_type"] == "compliance_violation")
    assert "FEOC-covered" in china_flag["human_readable_reason"]
    assert china_flag["severity"] == "blocking"
    assert china_flag["source"] == "compliance_engine"
    china_sublot = next(s for s in heat2["sublots"] if s["origin_country"] == "China")
    assert china_sublot["flagged"] is True
    assert china_sublot["flags"][0]["issue_type"] == "compliance_violation"


def test_upload_records_extraction_degraded_audit_entry_with_category(client, conn, monkeypatch):
    """upload_document must write a durable, queryable audit_log entry
    (entity_type='document') carrying the failure category, not just a
    log line -- distinct from the heat-level extraction_unavailable flag
    a reviewer sees in the UI. "How many documents were degraded by
    permanent-config failures this week" must be a direct filter on
    category, not a matter of cross-referencing exception class names."""

    def fake_extract_structured(raw_text):
        return {
            "certificate_id": None,
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": None,
                    "alloy_composition": None,
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [],
                    "segregation_attested": False,
                    "segregation_note": None,
                    "mass_kg": None,
                    "confidence": 0.0,
                    "flags": [
                        review_flags.make_flag(
                            "extraction_unavailable",
                            "AI extraction failed due to a configuration or request problem...",
                            source="extraction",
                        ).model_dump()
                    ],
                    "source": "regex",
                }
            ],
            "extraction_failure": {
                "category": "permanent",
                "exception_class": "AuthenticationError",
                "exception_message": "invalid x-api-key",
            },
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]

    heat = upload["heats"][0]
    assert heat["flags"][0]["issue_type"] == "extraction_unavailable"
    assert heat["flags"][0]["severity"] == "blocking"

    rows = conn.execute(
        "SELECT detail_json FROM audit_log WHERE entity_type = 'document' AND entity_id = ? AND action = 'extraction_degraded'",
        (doc_id,),
    ).fetchall()
    assert len(rows) == 1
    detail = json.loads(rows[0]["detail_json"])
    assert detail["category"] == "permanent"
    assert detail["exception_class"] == "AuthenticationError"


def test_upload_does_not_record_extraction_degraded_entry_on_clean_or_benign_fallback(client, conn):
    """No audit noise for the two non-failure cases: a genuinely clean
    LLM extraction, or the benign no-API-key-configured fallback (regex
    path, but not a failed attempt)."""
    _login_org_user(client, conn)
    upload = _upload(client).json()  # regex fallback, ANTHROPIC_API_KEY unset in this suite's conn fixture
    doc_id = upload["id"]

    rows = conn.execute(
        "SELECT id FROM audit_log WHERE entity_type = 'document' AND entity_id = ? AND action = 'extraction_degraded'",
        (doc_id,),
    ).fetchall()
    assert rows == []


def test_review_heat_locks_after_review(client, conn):
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    review_body = {
        "heat_id": "TR-0001",
        "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0},
        "segregation_attested": True,
        "segregation_attested_by": "Maria Alvarez, QA Lead",
        "segregation_note": "Dedicated line, purged between runs.",
        "mass_kg": 50.0,
        "sublots": [
            {"sublot_id": None, "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
        ],
    }
    resp = client.post(f"/documents/{doc_id}/heats/{heat_id}/review", json=review_body)
    assert resp.status_code == 200
    reviewed = resp.json()
    assert reviewed["reviewed"] is True
    assert reviewed["source"] == "human"
    assert reviewed["alloy_composition"] == {"Nd": 29.5, "Fe": 68.2, "B": 1.0}

    # The sub-lot flag IS resolved: the corrected sub-lot is now
    # high-confidence domestic, so the fresh compliance_engine check
    # against it comes back clean.
    sublot_flags = reviewed["sublots"][0]["flags"]
    assert all(f["status"] != "open" for f in sublot_flags)
    # But the regex fallback's own heat-level flag ("needs full manual
    # review") is untouched by any of this, and correctly stays open —
    # a heat-level extraction flag must survive /review unless it's
    # actually been resolved (e.g. via /correct), not get silently
    # dropped just because the form was submitted. Before the review_heat
    # merge fix, this flag was unconditionally wiped by /review
    # regardless of whether anything addressed it, which is what this
    # assertion used to (incorrectly) rely on.
    assert reviewed["flagged_for_review"] is True
    extraction_flag = next(f for f in reviewed["flags"] if f["source"] == "extraction")
    assert extraction_flag["status"] == "open"

    again = client.post(f"/documents/{doc_id}/heats/{heat_id}/review", json=review_body)
    assert again.status_code == 409


def test_review_heat_requires_org_match(client, conn):
    org_a = make_issuer(conn, "Org A")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    org_b = make_issuer(conn, "Org B")
    make_user(conn, "b@example.com", "pw", "org_user", org_b)

    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "b@example.com", "password": "pw"})
    resp = client.post(f"/documents/{doc_id}/heats/{heat_id}/review", json={"sublots": []})
    assert resp.status_code == 403


# --- heat-level extraction flags must survive /review, not get silently
# dropped (review_heat used to rebuild flags_json from sub-lot checks
# alone and overwrite the whole array) --------------------------------


def _heat_with_heat_level_flag(heat_id=None):
    """No sub-lot-level issue at all — the sole flag is heat-level
    (sublot_id=None), on a field (`heat_id`) that IS backend-correctable,
    so a resolved-via-/correct regression test can exercise a real
    correction rather than a field /correct can't actually save."""
    return {
        "heat_id": heat_id,
        "alloy_composition": {"Nd": 29.4, "Fe": 68.3, "B": 1.1, "Dy": 1.2},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": None, "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 195.0,
        "confidence": 0.8,
        "flags": [
            review_flags.make_flag(
                "missing_field",
                "No heat/melt number stated in the certificate.",
                source="extraction",
                field_name="heat_id",
            ).model_dump()
        ],
        "source": "llm",
    }


def _review_body_from_heat(heat, **overrides):
    sublot = heat["sublots"][0]
    body = {
        "heat_id": heat["heat_id"],
        "alloy_composition": heat["alloy_composition"],
        "mass_kg": heat["mass_kg"],
        "segregation_attested": heat["segregation_attested"],
        "segregation_note": heat["segregation_note"],
        "sublots": [
            {
                "id": sublot["id"],
                "sublot_id": sublot["sublot_id"],
                "blend_pct": sublot["blend_pct"],
                "origin_country": sublot["origin_country"],
                "origin_confidence": sublot["origin_confidence"],
                "notes": sublot["notes"],
            }
        ],
    }
    body.update(overrides)
    return body


def test_review_preserves_heat_level_extraction_flag_when_unaddressed(client, conn, monkeypatch):
    """Regression: a heat whose only issue is a heat-level extraction
    flag, submitted via /review with no changes (the flagged field
    still unaddressed), must still show that flag open afterward — not
    silently read as clean because review_heat rebuilt flags_json from
    sub-lot checks alone and threw the heat-level flag away."""
    monkeypatch.setattr(
        llm_extractor,
        "extract_structured",
        lambda raw_text: {
            "certificate_id": "CERT-1",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [_heat_with_heat_level_flag()],
        },
    )
    _login_org_user(client, conn)
    upload = _upload(client, filename="flagged.txt").json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    assert heat["flagged_for_review"] is True
    assert any(f["issue_type"] == "missing_field" and f["status"] == "open" for f in heat["flags"])

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/review",
        json=_review_body_from_heat(heat),  # unchanged — heat_id is still None
    )
    assert resp.status_code == 200
    reviewed = resp.json()

    missing_flag = next((f for f in reviewed["flags"] if f["issue_type"] == "missing_field"), None)
    assert missing_flag is not None, "heat-level extraction flag was dropped by /review"
    assert missing_flag["status"] == "open"
    assert reviewed["flagged_for_review"] is True
    assert reviewed["fully_addressed"] is False


def test_review_does_not_reopen_a_flag_already_resolved_via_correct(client, conn, monkeypatch):
    """Regression, the /correct + /review composition case: a flag
    resolved via /correct before /review is ever submitted must stay
    resolved — the merge in review_heat reads current flags_json (which
    already reflects the /correct resolution), it doesn't revert to some
    earlier snapshot."""
    monkeypatch.setattr(
        llm_extractor,
        "extract_structured",
        lambda raw_text: {
            "certificate_id": "CERT-1",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [_heat_with_heat_level_flag()],
        },
    )
    _login_org_user(client, conn)
    upload = _upload(client, filename="flagged3.txt").json()
    doc_id = upload["id"]
    heat = upload["heats"][0]

    corrected = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "heat", "field_name": "heat_id", "corrected_value": "H-FIXED"},
    )
    assert corrected.status_code == 200
    missing_flag = next(f for f in corrected.json()["flags"] if f["issue_type"] == "missing_field")
    assert missing_flag["status"] == "resolved"

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/review",
        json=_review_body_from_heat(heat, heat_id="H-FIXED"),
    )
    assert resp.status_code == 200
    reviewed = resp.json()

    missing_flag_after = next(f for f in reviewed["flags"] if f["issue_type"] == "missing_field")
    assert missing_flag_after["status"] == "resolved", "a flag already resolved via /correct must not be reopened by /review"
    assert reviewed["flagged_for_review"] is False
    assert reviewed["fully_addressed"] is True


def test_credential_issue_requires_reviewed_heat(client, conn):
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    unreviewed = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "NdFeB", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert unreviewed.status_code == 400

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )

    issued = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert issued.status_code == 200
    cred_id = issued.json()["id"]

    heat_row = conn.execute("SELECT credential_id FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    assert heat_row["credential_id"] == cred_id

    double_issue = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert double_issue.status_code == 409


def test_credential_issue_requires_no_open_blocking_flag(client, conn):
    """issue_credential used to check only heat["reviewed"] -- a heat
    reviewed with an unresolved compliance_violation (e.g. a banned-
    country sub-lot origin) could still have a credential issued from
    it, with nothing on the backend to stop it. reviewed=True and
    fully_addressed=False are not the same thing (see
    test_corrections.py's test_fully_addressed_false_when_review_
    submitted_with_open_blocking_flag, which reproduces the same China
    sub-lot shape used here)."""
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    reviewed = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "China", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    ).json()
    assert reviewed["reviewed"] is True
    assert reviewed["fully_addressed"] is False
    blocking_flag = next(f for f in reviewed["sublots"][0]["flags"] if f["issue_type"] == "compliance_violation")
    assert blocking_flag["severity"] == "blocking"
    assert blocking_flag["status"] == "open"

    blocked = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "China"},
            "sources": [],
        },
    )
    assert blocked.status_code == 409, blocked.text

    # Correcting the flagged origin resolves the blocking flag -- issuance
    # should now be allowed, same as any other addressed heat.
    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={
            "target": "sublot",
            "sublot_id": reviewed["sublots"][0]["id"],
            "field_name": "origin_country",
            "corrected_value": "United States",
        },
    )
    allowed = client.post(
        "/credentials/issue",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": heat_id,
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert allowed.status_code == 200, allowed.text


def test_extraction_stats_reflects_flagged_and_reviewed(client, conn):
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    client.post("/auth/logout")

    client.post("/auth/login", json={"email": "admin@example.com", "password": "pw"})
    stats = client.get("/admin/extraction-stats").json()

    regex_overall = next(r for r in stats["overall"] if r["extraction_source"] == "regex")
    assert regex_overall["total"] == 1
    assert regex_overall["reviewed"] == 1


def test_extraction_stats_requires_platform_admin(client, conn):
    _login_org_user(client, conn)
    resp = client.get("/admin/extraction-stats")
    assert resp.status_code == 403
