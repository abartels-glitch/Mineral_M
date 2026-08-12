"""Field-level correction workflow: a reviewer fixes one flagged field in
place (POST .../correct) rather than resubmitting the whole heat via
/review. Covers: the corresponding flag resolves (not deleted), a
sub-lot correction re-runs the deterministic compliance check against
the corrected value, `flagged`/`flagged_for_review`/`fully_addressed`
recompute from open flags only, the correction is audited, and
correction is allowed independently of the one-shot /review lock.

Same TestClient + dependency-override pattern as test_heats.py.
"""
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import llm_extractor
import main
import storage
from db import SCHEMA

MTR_TEXT = (
    "CERTIFICATE OF CONFORMANCE / MILL TEST REPORT\n"
    "Supplier: Test Recycler, LLC\n"
    "Material: Sintered NdFeB Magnet Alloy (N42)\n"
    "Country of Origin: United States\n"
    "Batch Mass: 50.0 kg\n"
)  # deliberately no "Heat Number:" line -> regex fallback flags heat_id missing


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


def _upload(client, filename="mtr.txt", text=MTR_TEXT):
    return client.post(
        "/documents/upload",
        files={"file": (filename, text.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    )


def _upload_mocked(client, monkeypatch, heats):
    def fake_extract_structured(raw_text):
        return {"certificate_id": "CERT-1", "supplier_id": "Rio Grande Magnetics, LLC", "signatures": [], "heats": heats}

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    return client.post(
        "/documents/upload",
        files={"file": ("complex.txt", b"irrelevant, extraction is mocked", "text/plain")},
        data={"document_type": "mtr_coc"},
    )


def _missing_heat_id_heat():
    return {
        "heat_id": None,
        "alloy_composition": {"Nd": 29.6, "Fe": 68.1, "B": 1.0},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": None, "blend_pct": 100.0, "origin_country": "United States", "origin_confidence": "high", "notes": None}
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 178.0,
        "confidence": 0.9,
        "flags": [
            {
                "issue_type": "missing_field",
                "field_name": "heat_id",
                "severity": "needs_review",
                "human_readable_reason": "no heat/melt number stated on the certificate",
                "source": "extraction",
            }
        ],
        "source": "llm",
    }


def _two_missing_origin_sublots_heat():
    """Two sub-lots on one heat, both missing origin_country — the
    compliance_engine flag _evaluate_sublot_flag produces for each is
    byte-for-byte identical in shape (same issue_type/field_name/reason).
    Before sublot_id existed on Flag, document_heats.flags_json's
    flattened copy of these two flags was indistinguishable; this is the
    exact scenario that made resolving one sub-lot's copy there unsafe."""
    return {
        "heat_id": "H-MULTI",
        "alloy_composition": {"Nd": 29.2, "Fe": 68.5, "B": 1.0},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": "B1", "blend_pct": 65.0, "origin_country": None, "origin_confidence": None, "notes": "pending"},
            {"sublot_id": "B2", "blend_pct": 35.0, "origin_country": None, "origin_confidence": None, "notes": "pending"},
        ],
        "segregation_attested": False,
        "segregation_note": None,
        "mass_kg": 95.0,
        "confidence": 0.85,
        "flags": [],
        "source": "llm",
    }


def _two_covered_origin_sublots_heat():
    """Three sub-lots on one heat: D1 and D3 both plainly state China
    (covered), D2 states United States (clean). Modeled directly on a real
    (non-mocked) llm_extractor.extract_structured call against equivalent
    MTR text -- confirmed live, across three separate calls, that the
    model consistently emits one heat-level flags entry per violating
    sub-lot (never one entry combining both), each naming the specific
    sub-lot in human_readable_reason ("Sub-lot D1 ... China", "Sub-lot D3
    ... China"), both with field_name='origin_country' and sublot_id=None
    (source='extraction' flags are always heat-scoped -- see
    review_flags.py -- so there's no field on the flag itself connecting
    a given entry to D1 vs. D3; only the free-text reason does, and nothing
    in this codebase parses that text back into a sub-lot reference).
    Exists to exercise _resolve_heat_level_origin_flags_if_all_sublots_clear
    against a heat where more than one sub-lot must clear before it can
    fire, not just the single-sub-lot case every other origin test here
    covers."""
    return {
        "heat_id": "H-MULTI-COVERED",
        "alloy_composition": {"Nd": 29.6, "Fe": 68.1, "B": 1.1, "Dy": 1.2},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": "D1", "blend_pct": 40.0, "origin_country": "China", "origin_confidence": "high", "notes": "broker-sourced scrap, plainly stated"},
            {"sublot_id": "D2", "blend_pct": 35.0, "origin_country": "United States", "origin_confidence": "high", "notes": "domestically collected scrap"},
            {"sublot_id": "D3", "blend_pct": 25.0, "origin_country": "China", "origin_confidence": "high", "notes": "broker-sourced scrap, second lot, plainly stated"},
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line; broker-sourced additions per sub-lots D1 and D3.",
        "mass_kg": 180.0,
        "confidence": 0.95,
        "flags": [
            {
                "issue_type": "compliance_violation",
                "field_name": "origin_country",
                "severity": "blocking",
                "human_readable_reason": "Sub-lot D1 lists China as country of origin (40% of batch). China is a covered country under relevant trade compliance frameworks.",
                "source": "extraction",
                "status": "open",
                "resolved_by": None,
                "resolved_at": None,
                "sublot_id": None,
            },
            {
                "issue_type": "compliance_violation",
                "field_name": "origin_country",
                "severity": "blocking",
                "human_readable_reason": "Sub-lot D3 lists China as country of origin (25% of batch). China is a covered country under relevant trade compliance frameworks.",
                "source": "extraction",
                "status": "open",
                "resolved_by": None,
                "resolved_at": None,
                "sublot_id": None,
            },
        ],
        "source": "llm",
    }


def _missing_origin_heat():
    """Sub-lot with no stated origin — main.py's own deterministic
    _evaluate_sublot_flag (source='compliance_engine') is what flags
    this, independent of whatever the LLM did or didn't notice, so this
    doesn't need a mocked LLM `flags` entry to exercise the compliance
    engine's field_name='origin_country' flag."""
    return {
        "heat_id": "H-1",
        "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0},
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": [
            {"sublot_id": "U1", "blend_pct": 100.0, "origin_country": None, "origin_confidence": None, "notes": "broker-sourced, documentation pending"}
        ],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 152.0,
        "confidence": 0.7,
        "flags": [],
        "source": "llm",
    }


# --- heat-level field correction --------------------------------------------


def test_correct_heat_field_resolves_matching_flag(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_heat_id_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    assert heat["heat_id"] is None
    missing_flag = next(f for f in heat["flags"] if f["field_name"] == "heat_id")
    assert missing_flag["status"] == "open"
    assert heat["fully_addressed"] is False

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "heat", "field_name": "heat_id", "corrected_value": "TR-0001"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    assert updated["heat_id"] == "TR-0001"
    assert updated["source"] == "human"

    resolved = next(f for f in updated["flags"] if f["field_name"] == "heat_id")
    assert resolved["status"] == "resolved"
    assert resolved["resolved_by"] == "u@example.com"
    assert resolved["resolved_at"] is not None
    # kept, not deleted
    assert len(updated["flags"]) == len(heat["flags"])
    assert updated["flagged_for_review"] is False
    assert updated["fully_addressed"] is True


def test_correct_heat_field_rejects_unknown_field(client, conn):
    # nonconformance_refs (not alloy_composition/test_results, which are
    # correctable -- see test_corrections_object_fields.py) stays off the
    # allowlist: it's a list of strings (llm_extractor.HEAT_SCHEMA), not a
    # scalar or the flat/one-level-nested dict shapes this pass built
    # editors for. /review's full-replace form remains the only way to
    # change it until a list-shaped editor exists.
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "nonconformance_refs", "corrected_value": "[]"},
    )
    assert resp.status_code == 400


def test_correction_allowed_after_heat_reviewed_lock(client, conn):
    """Unlike /review (409 on a second call), /correct isn't a one-shot
    workflow — a reviewer can fix a field after the heat is otherwise
    locked, since it's an audited correction, not a re-review."""
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={"heat_id": "TR-0001", "mass_kg": 50.0, "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}]},
    )
    again = client.post(f"/documents/{doc_id}/heats/{heat_id}/review", json={"sublots": []})
    assert again.status_code == 409

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "mass_kg", "corrected_value": "55.0"},
    )
    assert resp.status_code == 200
    assert resp.json()["mass_kg"] == 55.0


# --- sub-lot correction re-runs the compliance check ------------------------


def test_correct_sublot_origin_to_covered_country_flips_to_blocking(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_origin_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    sublot = heat["sublots"][0]
    assert sublot["flags"][0]["issue_type"] == "missing_field"
    assert sublot["flags"][0]["source"] == "compliance_engine"

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "sublot", "sublot_id": sublot["id"], "field_name": "origin_country", "corrected_value": "China"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    updated_sublot = updated["sublots"][0]
    assert updated_sublot["origin_country"] == "China"
    assert updated_sublot["flagged"] is True

    # the old flag on origin_country is resolved, not gone
    origin_country_flags = [f for f in updated_sublot["flags"] if f["field_name"] == "origin_country"]
    assert any(f["status"] == "resolved" and f["issue_type"] == "missing_field" for f in origin_country_flags)
    # a fresh, open compliance_violation flag was produced by re-running
    # the deterministic check against the corrected value
    fresh = next(f for f in origin_country_flags if f["status"] == "open")
    assert fresh["issue_type"] == "compliance_violation"
    assert fresh["severity"] == "blocking"
    assert fresh["source"] == "compliance_engine"

    assert updated["flagged_for_review"] is True
    assert updated["fully_addressed"] is False


def test_correct_sublot_fully_clears_flags(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_origin_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    sublot = heat["sublots"][0]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "sublot", "sublot_id": sublot["id"], "field_name": "origin_country", "corrected_value": "United States"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    updated_sublot = updated["sublots"][0]
    assert updated_sublot["flagged"] is False
    assert all(f["status"] == "resolved" for f in updated_sublot["flags"])
    assert updated["flagged_for_review"] is False
    assert updated["fully_addressed"] is True


def test_correct_sublot_requires_sublot_id(client, conn, monkeypatch):
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_origin_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "sublot", "field_name": "origin_country", "corrected_value": "China"},
    )
    assert resp.status_code == 400


def test_correct_one_sublot_does_not_affect_sibling_sublots_identical_flag(client, conn, monkeypatch):
    """The regression this sublot_id fix targets: two sub-lots on the
    same heat both flagged missing_field/origin_country — an identical
    flag shape. Correcting B1 must resolve only B1's flag (in both its
    own flags list and the heat-level flattened copy), leaving B2's
    still-open flag completely untouched and still attributed to B2."""
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_two_missing_origin_sublots_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    # _fetch_sublots orders by the sub-lot's own (random) row id, not
    # insertion order — match by label, not position.
    b1 = next(s for s in heat["sublots"] if s["sublot_id"] == "B1")
    b2 = next(s for s in heat["sublots"] if s["sublot_id"] == "B2")
    assert b1["flags"][0]["status"] == "open" and b1["flags"][0]["sublot_id"] == b1["id"]
    assert b2["flags"][0]["status"] == "open" and b2["flags"][0]["sublot_id"] == b2["id"]
    # heat-level flattened copy has both, identical in shape apart from sublot_id
    heat_origin_flags = [f for f in heat["flags"] if f["field_name"] == "origin_country"]
    assert len(heat_origin_flags) == 2
    assert {f["sublot_id"] for f in heat_origin_flags} == {b1["id"], b2["id"]}

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "sublot", "sublot_id": b1["id"], "field_name": "origin_country", "corrected_value": "United States"},
    )
    assert resp.status_code == 200
    updated = resp.json()
    updated_b1 = next(s for s in updated["sublots"] if s["id"] == b1["id"])
    updated_b2 = next(s for s in updated["sublots"] if s["id"] == b2["id"])

    # B1: resolved on its own sub-lot row
    assert updated_b1["flagged"] is False
    assert updated_b1["flags"][0]["status"] == "resolved"
    assert updated_b1["flags"][0]["resolved_by"] == "u@example.com"

    # B2: completely untouched, still open, still correctly attributed
    assert updated_b2["flagged"] is True
    assert len(updated_b2["flags"]) == 1
    assert updated_b2["flags"][0]["status"] == "open"
    assert updated_b2["flags"][0]["resolved_by"] is None
    assert updated_b2["flags"][0]["sublot_id"] == b2["id"]

    # heat-level flattened copy: B1's copy resolved, B2's copy still open —
    # this is the part that used to be ambiguous without sublot_id
    heat_origin_flags = [f for f in updated["flags"] if f["field_name"] == "origin_country"]
    assert len(heat_origin_flags) == 2
    b1_copy = next(f for f in heat_origin_flags if f["sublot_id"] == b1["id"])
    b2_copy = next(f for f in heat_origin_flags if f["sublot_id"] == b2["id"])
    assert b1_copy["status"] == "resolved"
    assert b2_copy["status"] == "open"

    # heat still flagged overall (B2 unresolved) and not fully addressed
    assert updated["flagged_for_review"] is True
    assert updated["fully_addressed"] is False


def test_heat_level_extraction_flag_waits_for_every_covered_sublot_before_resolving(client, conn, monkeypatch):
    """Multi-sub-lot version of the Flag A / Flag B relationship: heat
    H-MULTI-COVERED has two independently-flagged China sub-lots (D1, D3)
    plus a clean US one (D2), and two heat-level Flag A entries (source=
    extraction, sublot_id=None) -- one per violating sub-lot, per the real
    LLM behavior _two_covered_origin_sublots_heat's docstring records.

    Correcting only D1 must NOT resolve either Flag A: D3's own
    compliance_engine flag is still open, so
    _resolve_heat_level_origin_flags_if_all_sublots_clear's "all sub-lots
    clear" gate stays False. Only once D3 is also corrected -- the last
    of the two covered sub-lots -- do both Flag A entries resolve, in the
    same request, since the function doesn't try to match a specific
    Flag A to a specific sub-lot (see the docstring on why it can't); it
    resolves every open origin-related extraction flag on the heat once
    the aggregate condition is met."""
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_two_covered_origin_sublots_heat()]).json()
    doc_id = upload["id"]
    heat = upload["heats"][0]
    d1 = next(s for s in heat["sublots"] if s["sublot_id"] == "D1")
    d2 = next(s for s in heat["sublots"] if s["sublot_id"] == "D2")
    d3 = next(s for s in heat["sublots"] if s["sublot_id"] == "D3")

    assert d1["origin_country"] == "China" and d1["flagged"] is True
    assert d2["origin_country"] == "United States" and d2["flagged"] is False
    assert d3["origin_country"] == "China" and d3["flagged"] is True

    flag_a_entries = [f for f in heat["flags"] if f["source"] == "extraction" and f["sublot_id"] is None]
    assert len(flag_a_entries) == 2
    assert all(f["status"] == "open" for f in flag_a_entries)
    assert any("D1" in f["human_readable_reason"] for f in flag_a_entries)
    assert any("D3" in f["human_readable_reason"] for f in flag_a_entries)

    # Correct D1 only -- D3 is still an open compliance_engine violation.
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "sublot", "sublot_id": d1["id"], "field_name": "origin_country", "corrected_value": "United States"},
    )
    assert resp.status_code == 200
    after_d1 = resp.json()
    updated_d1 = next(s for s in after_d1["sublots"] if s["id"] == d1["id"])
    updated_d3 = next(s for s in after_d1["sublots"] if s["id"] == d3["id"])
    assert updated_d1["flagged"] is False
    assert updated_d3["flagged"] is True

    flag_a_after_d1 = [f for f in after_d1["flags"] if f["source"] == "extraction" and f["sublot_id"] is None]
    assert len(flag_a_after_d1) == 2
    assert all(f["status"] == "open" for f in flag_a_after_d1), (
        "Flag A resolved prematurely after only one of two covered sub-lots was corrected"
    )
    assert after_d1["flagged_for_review"] is True
    assert after_d1["fully_addressed"] is False

    # Correct D3 -- the last covered sub-lot. Now both Flag A entries
    # should resolve, since the aggregate condition is finally satisfied.
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat['id']}/correct",
        json={"target": "sublot", "sublot_id": d3["id"], "field_name": "origin_country", "corrected_value": "United States"},
    )
    assert resp.status_code == 200
    after_d3 = resp.json()
    updated_d3_final = next(s for s in after_d3["sublots"] if s["id"] == d3["id"])
    assert updated_d3_final["flagged"] is False

    flag_a_after_d3 = [f for f in after_d3["flags"] if f["source"] == "extraction" and f["sublot_id"] is None]
    assert len(flag_a_after_d3) == 2
    assert all(f["status"] == "resolved" for f in flag_a_after_d3), (
        "Flag A never resolved even after every covered sub-lot was corrected"
    )
    assert all(f["resolved_by"] == "u@example.com" for f in flag_a_after_d3)

    assert after_d3["flagged_for_review"] is False
    assert after_d3["fully_addressed"] is True


# --- fully_addressed vs. reviewed --------------------------------------------


def test_fully_addressed_false_when_review_submitted_with_open_blocking_flag(client, conn):
    """Reproduces the badge bug this feature fixes: submitting /review
    always set reviewed=True even with a blocking flag still open.
    fully_addressed must say "no" even though reviewed says "yes"."""
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "China", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    reviewed = resp.json()
    assert reviewed["reviewed"] is True
    assert reviewed["flagged_for_review"] is True
    assert reviewed["fully_addressed"] is False


# --- audit trail --------------------------------------------------------------


def test_correction_is_recorded_in_heat_audit_trail(client, conn):
    _login_org_user(client, conn)
    upload = _upload(client).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "heat_id", "corrected_value": "TR-0001"},
    )

    trail = client.get(f"/documents/{doc_id}/heats/{heat_id}/audit-trail").json()
    entry = next(e for e in trail if e["action"] == "field_corrected")
    assert entry["actor"] == "u@example.com"
    assert entry["detail"]["target"] == "heat"
    assert entry["detail"]["field_name"] == "heat_id"
    assert entry["detail"]["previous_value"] is None
    assert entry["detail"]["corrected_value"] == "TR-0001"


def test_correction_requires_org_match(client, conn):
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
    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={"target": "heat", "field_name": "heat_id", "corrected_value": "TR-0001"},
    )
    assert resp.status_code == 403


# --- sub-lot row id stability across /review ----------------------------------
# Found via a live E2E walkthrough: review_heat used to unconditionally drop
# and reinsert every sub-lot row with a fresh id on every /review call. A
# client that captured a sub-lot's id before /review (the only place ids are
# visible pre-review) got a 404 "sub-lot not found" on a later /correct call,
# with no indication it needed to refetch first.


def test_sublot_id_stable_across_review_when_round_tripped(client, conn, monkeypatch):
    """The regression test: capture a sub-lot's id before /review,
    round-trip it in the /review submission, and confirm both that the
    id survives unchanged and that a /correct call using that same
    pre-review id still resolves — no refetch required."""
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_origin_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]
    pre_review_sublot_id = upload["heats"][0]["sublots"][0]["id"]

    reviewed = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "H-1",
            "mass_kg": 152.0,
            "sublots": [
                {
                    "id": pre_review_sublot_id,
                    "origin_country": "United States",
                    "origin_confidence": "high",
                    "blend_pct": 100.0,
                }
            ],
        },
    ).json()

    assert reviewed["sublots"][0]["id"] == pre_review_sublot_id

    resp = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/correct",
        json={
            "target": "sublot",
            "sublot_id": pre_review_sublot_id,
            "field_name": "origin_country",
            "corrected_value": "China",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["sublots"][0]["origin_country"] == "China"


def test_review_adds_new_sublot_without_id_gets_fresh_row(client, conn, monkeypatch):
    """A sub-lot submitted with no id — the reviewer splitting a blend
    into an extra sub-lot during review, say — is correctly treated as
    new rather than confused with the existing row."""
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_missing_origin_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]
    existing_id = upload["heats"][0]["sublots"][0]["id"]

    reviewed = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "H-1",
            "mass_kg": 152.0,
            "sublots": [
                {"id": existing_id, "origin_country": "United States", "origin_confidence": "high", "blend_pct": 60.0},
                {"origin_country": "United States", "origin_confidence": "high", "blend_pct": 40.0, "notes": "split off during review"},
            ],
        },
    ).json()

    assert len(reviewed["sublots"]) == 2
    ids = {s["id"] for s in reviewed["sublots"]}
    assert existing_id in ids
    assert len(ids) == 2  # the new row got its own distinct id, not a collision


def test_review_omitting_existing_sublot_removes_it(client, conn, monkeypatch):
    """Full-replace semantics are preserved: a sub-lot the reviewer
    doesn't resubmit is removed — same as the pre-fix behavior for a
    caller that never round-trips an id at all."""
    _login_org_user(client, conn)
    upload = _upload_mocked(client, monkeypatch, [_two_missing_origin_sublots_heat()]).json()
    doc_id = upload["id"]
    heat_id = upload["heats"][0]["id"]
    sublots = upload["heats"][0]["sublots"]
    assert len(sublots) == 2
    keep_id = sublots[0]["id"]
    dropped_id = sublots[1]["id"]

    reviewed = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": "H-MULTI",
            "mass_kg": 95.0,
            "sublots": [
                {"id": keep_id, "origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0},
            ],
        },
    ).json()

    assert len(reviewed["sublots"]) == 1
    assert reviewed["sublots"][0]["id"] == keep_id
    assert conn.execute("SELECT id FROM heat_sublots WHERE id = ?", (dropped_id,)).fetchone() is None
