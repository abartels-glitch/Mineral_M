"""Real PDF fixtures exercising the OCR -> LLM-structuring pipeline for
specific document edge cases the regex fallback can't meaningfully
distinguish (its patterns only match "Heat Number:"/"Material:" labels,
which none of these documents use — they use the more realistic "Heat
No.:" convention seed.py's own sample documents use). No API key is
present in this environment (see test_heats.py's docstring), so each
test monkeypatches llm_extractor.extract_structured with a response
crafted to match that fixture's actual real content, the same
established pattern as test_heats.py's
test_upload_with_mocked_multi_heat_flagged_sublot — this still exercises
real OCR text extraction against the real PDF bytes, and the real
main.py/review_flags downstream flagging logic against a realistic
extraction result, without a live network call.
"""
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import llm_extractor
import main
import review_flags
import storage
from db import SCHEMA

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


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


def _upload_fixture(client, fixture_name):
    pdf_bytes = (FIXTURES_DIR / f"{fixture_name}.pdf").read_bytes()
    return client.post(
        "/documents/upload",
        files={"file": (f"{fixture_name}.pdf", pdf_bytes, "application/pdf")},
        data={"document_type": "mtr_coc"},
    )


def test_covered_country_fixture_triggers_compliance_violation(client, conn, monkeypatch):
    """rio_grande_mtr_covered_country.pdf plainly states 'Country of
    Origin: China' — a clean, high-confidence read (the text isn't
    hedged), but main.py's own deterministic per-sub-lot check must
    flag it as compliance_violation regardless of what the (mocked)
    LLM's own flags list says, same as test_heats.py's H-2 case."""

    def fake_extract_structured(raw_text):
        assert "Country of Origin: China" in raw_text
        return {
            "certificate_id": "RGM-CERT-2026-0505",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0505",
                    "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": None,
                            "blend_pct": 100.0,
                            "origin_country": "China",
                            "origin_confidence": "high",
                            "notes": "100% purchased alloy stock, single source, no blending",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated single-line sintering process; qualified international alloy supplier.",
                    "mass_kg": 200.0,
                    "confidence": 0.95,
                    "flags": [],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_covered_country")
    assert resp.status_code == 200
    heat = resp.json()["heats"][0]

    assert heat["flagged_for_review"] is True
    china_flag = next(f for f in heat["flags"] if f["issue_type"] == "compliance_violation")
    assert "FEOC-covered" in china_flag["human_readable_reason"]
    assert china_flag["severity"] == "blocking"
    assert china_flag["source"] == "compliance_engine"
    china_sublot = next(s for s in heat["sublots"] if s["origin_country"] == "China")
    assert china_sublot["flagged"] is True


def test_different_lab_layout_fixture_extracts_cleanly(client, conn, monkeypatch):
    """rio_grande_mtr_different_lab_layout.pdf is a third-party lab
    report using entirely different labels ('Sample Reference' not
    'Heat No.', 'Lot Mass' not 'Batch Mass', composition in a table
    rather than a flat list) but states the same kind of clean, direct
    facts as the standard-format documents. This documents the intended
    behavior once genuinely extracted (by an LLM, not regex, which
    would find none of these fields at all): a differently-organized
    document with unambiguous content should extract clean and
    unflagged."""

    def fake_extract_structured(raw_text):
        assert "SOUTHWEST METALLURGICAL TESTING LABORATORIES" in raw_text
        assert "Sample Reference: RGM-NDFEB-2026-0503" in raw_text
        return {
            "certificate_id": "SWML-2026-3387",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0503",
                    "alloy_composition": {"Nd": 29.7, "Fe": 68.0, "B": 1.0, "Dy": 1.3},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": None,
                            "blend_pct": 100.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "Domestically collected scrap, single lot, no blending",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated single-line sintering process; purged between runs.",
                    "mass_kg": 168.5,
                    "confidence": 0.95,
                    "flags": [],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_different_lab_layout")
    assert resp.status_code == 200
    heat = resp.json()["heats"][0]

    assert heat["heat_id"] == "RGM-NDFEB-2026-0503"
    assert heat["mass_kg"] == 168.5
    assert heat["flagged_for_review"] is False
    assert heat["flags"] == []
    assert heat["sublots"][0]["origin_country"] == "United States"


def test_inconsistent_composition_fixture_flags_inconsistent_data(client, conn, monkeypatch):
    """rio_grande_mtr_inconsistent_composition.pdf states composition
    with inconsistent units/formatting per element ('Nd 29.4%, Fe: 68.3
    wt%, B=1.1, Dy...1.2 percent') — internally messy in a way the
    system prompt's inconsistent_data category exists for."""

    def fake_extract_structured(raw_text):
        assert "Nd 29.4%, Fe: 68.3 wt%, B=1.1, Dy...1.2 percent" in raw_text
        return {
            "certificate_id": "RGM-CERT-2026-0502",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0502",
                    "alloy_composition": {"Nd": 29.4, "Fe": 68.3, "B": 1.1, "Dy": 1.2},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": None,
                            "blend_pct": 100.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "100% domestically collected scrap, single source, no blending",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated single-line sintering process.",
                    "mass_kg": 195.0,
                    "confidence": 0.8,
                    "flags": [
                        review_flags.make_flag(
                            "inconsistent_data",
                            "Composition elements are stated with inconsistent units/formatting (%, wt%, '=', 'percent') rather than a uniform table.",
                            source="extraction",
                            field_name="alloy_composition",
                        ).model_dump()
                    ],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_inconsistent_composition")
    assert resp.status_code == 200
    heat = resp.json()["heats"][0]

    assert heat["flagged_for_review"] is True
    inconsistent_flag = next(f for f in heat["flags"] if f["issue_type"] == "inconsistent_data")
    assert inconsistent_flag["field_name"] == "alloy_composition"
    assert inconsistent_flag["severity"] == "needs_review"
    assert inconsistent_flag["source"] == "extraction"


def test_missing_heat_number_fixture_flags_missing_field(client, conn, monkeypatch):
    """rio_grande_mtr_missing_heat_number.pdf has no heat/melt/lot
    number stated anywhere in the document."""

    def fake_extract_structured(raw_text):
        assert "Heat No" not in raw_text
        return {
            "certificate_id": "RGM-CERT-2026-0501",
            # This fixture has two candidate supplier fields ("Supplier:
            # Rio Grande Magnetics, LLC" and "Supplier ID: RGM-TX-01") —
            # a live E2E run against the real model confirmed it picks
            # the more specific "Supplier ID:" line, not the company
            # name. Matches real behavior so this doesn't silently drift
            # if the fixture or prompt changes later.
            "supplier_id": "RGM-TX-01",
            "signatures": [],
            "heats": [
                {
                    "heat_id": None,
                    "alloy_composition": {"Nd": 29.6, "Fe": 68.1, "B": 1.0, "Dy": 1.3},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": None,
                            "blend_pct": 100.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "100% domestically collected scrap, single source, no blending",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated single-line sintering process.",
                    "mass_kg": 178.0,
                    "confidence": 0.85,
                    "flags": [
                        review_flags.make_flag(
                            "missing_field",
                            "No heat, melt, or lot number is stated anywhere in the certificate.",
                            source="extraction",
                            field_name="heat_id",
                        ).model_dump()
                    ],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_missing_heat_number")
    assert resp.status_code == 200
    heat = resp.json()["heats"][0]

    assert heat["heat_id"] is None
    assert heat["flagged_for_review"] is True
    missing_flag = next(f for f in heat["flags"] if f["issue_type"] == "missing_field")
    assert missing_flag["field_name"] == "heat_id"
    assert missing_flag["severity"] == "needs_review"


def test_unconfirmed_origin_fixture_flags_low_confidence(client, conn, monkeypatch):
    """rio_grande_mtr_unconfirmed_origin.pdf explicitly hedges its
    sub-lot's origin: 'unconfirmed', 'documentation pending', 'not yet
    verified' — the system prompt's own worked example of low
    confidence, as distinct from a plainly-stated-but-covered origin
    (see the covered_country fixture's test above, which is the
    opposite case: plainly stated, high confidence, still flagged, but
    for compliance_violation instead)."""

    def fake_extract_structured(raw_text):
        assert "unconfirmed" in raw_text
        assert "country of origin\n  not yet verified" in raw_text.lower()
        return {
            "certificate_id": "RGM-CERT-2026-0504",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0504",
                    "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3},
                    "test_results": None,
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": "U1",
                            "blend_pct": 100.0,
                            "origin_country": None,
                            "origin_confidence": "low",
                            "notes": "broker-sourced material of undetermined origin, documentation pending from upstream supplier",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated single-line sintering process.",
                    "mass_kg": 152.0,
                    "confidence": 0.7,
                    "flags": [
                        review_flags.make_flag(
                            "low_confidence_extraction",
                            "Sub-lot U1's origin is stated as unconfirmed/pending upstream documentation.",
                            source="extraction",
                            field_name="origin_country",
                        ).model_dump()
                    ],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_unconfirmed_origin")
    assert resp.status_code == 200
    heat = resp.json()["heats"][0]

    assert heat["flagged_for_review"] is True
    low_conf_flag = next(f for f in heat["flags"] if f["issue_type"] == "low_confidence_extraction")
    assert low_conf_flag["field_name"] == "origin_country"
    assert heat["sublots"][0]["origin_confidence"] == "low"


# --- Baseline single-heat happy path and full multi-heat/sub-lot shape -----


def test_sample_fixture_extracts_cleanly_as_the_happy_path_baseline(client, conn, monkeypatch):
    """rio_grande_mtr_sample.pdf is the clean single-heat baseline (same
    document seed.py's own docstring references) — plainly-stated,
    unambiguous, fully-compliant content throughout. Confirms the happy
    path stays happy: zero flags, not flagged for review, every field
    populated exactly as stated."""

    def fake_extract_structured(raw_text):
        assert "Heat No.: RGM-NDFEB-2026-0412" in raw_text
        assert "Country of Origin: United States" in raw_text
        return {
            "certificate_id": "RGM-CERT-2026-0412",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [
                {"name": "Maria Alvarez", "title": "QA Lead", "org": "Rio Grande Magnetics, LLC", "role": "issuer"}
            ],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0412",
                    "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3},
                    "test_results": {
                        "Br (kG)": {"value": 13.2, "result": "pass"},
                        "Hci (kOe)": {"value": 11.8, "result": "pass"},
                        "BHmax (MGOe)": {"value": 42.0, "result": "pass"},
                    },
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": None,
                            "blend_pct": 100.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "100% domestically collected scrap (decommissioned motors, HDD magnets), single source, no blending",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": (
                        "Dedicated single-line sintering process; tooling purged and lot-tagged between "
                        "production runs; no shared feedstock with non-domestic or non-qualifying material."
                    ),
                    "mass_kg": 182.5,
                    "confidence": 0.95,
                    "flags": [],
                    "source": "llm",
                }
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_sample")
    assert resp.status_code == 200
    body = resp.json()

    assert body["certificate_id"] == "RGM-CERT-2026-0412"
    assert len(body["heats"]) == 1
    heat = body["heats"][0]

    assert heat["heat_id"] == "RGM-NDFEB-2026-0412"
    assert heat["mass_kg"] == 182.5
    assert heat["alloy_composition"] == {"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3}
    assert heat["segregation_attested"] is True
    assert heat["flagged_for_review"] is False
    assert heat["flags"] == []
    assert len(heat["sublots"]) == 1
    assert heat["sublots"][0]["origin_country"] == "United States"
    assert heat["sublots"][0]["origin_confidence"] == "high"
    assert heat["sublots"][0]["flagged"] is False


def test_complex_fixture_extracts_three_independent_heats_with_correct_sublots(client, conn, monkeypatch):
    """rio_grande_mtr_complex.pdf is a consolidated multi-heat
    certificate covering three heats/melts in one document. Unlike
    test_heats.py's test_upload_with_mocked_multi_heat_flagged_sublot
    (which uses placeholder H-1/H-2 ids purely to exercise the flagging
    logic), this confirms the multi-heat *extraction* itself against
    the fixture's real content: three heats correctly split out with
    their own distinct composition/mass/nonconformance/segregation
    data, not just that flags end up in the right place. Heat -0492's
    low-confidence sub-lot and heat -0493's China sub-lot (each
    independently triggering their own flag, same as test_heats.py's
    H-2 case) are confirmed too, since they're part of the same real
    document, but that's not the only thing being checked here."""

    def fake_extract_structured(raw_text):
        assert "CONSOLIDATED - MULTI-HEAT" in raw_text
        assert "Melt Ref.: RGM-NDFEB-2026-0491" in raw_text
        assert "Melt Ref.: RGM-NDFEB-2026-0492" in raw_text
        assert "Melt Ref.: RGM-NDFEB-2026-0493" in raw_text
        return {
            "certificate_id": "RGM-CERT-2026-0498",
            "supplier_id": "Rio Grande Magnetics, LLC",
            "signatures": [
                {"name": "Maria Alvarez", "title": "QA Lead", "org": "Rio Grande Magnetics, LLC", "role": "issuer"},
                {"name": "James Okafor", "title": "Plant Manager", "org": "Rio Grande Magnetics, LLC", "role": "witness"},
            ],
            "heats": [
                {
                    "heat_id": "RGM-NDFEB-2026-0491",
                    "alloy_composition": {"Nd": 29.8, "Fe": 67.9, "B": 1.1, "Dy": 1.2},
                    "test_results": {
                        "Br (kG)": {"value": 13.4, "result": "pass"},
                        "Hci (kOe)": {"value": 12.0, "result": "pass"},
                        "BHmax (MGOe)": {"value": 43.1, "result": "pass"},
                    },
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": "A1",
                            "blend_pct": 100.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "domestically collected scrap",
                        }
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated line, purged between runs.",
                    "mass_kg": 210.0,
                    "confidence": 0.95,
                    "flags": [],
                    "source": "llm",
                },
                {
                    "heat_id": "RGM-NDFEB-2026-0492",
                    "alloy_composition": {"Nd": 29.2, "Fe": 68.5, "B": 1.0, "Dy": 1.1},
                    "test_results": {
                        "Br (kG)": {"value": 13.0, "result": "marginal"},
                        "Hci (kOe)": {"value": 11.5, "result": "pass"},
                        "BHmax (MGOe)": {"value": 41.0, "result": "pass"},
                    },
                    "nonconformance_refs": ["NCR-2026-014 (Br marginally below target, disposition: use-as-is)"],
                    "feedstock_sublots": [
                        {
                            "sublot_id": "B1",
                            "blend_pct": 65.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "domestically collected scrap",
                        },
                        {
                            "sublot_id": "B2",
                            "blend_pct": 35.0,
                            "origin_country": None,
                            "origin_confidence": "low",
                            "notes": "broker-sourced, bonded warehouse, documentation pending",
                        },
                    ],
                    "segregation_attested": False,
                    "segregation_note": None,
                    "mass_kg": 95.0,
                    "confidence": 0.85,
                    "flags": [
                        review_flags.make_flag(
                            "low_confidence_extraction",
                            "Sub-lot B2's origin is unconfirmed, pending upstream documentation.",
                            source="extraction",
                            field_name="origin_country",
                            sublot_id="B2",
                        ).model_dump()
                    ],
                    "source": "llm",
                },
                {
                    "heat_id": "RGM-NDFEB-2026-0493",
                    "alloy_composition": {"Nd": 30.1, "Fe": 67.5, "B": 1.0, "Dy": 1.4},
                    "test_results": {
                        "Br (kG)": {"value": 13.5, "result": "pass"},
                        "Hci (kOe)": {"value": 12.2, "result": "pass"},
                        "BHmax (MGOe)": {"value": 43.5, "result": "pass"},
                    },
                    "nonconformance_refs": [],
                    "feedstock_sublots": [
                        {
                            "sublot_id": "C1",
                            "blend_pct": 80.0,
                            "origin_country": "United States",
                            "origin_confidence": "high",
                            "notes": "domestically collected scrap",
                        },
                        {
                            "sublot_id": "C2",
                            "blend_pct": 20.0,
                            "origin_country": "China",
                            "origin_confidence": "high",
                            "notes": "broker-sourced alloy addition",
                        },
                    ],
                    "segregation_attested": True,
                    "segregation_note": "Dedicated line; however Heat 3 includes a broker-sourced addition per sub-lot C2.",
                    "mass_kg": 120.0,
                    "confidence": 0.95,
                    "flags": [],
                    "source": "llm",
                },
            ],
        }

    monkeypatch.setattr(llm_extractor, "extract_structured", fake_extract_structured)
    _login_org_user(client, conn)
    resp = _upload_fixture(client, "rio_grande_mtr_complex")
    assert resp.status_code == 200
    body = resp.json()

    assert body["certificate_id"] == "RGM-CERT-2026-0498"
    assert len(body["heats"]) == 3

    heat1 = next(h for h in body["heats"] if h["heat_id"] == "RGM-NDFEB-2026-0491")
    heat2 = next(h for h in body["heats"] if h["heat_id"] == "RGM-NDFEB-2026-0492")
    heat3 = next(h for h in body["heats"] if h["heat_id"] == "RGM-NDFEB-2026-0493")

    # Heat 1: clean, single domestic sub-lot, no flags.
    assert heat1["mass_kg"] == 210.0
    assert heat1["alloy_composition"] == {"Nd": 29.8, "Fe": 67.9, "B": 1.1, "Dy": 1.2}
    assert heat1["segregation_attested"] is True
    assert heat1["flagged_for_review"] is False
    assert heat1["flags"] == []
    assert len(heat1["sublots"]) == 1

    # Heat 2: nonconformance ref carried through, not segregation-attested,
    # two sub-lots, B2's low-confidence origin flagged.
    assert heat2["mass_kg"] == 95.0
    assert heat2["alloy_composition"] == {"Nd": 29.2, "Fe": 68.5, "B": 1.0, "Dy": 1.1}
    assert heat2["nonconformance_refs"] == ["NCR-2026-014 (Br marginally below target, disposition: use-as-is)"]
    assert heat2["segregation_attested"] is False
    assert len(heat2["sublots"]) == 2
    b1 = next(s for s in heat2["sublots"] if s["sublot_id"] == "B1")
    b2 = next(s for s in heat2["sublots"] if s["sublot_id"] == "B2")
    assert b1["blend_pct"] == 65.0
    assert b1["origin_country"] == "United States"
    assert b2["blend_pct"] == 35.0
    assert b2["origin_confidence"] == "low"
    assert b2["flagged"] is True
    assert heat2["flagged_for_review"] is True
    assert any(f["issue_type"] == "low_confidence_extraction" for f in heat2["flags"])

    # Heat 3: China sub-lot independently flagged compliance_violation by
    # main.py's deterministic check, same as test_heats.py's H-2 case —
    # regardless of what the (mocked) model's own flags list said (empty).
    assert heat3["mass_kg"] == 120.0
    assert heat3["alloy_composition"] == {"Nd": 30.1, "Fe": 67.5, "B": 1.0, "Dy": 1.4}
    assert len(heat3["sublots"]) == 2
    c2 = next(s for s in heat3["sublots"] if s["sublot_id"] == "C2")
    assert c2["origin_country"] == "China"
    assert c2["flagged"] is True
    assert heat3["flagged_for_review"] is True
    china_flag = next(f for f in heat3["flags"] if f["issue_type"] == "compliance_violation")
    assert "FEOC-covered" in china_flag["human_readable_reason"]
    assert china_flag["severity"] == "blocking"
    assert china_flag["source"] == "compliance_engine"
