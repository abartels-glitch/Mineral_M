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
            "supplier_id": "Rio Grande Magnetics, LLC",
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
