"""Tests for org_config.py, and the regression case the whole refactor
exists to prove: onboarding a second design partner with a genuinely
different materials-scope list and document terminology is a config file,
not a change to llm_extractor.py or passport.py.

"Structurally different" here means: a different accepted document_type,
different heat_id label wording, and a materials-scope list that shares NO
keywords with Rio Grande Magnetics' real config or DEFAULT_CONFIG — proving
per-org isolation, not just "any org's list happens to match." A fictional
"Acme Tantalum Components" (tantalum capacitor-grade powder, not a magnet
recycler) is used, in the same spirit as seed.py's own fictional Rio Grande
Magnetics.
"""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import llm_extractor
import main
import org_config
import passport as passport_engine
import storage
from db import LEGACY_KEY_ID, SCHEMA
from seed import issue_credential

ACME_CONFIG = {
    "org_name": "Acme Tantalum Components",
    "document_types": ["tantalum_mtr"],
    "heat_id_label_hint": "This supplier's certs label the batch as 'Lot No.' or 'Batch Ref.', never 'Heat No.'.",
    "materials_scope": ["ta-205", "tantalum capacitor-grade powder"],
}


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(storage, "OBJECTS_DIR", tmp_path / "objects")
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    yield c
    c.close()


@pytest.fixture
def acme_config_dir(tmp_path, monkeypatch):
    """Points org_config.CONFIG_DIR at an isolated tmp dir containing only
    Acme's config — proves the mechanism generically instead of coupling
    this test to the real config/orgs/riograndemagnetics.json on disk."""
    config_dir = tmp_path / "config-orgs"
    config_dir.mkdir()
    slug = org_config.org_slug(ACME_CONFIG["org_name"])
    (config_dir / f"{slug}.json").write_text(json.dumps(ACME_CONFIG))
    monkeypatch.setattr(org_config, "CONFIG_DIR", config_dir)
    return config_dir


def make_issuer(conn, name):
    issuer_id = "issuer-" + org_config.org_slug(name)
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, name, public_key_b64, private_key_path, "2026-01-01T00:00:00Z"),
    )
    conn.execute(
        """
        INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
        VALUES (?, ?, ?, '2026-01-01T00:00:00Z', NULL, NULL, 'test', '2026-01-01T00:00:00Z')
        """,
        (issuer_id, LEGACY_KEY_ID, public_key_b64),
    )
    conn.commit()
    return issuer_id, private_key_path


# ---- org_config.py's own mechanics ----


def test_org_slug_normalizes_name():
    assert org_config.org_slug("Rio Grande Magnetics") == "riograndemagnetics"
    assert org_config.org_slug("Acme Tantalum Components") == "acmetantalumcomponents"


def test_load_config_for_org_name_falls_back_to_default_when_no_file_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(org_config, "CONFIG_DIR", tmp_path / "empty-dir-no-configs")
    cfg = org_config.load_config_for_org_name("Some Org With No Config File")
    assert cfg is org_config.DEFAULT_CONFIG


def test_load_config_for_org_name_reads_the_real_file_when_it_exists(acme_config_dir):
    cfg = org_config.load_config_for_org_name("Acme Tantalum Components")
    assert cfg == ACME_CONFIG


def test_load_config_for_issuer_resolves_via_the_issuers_table(conn, acme_config_dir):
    issuer_id, _ = make_issuer(conn, "Acme Tantalum Components")
    cfg = org_config.load_config_for_issuer(conn, issuer_id)
    assert cfg == ACME_CONFIG


def test_load_config_for_issuer_falls_back_to_default_for_unknown_issuer_id(conn):
    cfg = org_config.load_config_for_issuer(conn, "no-such-issuer")
    assert cfg is org_config.DEFAULT_CONFIG


# ---- llm_extractor.py: proves the extraction schema is genuinely
# org-parameterized, with zero code change, via the public
# extract_structured/_build_tool surface ----


def test_build_tool_embeds_the_calling_orgs_heat_id_hint_not_a_hardcoded_one():
    tool = llm_extractor._build_tool(ACME_CONFIG)
    heat_schema = tool["input_schema"]["properties"]["heats"]["items"]
    assert heat_schema["properties"]["heat_id"]["description"] == ACME_CONFIG["heat_id_label_hint"]
    # Not Rio Grande's / the default's hint leaking through:
    assert heat_schema["properties"]["heat_id"]["description"] != org_config.DEFAULT_CONFIG["heat_id_label_hint"]


def test_extract_structured_regex_fallback_is_unaffected_by_org_cfg(monkeypatch):
    # The regex fallback path (no API key) never reads org_cfg at all --
    # confirms passing a structurally different org doesn't need any
    # special-casing here, since org_cfg only matters on the LLM path.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = llm_extractor.extract_structured("Supplier: Acme\n", ACME_CONFIG)
    assert result["heats"][0]["source"] == "regex"


# ---- passport.py: proves materials-scope checking is genuinely
# per-issuer, with zero code change, using two orgs whose scopes don't
# overlap at all ----


def test_material_in_scope_for_acme_but_not_for_default_scope():
    assert passport_engine._material_in_scope("Ta-205 Capacitor Grade Powder", ACME_CONFIG["materials_scope"])
    assert not passport_engine._material_in_scope(
        "Ta-205 Capacitor Grade Powder", org_config.DEFAULT_CONFIG["materials_scope"]
    )


def test_credential_in_acmes_scope_passes_when_issued_by_acme(conn, acme_config_dir):
    issuer_id, key_path = make_issuer(conn, "Acme Tantalum Components")
    subject = {
        "material_type": "Ta-205 Capacitor Grade Powder",
        "origin_country": "United States",
        "mass_kg": 50.0,
    }
    cred_id = issue_credential(conn, issuer_id, key_path, "tantalum_batch", subject, None, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "pass"
    assert result["nodes"][0]["node_status"] == "pass"


def test_ndfeb_material_is_out_of_scope_for_acme_even_though_its_in_scope_for_rio_grande(conn, acme_config_dir):
    # The exact material_type that's squarely in-scope for Rio Grande
    # Magnetics (and for DEFAULT_CONFIG) must read as insufficient_data --
    # not pass -- when the issuing org is Acme, whose materials_scope has
    # no NdFeB/neodymium keyword at all. This is the core proof that scope
    # is per-issuer, not a single global list any credential can match.
    issuer_id, key_path = make_issuer(conn, "Acme Tantalum Components")
    subject = {
        "material_type": "Sintered NdFeB Magnet Alloy (N42)",
        "origin_country": "United States",
        "mass_kg": 50.0,
    }
    cred_id = issue_credential(conn, issuer_id, key_path, "ndfeb_batch", subject, None, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "insufficient_data"
    assert any("outside the DFARS rare-earth scope" in r for r in result["nodes"][0]["reasons"])
    assert any("Acme Tantalum Components" in r for r in result["nodes"][0]["reasons"])


def test_reason_string_lists_the_calling_orgs_own_scope_not_a_hardcoded_one(conn, acme_config_dir):
    issuer_id, key_path = make_issuer(conn, "Acme Tantalum Components")
    subject = {"material_type": "Stainless Steel Fastener", "origin_country": "United States", "mass_kg": 1.0}
    cred_id = issue_credential(conn, issuer_id, key_path, "unrelated_part", subject, None, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    reason = result["nodes"][0]["reasons"][0]
    for keyword in ACME_CONFIG["materials_scope"]:
        assert keyword in reason
    # And not Rio Grande's/default's keywords, which share no terms with Acme's:
    assert "ndfeb" not in reason.lower()


# ---- main.py integration: the document_type acceptance gate this
# refactor's config also drives (light enforcement added alongside the
# schema/scope move — see main.py's upload_document). Same TestClient +
# dependency-override pattern as test_heats.py/test_auth.py, not an ad hoc
# one, so this exercises the real session/auth path rather than bypassing it.


@pytest.fixture
def api_conn(tmp_path, monkeypatch):
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
def api_client(api_conn):
    def override_get_db():
        yield api_conn

    main.app.dependency_overrides[main.get_db] = override_get_db
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def _login_acme_org_user(api_client, api_conn):
    issuer_id, _ = make_issuer(api_conn, "Acme Tantalum Components")
    user_id = "user-acme"
    api_conn.execute(
        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, issuer_id, "acme@example.com", auth.hash_password("pw"), "org_user", "2026-01-01T00:00:00Z"),
    )
    api_conn.commit()
    api_client.post("/auth/login", json={"email": "acme@example.com", "password": "pw"})
    return issuer_id


def test_upload_rejects_a_document_type_not_in_the_orgs_config(api_client, api_conn, acme_config_dir):
    _login_acme_org_user(api_client, api_conn)
    resp = api_client.post(
        "/documents/upload",
        files={"file": ("cert.txt", b"Supplier: Acme\n", "text/plain")},
        data={"document_type": "mtr_coc"},  # Rio Grande's/DEFAULT's type, not Acme's
    )
    assert resp.status_code == 400
    assert "not accepted for Acme Tantalum Components" in resp.json()["detail"]


def test_upload_accepts_the_orgs_own_configured_document_type(api_client, api_conn, acme_config_dir):
    _login_acme_org_user(api_client, api_conn)
    resp = api_client.post(
        "/documents/upload",
        files={"file": ("cert.txt", b"Supplier: Acme\n", "text/plain")},
        data={"document_type": "tantalum_mtr"},
    )
    assert resp.status_code == 200


def test_document_type_rejection_is_driven_by_the_orgs_config_not_a_separate_hardcoded_gate(
    api_client, api_conn, acme_config_dir, monkeypatch
):
    """Negative control for the 400 above: widen Acme's own config (via
    org_config.load_config_for_issuer, the exact function main.py's
    upload_document calls) to also accept 'mtr_coc', and send the *identical*
    request test_upload_rejects_a_document_type_not_in_the_orgs_config sends.
    It must now succeed -- proving the 400 is genuinely sourced from
    org_cfg["document_types"], not some other/hardcoded check that happens
    to also reject 'mtr_coc' for unrelated reasons."""
    _login_acme_org_user(api_client, api_conn)
    widened = {**ACME_CONFIG, "document_types": ["tantalum_mtr", "mtr_coc"]}
    monkeypatch.setattr(main.org_config, "load_config_for_issuer", lambda conn, issuer_id: widened)

    resp = api_client.post(
        "/documents/upload",
        files={"file": ("cert.txt", b"Supplier: Acme\n", "text/plain")},
        data={"document_type": "mtr_coc"},
    )
    assert resp.status_code == 200
