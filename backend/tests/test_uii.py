"""UII / Data Matrix generation and the binding routes."""
import sqlite3
from urllib.parse import parse_qs, quote, urlparse

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


# --- Construct #1 UII wired into issuance and the passport lookup path -----


def _login_org_user(client, conn, iac=None, enterprise_id=None):
    org_id = make_issuer(conn, iac=iac, enterprise_id=enterprise_id)
    make_user(conn, "u@example.com", "pw", "org_user", org_id)
    client.post("/auth/login", json={"email": "u@example.com", "password": "pw"})
    return org_id


def test_issuance_generates_real_construct_1_uii_when_issuer_has_iac_and_eid(client, conn):
    _login_org_user(client, conn, iac="UN", enterprise_id="123456789")
    cred = _issue_credential(client)

    binding_row = conn.execute(
        "SELECT uii_code FROM uii_bindings WHERE credential_id = ?", (cred["id"],)
    ).fetchone()
    expected = uii.generate_uii("UN", "123456789", cred["id"])
    assert binding_row["uii_code"] == expected
    assert binding_row["uii_code"] != cred["id"]


def test_issuance_falls_back_to_legacy_uii_code_when_issuer_has_no_iac(client, conn):
    _login_org_user(client, conn)  # no iac/enterprise_id registered
    cred = _issue_credential(client)

    binding_row = conn.execute(
        "SELECT uii_code FROM uii_bindings WHERE credential_id = ?", (cred["id"],)
    ).fetchone()
    assert binding_row["uii_code"] == cred["id"]


def test_passport_url_query_param_carries_the_real_uii_not_the_raw_credential_id(client, conn):
    _login_org_user(client, conn, iac="UN", enterprise_id="123456789")
    cred = _issue_credential(client)

    binding_resp = client.get(f"/credentials/{cred['id']}/uii").json()
    expected_bare_uii = uii.generate_uii("UN", "123456789", cred["id"])
    expected_scan_payload = uii.wrap_scan_payload(expected_bare_uii)
    id_param = parse_qs(urlparse(binding_resp["passport_url"]).query)["id"][0]
    # the enveloped (scannable) form is what's in the URL, not the bare
    # UII value and definitely not the raw credential_id
    assert id_param == expected_scan_payload
    assert id_param != expected_bare_uii
    assert id_param != cred["id"]


def test_scan_lookup_resolves_a_real_construct_1_uii(client, conn):
    _login_org_user(client, conn, iac="UN", enterprise_id="123456789")
    cred = _issue_credential(client)

    real_uii_scan_payload = uii.wrap_scan_payload(uii.generate_uii("UN", "123456789", cred["id"]))
    resp = client.get(f"/passport/{quote(real_uii_scan_payload, safe='')}")
    assert resp.status_code == 200
    assert resp.json()["credential_id"] == cred["id"]


def test_scan_lookup_still_resolves_legacy_bare_credential_id(client, conn):
    _login_org_user(client, conn)  # no iac/enterprise_id -> legacy uii_code
    cred = _issue_credential(client)

    resp = client.get(f"/passport/{cred['id']}")
    assert resp.status_code == 200
    assert resp.json()["credential_id"] == cred["id"]


def test_malformed_scan_returns_400_not_404(client):
    text = "[)>" + "\x1e" + "06" + "\x1d" + "25SGARBAGE"  # no trailing RS+EOT — truncated
    resp = client.get(f"/passport/{quote(text, safe='')}")
    assert resp.status_code == 400
    assert "malformed" in resp.json()["detail"].lower()


def test_spoofed_well_formed_uii_that_was_never_issued_404s_not_false_match(client, conn):
    """Spoofing regression: a syntactically valid Construct #1 UII, using
    a real registered issuer prefix but a serial that was never actually
    issued, must 404 as not-found — never resolve to some other
    credential, even one issued under the exact same issuer prefix."""
    _login_org_user(client, conn, iac="UN", enterprise_id="123456789")
    real_cred = _issue_credential(client)  # a real credential DOES exist under this issuer

    spoofed_bare = uii.generate_uii("UN", "123456789", "f" * 32)  # never-issued serial
    real_bare = uii.generate_uii("UN", "123456789", real_cred["id"])
    assert spoofed_bare != real_bare  # sanity: genuinely different

    resp = client.get(f"/passport/{quote(uii.wrap_scan_payload(spoofed_bare), safe='')}")
    assert resp.status_code == 404


def test_audit_trail_marks_legacy_resolution_distinctly_from_real_uii_resolution(client, conn):
    _login_org_user(client, conn, iac="UN", enterprise_id="123456789")
    cred = _issue_credential(client)
    real_uii_scan_payload = uii.wrap_scan_payload(uii.generate_uii("UN", "123456789", cred["id"]))

    client.get(f"/passport/{quote(real_uii_scan_payload, safe='')}")  # real Construct #1 UII lookup
    client.get(f"/passport/{cred['id']}")  # legacy-shaped (bare id) lookup, same credential

    trail = client.get(f"/credentials/{cred['id']}/audit-trail").json()
    viewed = [e for e in trail["audit_log"] if e["action"] == "passport_viewed"]
    assert len(viewed) == 2
    assert viewed[0]["detail"] == {}
    assert viewed[1]["detail"] == {"is_legacy": True}


# --- MIL-STD-130 Construct #1 UII generator/parser --------------------------
# Isolated, DB-free unit tests: generate_uii/parse_uii take plain data and
# injected resolver callables, not a live DB connection, so these don't need
# the client/conn fixtures above. NOT wired into issuance/main.py/scan.html
# yet — see uii.py's module docstring.

IAC = "UN"
ENTERPRISE_ID = "123456789"
CRED_ID = "0123456789abcdef0123456789abcdef"  # uuid4().hex-shaped
KNOWN_PREFIXES = {f"{IAC}{ENTERPRISE_ID}": (IAC, ENTERPRISE_ID)}


def _resolvers(uii_bindings=None, legacy_ids=None):
    """Fake stand-ins for the real DB-backed lookups main.py will supply
    once this is wired in — a plain dict is enough to exercise every
    parse_uii branch without a DB."""
    uii_bindings = uii_bindings or {}
    legacy_ids = legacy_ids or {}
    return (lambda uii_code: uii_bindings.get(uii_code), lambda text: legacy_ids.get(text))


def test_generate_uii_produces_bare_canonical_value_no_envelope():
    generated = uii.generate_uii(IAC, ENTERPRISE_ID, CRED_ID)
    assert generated == f"{IAC}{ENTERPRISE_ID}{CRED_ID.upper()}"
    assert not generated.startswith("[)>")


def test_wrap_scan_payload_produces_expected_construct_1_envelope():
    bare = uii.generate_uii(IAC, ENTERPRISE_ID, CRED_ID)
    wrapped = uii.wrap_scan_payload(bare)
    assert wrapped == f"[)>\x1e06\x1d25S{IAC}{ENTERPRISE_ID}{CRED_ID.upper()}\x1e\x04"


def test_generate_then_parse_roundtrips_to_found():
    scan_payload = uii.wrap_scan_payload(uii.generate_uii(IAC, ENTERPRISE_ID, CRED_ID))
    resolve_uii, resolve_legacy = _resolvers(
        uii_bindings={f"{IAC}{ENTERPRISE_ID}{CRED_ID.upper()}": "cred-row-id"}
    )
    result = uii.parse_uii(scan_payload, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "found"
    assert result.is_legacy is False
    assert result.credential_id == "cred-row-id"
    assert result.iac == IAC
    assert result.enterprise_id == ENTERPRISE_ID
    assert result.serial == CRED_ID.upper()


def test_well_formed_uii_with_no_matching_binding_is_not_found():
    scan_payload = uii.wrap_scan_payload(uii.generate_uii(IAC, ENTERPRISE_ID, CRED_ID))
    resolve_uii, resolve_legacy = _resolvers()  # nothing registered
    result = uii.parse_uii(scan_payload, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "not_found"
    assert result.is_legacy is False
    assert result.credential_id is None
    assert result.serial == CRED_ID.upper()  # fields still extracted even without a match


def test_malformed_envelope_missing_record_separator():
    text = "[)>06\x1d25SUN123456789SERIAL\x1e\x04"  # header not followed by RS
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "record separator" in result.reason


def test_malformed_envelope_wrong_format_number():
    text = "[)>\x1e05\x1d25SUN123456789SERIAL\x1e\x04"  # GS1 format 05, not MH10 format 06
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "format number" in result.reason


def test_malformed_envelope_truncated_missing_trailer():
    text = "[)>\x1e06\x1d25SUN123456789SERIAL"  # no trailing RS+EOT
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "trailing" in result.reason


def test_malformed_no_recognizable_data_identifier():
    text = "[)>\x1e06\x1d99ZSOMEUNRELATEDDATA\x1e\x04"
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "25S" in result.reason


def test_construct_2_shaped_message_is_rejected_as_unsupported_not_misparsed():
    # Construct #2 splits enterprise id (18V) and part number (1P) into
    # their own elements instead of one concatenated 25S — must not be
    # mistaken for Construct #1.
    text = f"[)>\x1e06\x1d18V{IAC}{ENTERPRISE_ID}\x1d1PPARTNUMBER123\x1dSSERIAL456\x1e\x04"
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "unsupported_construct"
    assert result.credential_id is None


def test_unrecognized_issuer_prefix_is_malformed():
    text = "[)>\x1e06\x1d25SZZ999999999SERIAL\x1e\x04"  # ZZ999999999 not a known issuer
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "prefix not recognized" in result.reason


def test_known_prefix_with_no_serial_is_malformed():
    text = f"[)>\x1e06\x1d25S{IAC}{ENTERPRISE_ID}\x1e\x04"  # prefix matches, nothing after it
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "no serial number" in result.reason


def test_serial_with_invalid_charset_is_malformed():
    text = f"[)>\x1e06\x1d25S{IAC}{ENTERPRISE_ID}lowercase-serial\x1e\x04"
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(text, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "A-Z0-9" in result.reason


def test_legacy_bare_credential_id_resolves_and_is_flagged_as_legacy():
    legacy_id = "legacy-cred-id-1234"
    resolve_uii, resolve_legacy = _resolvers(legacy_ids={legacy_id: "cred-row-id"})
    result = uii.parse_uii(legacy_id, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "found"
    assert result.is_legacy is True
    assert result.credential_id == "cred-row-id"


def test_unrecognized_text_with_no_envelope_and_no_legacy_match_is_not_found():
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii("total-garbage-not-a-uii-and-not-an-id", KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "not_found"
    assert result.is_legacy is True


def test_empty_payload_is_malformed():
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii("   ", KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "malformed"
    assert "empty" in result.reason


def test_very_long_garbage_string_does_not_crash():
    garbage = "X" * 5000
    resolve_uii, resolve_legacy = _resolvers()
    result = uii.parse_uii(garbage, KNOWN_PREFIXES, resolve_uii, resolve_legacy)
    assert result.outcome == "not_found"  # no envelope -> legacy path -> no match
    assert result.is_legacy is True
