"""Stage 4 of the client-side key custody redesign: passport.py's
_evaluate_node now checks "was this key_id valid for this issuer when
this credential was signed" instead of "is this the issuer's current
public_key" -- the structural fix for the bug the whole redesign
started from (a routine key rotation used to retroactively break every
credential signed under the previous key).

Uses compile_passport directly against an in-memory DB built from the
real schema, constructing issuer_keys rows by hand to control exact
valid_from/valid_to/revoked_at windows -- the thing this stage is
actually about, not exercised by any HTTP-level test.
"""
import base64
import hashlib
import json
import sqlite3
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import crypto_utils
import passport as passport_engine
import storage
from crypto_utils import canonical_bytes, credential_signable_payload
from db import SCHEMA

US_NDFEB_SUBJECT = {
    "material_type": "Sintered NdFeB Magnet Alloy (N42)",
    "origin_country": "United States",
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


def make_issuer(conn, name="Test Issuer", created_at="2026-01-01T00:00:00+00:00"):
    issuer_id = "issuer-" + name.replace(" ", "-").lower()
    # A legacy platform-held key still on issuers.public_key/private_key_path
    # -- unused by verification after this stage, but the column still
    # exists (frozen), and make_issuer_key below is what verification
    # actually reads from now.
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, name, public_key_b64, private_key_path, created_at),
    )
    conn.commit()
    return issuer_id


def make_key(conn, issuer_id, key_id, valid_from, valid_to=None, revoked_at=None, registered_by="test"):
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    conn.execute(
        """
        INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (issuer_id, key_id, public_key_b64, valid_from, valid_to, revoked_at, registered_by, valid_from),
    )
    conn.commit()
    return private_key


def insert_credential(conn, issuer_id, key_id, private_key, cred_id=None, issued_at="2026-01-15T00:00:00+00:00", subject=None):
    """Signs and inserts a credential row directly -- bypasses the HTTP
    two-phase flow entirely (this file is about verification, not
    issuance), same spirit as test_passport.py's own direct-insert
    style but hand-rolled since it needs to sign with an arbitrary
    caller-supplied key, not always the issuer's current one."""
    cred_id = cred_id or uuid.uuid4().hex
    subject = subject or US_NDFEB_SUBJECT
    payload = credential_signable_payload(
        id=cred_id, issuer_id=issuer_id, credential_type="collected_scrap_lot",
        subject=subject, sources=[], segregation_attested=False, segregation_attested_by=None,
        segregation_note=None, document_id=None, document_content_hash=None, issued_at=issued_at,
    )
    signature_b64 = base64.b64encode(private_key.sign(canonical_bytes(payload))).decode("ascii")
    payload_hash = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    conn.execute(
        """
        INSERT INTO credentials (
            id, issuer_id, credential_type, subject_json, sources_json,
            segregation_attested, segregation_attested_by, segregation_note,
            document_id, document_content_hash, heat_id, key_id, payload_hash, signature,
            superseded_by, revoked_at, issued_at
        ) VALUES (?, ?, 'collected_scrap_lot', ?, '[]', 0, NULL, NULL, NULL, NULL, NULL, ?, ?, ?, NULL, NULL, ?)
        """,
        (cred_id, issuer_id, json.dumps(subject), key_id, payload_hash, signature_b64, issued_at),
    )
    conn.commit()
    return cred_id


def test_legacy_credential_still_verifies_via_issuer_keys_lookup(conn):
    """The exact regression Stage 1's migration exists to protect --
    now exercised through the real replacement lookup (issuer_keys),
    not the frozen issuers.public_key column this stage stops reading."""
    issuer_id = make_issuer(conn)
    private_key = make_key(conn, issuer_id, "legacy-platform-held", valid_from="2026-01-01T00:00:00+00:00")
    cred_id = insert_credential(conn, issuer_id, "legacy-platform-held", private_key, issued_at="2026-01-05T00:00:00+00:00")

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "pass", result["nodes"][0]["reasons"]


def test_credential_signed_under_superseded_key_still_verifies_in_its_own_window(conn):
    """The actual bug fix: rotating to a new key must NOT retroactively
    break a credential signed while the old key was legitimately
    active. old_key is valid [T1, T2); the credential was issued at T1
    (start of old_key's window, well before the rotation to new_key at
    T2) -- must still verify pass, even though old_key is no longer
    the issuer's current key by the time this passport is compiled."""
    issuer_id = make_issuer(conn)
    old_key = make_key(conn, issuer_id, "key-1", valid_from="2026-01-01T00:00:00+00:00", valid_to="2026-02-01T00:00:00+00:00")
    make_key(conn, issuer_id, "key-2", valid_from="2026-02-01T00:00:00+00:00")  # the rotation

    cred_id = insert_credential(conn, issuer_id, "key-1", old_key, issued_at="2026-01-15T00:00:00+00:00")

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "pass", result["nodes"][0]["reasons"]


def test_credential_signed_after_rotation_under_new_key_verifies_too(conn):
    """The other half of the same story -- a credential issued AFTER
    rotation, signed with the new key, verifies against the new key's
    own window, independent of the old one."""
    issuer_id = make_issuer(conn)
    make_key(conn, issuer_id, "key-1", valid_from="2026-01-01T00:00:00+00:00", valid_to="2026-02-01T00:00:00+00:00")
    new_key = make_key(conn, issuer_id, "key-2", valid_from="2026-02-01T00:00:00+00:00")

    cred_id = insert_credential(conn, issuer_id, "key-2", new_key, issued_at="2026-02-15T00:00:00+00:00")

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "pass", result["nodes"][0]["reasons"]


def test_credential_issued_outside_its_keys_validity_window_fails(conn):
    """Data-integrity/tamper case: a credential row claiming a key_id
    and issued_at combination that doesn't fall inside that key's own
    valid_from/valid_to window -- must fail even if (as constructed
    here) the signature is otherwise cryptographically genuine, since a
    key can't attest to something before it existed or after it was
    retired."""
    issuer_id = make_issuer(conn)
    private_key = make_key(conn, issuer_id, "key-1", valid_from="2026-03-01T00:00:00+00:00")
    # issued_at predates key-1's own valid_from
    cred_id = insert_credential(conn, issuer_id, "key-1", private_key, issued_at="2026-01-01T00:00:00+00:00")

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "fail"
    assert any("was not valid" in r for r in result["nodes"][0]["reasons"])


def test_revoked_key_retroactively_fails_every_credential_it_ever_signed(conn):
    """Sign-off #1: retroactive. Both credentials were issued while the
    key was genuinely active and unrevoked -- once revoked_at is set,
    BOTH must flip to revoked, not just ones issued after the
    revocation timestamp, since revoked_at is only a detection-time
    proxy for an unknown true compromise time."""
    issuer_id = make_issuer(conn)
    private_key = make_key(conn, issuer_id, "key-1", valid_from="2026-01-01T00:00:00+00:00")
    early_cred = insert_credential(conn, issuer_id, "key-1", private_key, issued_at="2026-01-02T00:00:00+00:00")
    later_cred = insert_credential(conn, issuer_id, "key-1", private_key, issued_at="2026-01-20T00:00:00+00:00")

    # Both verify cleanly before revocation.
    assert passport_engine.compile_passport(conn, early_cred)["verdict"] == "pass"
    assert passport_engine.compile_passport(conn, later_cred)["verdict"] == "pass"

    conn.execute(
        "UPDATE issuer_keys SET revoked_at = ? WHERE issuer_id = ? AND key_id = ?",
        ("2026-01-25T00:00:00+00:00", issuer_id, "key-1"),
    )
    conn.commit()

    early_result = passport_engine.compile_passport(conn, early_cred)
    later_result = passport_engine.compile_passport(conn, later_cred)
    assert early_result["verdict"] == "revoked", early_result["nodes"][0]["reasons"]
    assert later_result["verdict"] == "revoked", later_result["nodes"][0]["reasons"]
    assert any("compromised" in r for r in early_result["nodes"][0]["reasons"])


def test_revoked_outranks_a_simultaneous_window_validity_failure(conn):
    """Both problems are genuinely true at once here (issued outside
    the key's own valid_from window, AND that key is revoked) --
    "revoked" (rank 3) must still headline over "fail" (rank 2) via
    downgrade()'s existing rank ordering, exercised here specifically
    through the new key-based checks, not just trusted from
    test_passport.py's coverage of downgrade() in the abstract."""
    issuer_id = make_issuer(conn)
    private_key = make_key(
        conn, issuer_id, "key-1",
        valid_from="2026-03-01T00:00:00+00:00",
        revoked_at="2026-04-01T00:00:00+00:00",
    )
    cred_id = insert_credential(conn, issuer_id, "key-1", private_key, issued_at="2026-01-01T00:00:00+00:00")

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "revoked"
    reasons = result["nodes"][0]["reasons"]
    assert any("was not valid" in r for r in reasons)
    assert any("compromised" in r for r in reasons)


def test_unknown_key_id_fails_closed(conn):
    issuer_id = make_issuer(conn)
    private_key = make_key(conn, issuer_id, "key-1", valid_from="2026-01-01T00:00:00+00:00")
    cred_id = insert_credential(conn, issuer_id, "key-1", private_key, issued_at="2026-01-05T00:00:00+00:00")
    # Simulate a credential whose key_id was never actually registered
    # (shouldn't happen via the real issuance path, but verification
    # must fail closed, not raise, if it ever does).
    conn.execute("UPDATE credentials SET key_id = 'never-registered' WHERE id = ?", (cred_id,))
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)
    assert result["verdict"] == "fail"
    assert any("signing key record missing" in r for r in result["nodes"][0]["reasons"])
