"""Regression coverage for the issuer_keys migration (db._migrate_issuer_keys).

Built against a hand-rolled pre-migration schema, deliberately NOT
db.SCHEMA -- SCHEMA already has the post-migration shape baked in once
this change lands, so testing the migration itself requires simulating
what a real, existing dev DB looked like *before* this change: an
issuers table with public_key/private_key_path and no issuer_keys
table, a credentials table with no key_id column.
"""
import json
import sqlite3

import pytest

import crypto_utils
import db
import passport as passport_engine
from crypto_utils import credential_signable_payload, sign_payload

PRE_MIGRATION_SCHEMA = """
CREATE TABLE issuers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    iac TEXT,
    enterprise_id TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE documents (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL REFERENCES issuers(id),
    filename TEXT NOT NULL,
    document_type TEXT NOT NULL,
    object_key TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    certificate_id TEXT,
    supplier_id TEXT,
    signatures_json TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'uploaded',
    uploaded_at TEXT NOT NULL
);
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    issuer_id TEXT NOT NULL REFERENCES issuers(id),
    credential_type TEXT NOT NULL,
    subject_json TEXT NOT NULL,
    sources_json TEXT NOT NULL DEFAULT '[]',
    segregation_attested INTEGER NOT NULL DEFAULT 0,
    segregation_attested_by TEXT,
    segregation_note TEXT,
    document_id TEXT REFERENCES documents(id),
    document_content_hash TEXT,
    heat_id TEXT,
    payload_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    superseded_by TEXT REFERENCES credentials(id),
    revoked_at TEXT,
    issued_at TEXT NOT NULL
);
"""


@pytest.fixture
def pre_migration_conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(PRE_MIGRATION_SCHEMA)
    yield c
    c.close()


def _seed_legacy_issuer_and_credential(conn, issuer_id="issuer-legacy", created_at="2026-01-01T00:00:00+00:00"):
    """A pre-migration issuer/credential, signed exactly the way seed.py
    and today's issue_credential do -- one platform-generated keypair,
    stored as a PEM file, referenced only by issuers.public_key."""
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, "Legacy Test Issuer", public_key_b64, private_key_path, created_at),
    )
    subject = {"material_type": "Sintered NdFeB Magnet Alloy", "origin_country": "United States"}
    issued_at = "2026-01-02T00:00:00+00:00"
    cred_id = "cred-legacy-1"
    payload = credential_signable_payload(
        id=cred_id, issuer_id=issuer_id, credential_type="collected_scrap_lot",
        subject=subject, sources=[], segregation_attested=False, segregation_attested_by=None,
        segregation_note=None, document_id=None, document_content_hash=None, issued_at=issued_at,
    )
    signature, payload_hash = sign_payload(private_key_path, payload)
    conn.execute(
        """
        INSERT INTO credentials (
            id, issuer_id, credential_type, subject_json, sources_json,
            segregation_attested, segregation_attested_by, segregation_note,
            document_id, document_content_hash, heat_id, payload_hash, signature,
            superseded_by, revoked_at, issued_at
        ) VALUES (?, ?, 'collected_scrap_lot', ?, '[]', 0, NULL, NULL, NULL, NULL, NULL, ?, ?, NULL, NULL, ?)
        """,
        (cred_id, issuer_id, json.dumps(subject), payload_hash, signature, issued_at),
    )
    conn.commit()
    return issuer_id, cred_id


def test_fixture_really_is_pre_migration(pre_migration_conn):
    """Not a product assertion -- just confirms the hand-rolled schema
    above genuinely lacks issuer_keys/credentials.key_id, so the test
    below is a real regression check against a real "before" state, not
    a tautology against a schema that already has the new shape."""
    with pytest.raises(sqlite3.OperationalError):
        pre_migration_conn.execute("SELECT key_id FROM credentials")
    with pytest.raises(sqlite3.OperationalError):
        pre_migration_conn.execute("SELECT * FROM issuer_keys")


def test_migration_backfills_legacy_key_and_credential_still_verifies(pre_migration_conn):
    issuer_id, cred_id = _seed_legacy_issuer_and_credential(pre_migration_conn)

    # issuer_keys has to exist before the migration function can populate
    # it -- in the real app this comes from SCHEMA's own
    # CREATE TABLE IF NOT EXISTS, run here directly since this test
    # deliberately isn't using the post-migration SCHEMA string wholesale.
    pre_migration_conn.executescript(db.ISSUER_KEYS_TABLE_SQL)
    db._migrate_issuer_keys(pre_migration_conn)
    pre_migration_conn.commit()

    key_row = pre_migration_conn.execute(
        "SELECT * FROM issuer_keys WHERE issuer_id = ? AND key_id = 'legacy-platform-held'", (issuer_id,)
    ).fetchone()
    assert key_row is not None, "expected a synthesized legacy-platform-held row for this issuer"
    assert key_row["valid_to"] is None
    assert key_row["revoked_at"] is None
    assert key_row["valid_from"] == "2026-01-01T00:00:00+00:00", "valid_from should come from issuers.created_at"

    real_issuer_row = pre_migration_conn.execute("SELECT public_key FROM issuers WHERE id = ?", (issuer_id,)).fetchone()
    assert key_row["public_key"] == real_issuer_row["public_key"], "legacy key must be a copy of the real issuer public_key"

    cred_row = pre_migration_conn.execute("SELECT key_id FROM credentials WHERE id = ?", (cred_id,)).fetchone()
    assert cred_row["key_id"] == "legacy-platform-held", "existing credentials must be backfilled to the legacy key_id"

    # The actual regression check: verification (today's unchanged
    # issuers.public_key-keyed logic -- _evaluate_node isn't touched
    # until Stage 4) must still pass for this credential after the
    # migration ran, proving the migration didn't disturb anything the
    # existing verification path depends on.
    result = passport_engine.compile_passport(pre_migration_conn, cred_id)
    assert result["verdict"] == "pass", f"legacy credential should still verify post-migration: {result['reasons']}"


def test_migration_is_idempotent(pre_migration_conn):
    """init_db() runs every migration on every process start -- running
    this one twice must not error (duplicate legacy key insert) or
    double-backfill/corrupt anything."""
    issuer_id, cred_id = _seed_legacy_issuer_and_credential(pre_migration_conn)
    pre_migration_conn.executescript(db.ISSUER_KEYS_TABLE_SQL)

    db._migrate_issuer_keys(pre_migration_conn)
    db._migrate_issuer_keys(pre_migration_conn)
    pre_migration_conn.commit()

    rows = pre_migration_conn.execute(
        "SELECT * FROM issuer_keys WHERE issuer_id = ?", (issuer_id,)
    ).fetchall()
    assert len(rows) == 1, "re-running the migration must not create a second legacy row"


def test_migration_enforces_one_active_key_per_issuer(pre_migration_conn):
    """The unique partial index (valid_to IS NULL) is the DB-level guard
    against a rotation bug leaving two simultaneously-active keys for
    one issuer -- confirm it's actually created and actually enforced,
    not just declared in a comment."""
    issuer_id, _ = _seed_legacy_issuer_and_credential(pre_migration_conn)
    pre_migration_conn.executescript(db.ISSUER_KEYS_TABLE_SQL)
    db._migrate_issuer_keys(pre_migration_conn)
    pre_migration_conn.commit()

    with pytest.raises(sqlite3.IntegrityError):
        pre_migration_conn.execute(
            """
            INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
            VALUES (?, 'second-active-key', 'fake-public-key', '2026-02-01T00:00:00+00:00', NULL, NULL, 'test', '2026-02-01T00:00:00+00:00')
            """,
            (issuer_id,),
        )
