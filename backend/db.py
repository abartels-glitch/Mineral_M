"""SQLite schema and connection helper for the FEOC compliance passport MVP.

Deliberately SQLite for now — section 4.8 of the build spec calls for a
Postgres migration once the pilot needs concurrent writers, but that's not
yet.
"""
import json
import os
import sqlite3
from pathlib import Path

# FEOC_DATA_DIR override exists for concurrency regression tests, which
# need a real subprocess server (genuine OS-level concurrent connections
# — a shared in-memory test connection can't reproduce a race between
# two separate connections the way production's per-request connection
# does) pointed at an isolated temp DB, not the real dev database.
# storage.py/crypto_utils.py derive their own dirs from DATA_DIR at
# import time, so setting this one env var before the subprocess starts
# isolates the DB, object storage, and issuer keys together.
DATA_DIR = Path(os.environ.get("FEOC_DATA_DIR") or Path(__file__).resolve().parent.parent / "data")
DB_PATH = DATA_DIR / "passport.db"

SCHEMA = """
-- `iac`/`enterprise_id` are the Issuing Agency Code and Enterprise
-- Identifier this issuer is registered under (e.g. "UN" + a D-U-N-S
-- number) — together they're the fixed prefix of every MIL-STD-130
-- Construct #1 UII this issuer's credentials get (see uii.py). Both
-- nullable: an issuer only needs them once it starts minting real UIIs,
-- and existing/dev issuers predate the feature.
CREATE TABLE IF NOT EXISTS issuers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    iac TEXT,
    enterprise_id TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS documents (
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

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT REFERENCES issuers(id),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

-- One row per heat/melt on a certificate — a certificate can cover
-- several heats (spec section 4.1's multi-heat consolidated case).
-- `source` is the *current* value owner (flips to 'human' on review,
-- same convention as the old extracted_fields table); `extraction_source`
-- is written once and never touched again, so audit/stats can always
-- answer "how was this originally extracted" even after review.
CREATE TABLE IF NOT EXISTS document_heats (
    id TEXT PRIMARY KEY,
    document_id TEXT NOT NULL REFERENCES documents(id),
    heat_id TEXT,
    alloy_composition_json TEXT,
    test_results_json TEXT,
    nonconformance_refs_json TEXT NOT NULL DEFAULT '[]',
    segregation_attested INTEGER NOT NULL DEFAULT 0,
    segregation_attested_by TEXT,
    segregation_note TEXT,
    mass_kg REAL,
    confidence REAL,
    source TEXT NOT NULL DEFAULT 'regex',
    extraction_source TEXT NOT NULL DEFAULT 'regex',
    flagged_for_review INTEGER NOT NULL DEFAULT 0,
    flags_json TEXT NOT NULL DEFAULT '[]',
    reviewed INTEGER NOT NULL DEFAULT 0,
    reviewed_by TEXT,
    reviewed_at TEXT,
    credential_id TEXT REFERENCES credentials(id)
);

CREATE TABLE IF NOT EXISTS heat_sublots (
    id TEXT PRIMARY KEY,
    heat_id TEXT NOT NULL REFERENCES document_heats(id),
    sublot_id TEXT,
    blend_pct REAL,
    origin_country TEXT,
    origin_confidence TEXT,
    notes TEXT,
    flagged INTEGER NOT NULL DEFAULT 0,
    flags_json TEXT NOT NULL DEFAULT '[]'
);

-- `heat_id` is set once at issuance and never reassigned — it's the
-- permanent record of which heat this credential was signed from,
-- independent of document_heats.credential_id (which always points to
-- whichever credential is *currently active* for that heat, and moves
-- on to a reissued credential once this one is revoked/superseded).
-- Without this, a revoked credential's own audit trail would lose
-- track of its originating heat the moment it's superseded.
CREATE TABLE IF NOT EXISTS credentials (
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
    heat_id TEXT REFERENCES document_heats(id),
    payload_hash TEXT NOT NULL,
    signature TEXT NOT NULL,
    superseded_by TEXT REFERENCES credentials(id),
    revoked_at TEXT,
    issued_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS uii_bindings (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL REFERENCES credentials(id),
    uii_code TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    detail_json TEXT,
    created_at TEXT NOT NULL
);
"""


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _classify_legacy_reason(text: str) -> tuple:
    """Best-effort classification of a pre-migration flat reason string
    into (issue_type, field_name, source). The three deterministic
    phrasings below are known verbatim from main.py's old
    `_evaluate_sublot_flag` and can be classified exactly; anything else
    is an LLM-authored free-text reason (source='extraction'), keyword-
    matched onto the closest issue_type since we can't recover which
    field, if any, the model meant."""
    lower = text.lower()
    if "is feoc-covered" in lower:
        return "compliance_violation", "origin_country", "compliance_engine"
    if "origin country not stated" in lower:
        return "missing_field", "origin_country", "compliance_engine"
    if "origin confidence marked low" in lower:
        return "low_confidence_extraction", "origin_confidence", "compliance_engine"
    if "regex fallback" in lower:
        return "low_confidence_extraction", None, "extraction"
    if "covered country" in lower or "feoc" in lower:
        return "compliance_violation", None, "extraction"
    if "unconfirmed" in lower or "low-confidence" in lower or "low confidence" in lower:
        return "low_confidence_extraction", None, "extraction"
    if "inconsistent" in lower or "contradictory" in lower:
        return "inconsistent_data", None, "extraction"
    if "missing" in lower or "not stated" in lower or "not present" in lower:
        return "missing_field", None, "extraction"
    return "ambiguous_field", None, "extraction"


def _migrate_flags_json(conn: sqlite3.Connection) -> None:
    """CREATE TABLE IF NOT EXISTS doesn't touch a table that already
    exists on disk, so the flagged_reason -> flags_json rename (see
    review_flags.py) needs an explicit migration for any dev DB created
    before that change. A legacy flagged_reason could itself be several
    reasons joined with "; " (main.py's old dedupe-join), so each
    segment becomes its own classified flag rather than one blob. New
    rows never hit this path since they're written with flags_json
    directly."""
    for table in ("document_heats", "heat_sublots"):
        cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if "flags_json" not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN flags_json TEXT NOT NULL DEFAULT '[]'")
        if "flagged_reason" in cols:
            for row in conn.execute(f"SELECT id, flagged_reason FROM {table} WHERE flagged_reason IS NOT NULL"):
                new_flags = []
                for segment in row["flagged_reason"].split("; "):
                    issue_type, field_name, source = _classify_legacy_reason(segment)
                    new_flags.append(
                        {
                            "issue_type": issue_type,
                            "field_name": field_name,
                            "severity": "blocking" if issue_type == "compliance_violation" else "needs_review",
                            "human_readable_reason": segment,
                            "source": source,
                        }
                    )
                conn.execute(f"UPDATE {table} SET flags_json = ? WHERE id = ?", (json.dumps(new_flags), row["id"]))
            conn.execute(f"ALTER TABLE {table} DROP COLUMN flagged_reason")


def _migrate_credentials_heat_id(conn: sqlite3.Connection) -> None:
    """CREATE TABLE IF NOT EXISTS doesn't touch a table that already
    exists on disk. Existing rows get heat_id=NULL — they predate the
    revoke/reissue feature, so there's nothing to backfill it from
    (document_heats.credential_id only ever points forward to whichever
    credential is currently active, never a history of past ones)."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(credentials)")}
    if "heat_id" not in cols:
        conn.execute("ALTER TABLE credentials ADD COLUMN heat_id TEXT REFERENCES document_heats(id)")


def _migrate_issuers_uii_fields(conn: sqlite3.Connection) -> None:
    """CREATE TABLE IF NOT EXISTS doesn't touch a table that already
    exists on disk. Existing issuers get iac/enterprise_id = NULL — real
    values have to be registered per-issuer before that issuer can mint
    Construct #1 UIIs; there's no default to backfill."""
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(issuers)")}
    if "iac" not in cols:
        conn.execute("ALTER TABLE issuers ADD COLUMN iac TEXT")
    if "enterprise_id" not in cols:
        conn.execute("ALTER TABLE issuers ADD COLUMN enterprise_id TEXT")


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        _migrate_flags_json(conn)
        _migrate_credentials_heat_id(conn)
        _migrate_issuers_uii_fields(conn)
        conn.commit()
    finally:
        conn.close()


def get_db():
    """Shared FastAPI dependency — imported by both main.py and auth.py so
    there's exactly one connection-per-request pattern, and tests can
    override this single function to swap in an in-memory DB."""
    conn = get_connection()
    try:
        yield conn
    finally:
        conn.close()
