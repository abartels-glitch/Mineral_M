"""SQLite schema and connection helper for the FEOC compliance passport MVP.

Deliberately SQLite for now — section 4.8 of the build spec calls for a
Postgres migration once the pilot needs concurrent writers, but that's not
yet.
"""
import sqlite3
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "passport.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS issuers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
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
    flagged_reason TEXT,
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
    flagged_reason TEXT
);

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


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
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
