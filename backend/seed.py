"""Seed a fictional design-partner profile so the passport lookup has real
data to show immediately, without needing a real design partner yet.

Rio Grande Magnetics is a SYNTHETIC/PROVISIONAL profile (see README) — a
fictional single-site NdFeB magnet recycler in Texas that collects
decommissioned motors and hard-drive magnets from domestic sources only
and sinters them into new NdFeB magnets on one dedicated line. Modeled on
the real-world Noveon/e-VAC pattern of a traceable recycler, but no real
company or data is represented here.

Builds a 3-node credential graph: two collected_scrap_lot credentials feed
one sintered_ndfeb_batch credential, which exercises the 2+-source
segregation check end to end. Each is a single reviewed heat — matching
`tests/fixtures/rio_grande_mtr_sample.pdf`'s shape, the clean single-heat
regression bar, not the multi-heat complex case (that's what the fixture
PDFs and tests are for).

Idempotent: re-running the script reuses the existing issuer/credentials
instead of duplicating them.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone

import audit
import auth
import crypto_utils
import storage
from db import LEGACY_KEY_ID, get_connection, init_db

# Synthetic-only: "Rio Grande Magnetics" and these credentials are a fictional
# design partner (see README.md), not a real company. Do not reuse this email/
# password pattern, or grant them access to anything beyond this seeded demo
# database, once a real first design partner is onboarded — issue that org
# real, unique credentials through the normal /admin/users flow instead.
ISSUER_NAME = "Rio Grande Magnetics"
ORG_USER_EMAIL = "maria@riograndemagnetics.example"
ORG_USER_PASSWORD = "riograndemagnetics-dev"
ADMIN_EMAIL = "admin@feoc-passport.local"
ADMIN_PASSWORD = "platform-admin-dev"

SCRAP_LOT_1_TEXT = """CERTIFICATE OF CONFORMANCE / MILL TEST REPORT
Supplier: Rio Grande Magnetics, LLC
Heat No.: RGM-SCRAP-2026-0091
Feedstock: Domestically Collected NdFeB Scrap (decommissioned motors)
Country of Origin: United States
Batch Mass: 410.0 kg
"""

SCRAP_LOT_2_TEXT = """CERTIFICATE OF CONFORMANCE / MILL TEST REPORT
Supplier: Rio Grande Magnetics, LLC
Heat No.: RGM-SCRAP-2026-0092
Feedstock: Domestically Collected NdFeB Scrap (HDD magnets)
Country of Origin: United States
Batch Mass: 165.0 kg
"""

SINTERED_BATCH_TEXT = """CERTIFICATE OF CONFORMANCE / MILL TEST REPORT
Supplier: Rio Grande Magnetics, LLC
Heat No.: RGM-NDFEB-2026-0412
Alloy Composition (wt%): Nd 29.5, Fe 68.2, B 1.0, Dy 1.3
Country of Origin: United States
Batch Mass: 182.5 kg
"""

REVIEWER = "Maria Alvarez, QA Lead, Rio Grande Magnetics"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def seed_document_with_heat(
    conn,
    org_id: str,
    raw_text: str,
    heat_label: str,
    origin_country: str,
    mass_kg: float,
    alloy_composition: dict | None = None,
    segregation_attested: bool = False,
    segregation_note: str | None = None,
) -> str:
    """Creates a document plus one already-reviewed heat (a human has
    confirmed this data, matching the shape a real reviewer produces),
    marked `extraction_source='regex'` — representing "regex found the
    flat fields, a human filled in composition/segregation" since regex
    alone can't parse either. Returns the heat's row id, which is what
    credential issuance references."""
    document_id = uuid.uuid4().hex
    uploaded_at = now_iso()
    filename = f"{document_id}.txt"
    raw_bytes = raw_text.encode("utf-8")
    object_key = f"{document_id}/{filename}"
    storage.save_object(object_key, raw_bytes)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    conn.execute(
        """
        INSERT INTO documents (id, org_id, filename, document_type, object_key, content_hash, raw_text, supplier_id, status, uploaded_at)
        VALUES (?, ?, ?, 'mtr_coc', ?, ?, ?, ?, 'extracted', ?)
        """,
        (document_id, org_id, filename, object_key, content_hash, raw_text, ISSUER_NAME, uploaded_at),
    )
    audit.record(conn, "document", document_id, "uploaded", actor=REVIEWER, detail={"filename": filename})
    audit.record(conn, "document", document_id, "extracted", actor="system")

    heat_row_id = uuid.uuid4().hex
    reviewed_at = now_iso()
    conn.execute(
        """
        INSERT INTO document_heats (
            id, document_id, heat_id, alloy_composition_json, test_results_json, nonconformance_refs_json,
            segregation_attested, segregation_attested_by, segregation_note, mass_kg, confidence,
            source, extraction_source, flagged_for_review, flags_json, reviewed, reviewed_by, reviewed_at
        ) VALUES (?, ?, ?, ?, NULL, '[]', ?, ?, ?, ?, 1.0, 'human', 'regex', 0, '[]', 1, ?, ?)
        """,
        (
            heat_row_id,
            document_id,
            heat_label,
            json.dumps(alloy_composition) if alloy_composition else None,
            1 if segregation_attested else 0,
            REVIEWER if segregation_attested else None,
            segregation_note,
            mass_kg,
            REVIEWER,
            reviewed_at,
        ),
    )
    conn.execute(
        """
        INSERT INTO heat_sublots (id, heat_id, sublot_id, blend_pct, origin_country, origin_confidence, notes, flagged, flags_json)
        VALUES (?, ?, NULL, 100.0, ?, 'high', 'domestically collected scrap, single source', 0, '[]')
        """,
        (uuid.uuid4().hex, heat_row_id, origin_country),
    )
    audit.record(conn, "document_heat", heat_row_id, "reviewed", actor=REVIEWER)
    return heat_row_id


def issue_credential(
    conn,
    issuer_id: str,
    private_key_path: str,
    credential_type: str,
    subject: dict,
    heat_id: str | None,
    sources: list[str],
    segregation_attested: bool = False,
    segregation_attested_by: str | None = None,
    segregation_note: str | None = None,
) -> str:
    document_id = None
    document_content_hash = None
    if heat_id is not None:
        heat = conn.execute("SELECT document_id FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
        if heat is not None:
            document_id = heat["document_id"]
            doc = conn.execute("SELECT content_hash FROM documents WHERE id = ?", (document_id,)).fetchone()
            document_content_hash = doc["content_hash"] if doc else None

    credential_id = uuid.uuid4().hex
    issued_at = now_iso()
    payload = crypto_utils.credential_signable_payload(
        id=credential_id,
        issuer_id=issuer_id,
        credential_type=credential_type,
        subject=subject,
        sources=sources,
        segregation_attested=segregation_attested,
        segregation_attested_by=segregation_attested_by,
        segregation_note=segregation_note,
        document_id=document_id,
        document_content_hash=document_content_hash,
        issued_at=issued_at,
    )
    signature, payload_hash = crypto_utils.sign_payload(private_key_path, payload)
    conn.execute(
        """
        INSERT INTO credentials (
            id, issuer_id, credential_type, subject_json, sources_json,
            segregation_attested, segregation_attested_by, segregation_note,
            document_id, document_content_hash, key_id, payload_hash, signature, superseded_by, revoked_at, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
        """,
        (
            credential_id, issuer_id, credential_type, json.dumps(subject), json.dumps(sources),
            1 if segregation_attested else 0, segregation_attested_by, segregation_note,
            document_id, document_content_hash, LEGACY_KEY_ID, payload_hash, signature, issued_at,
        ),
    )
    if heat_id is not None:
        conn.execute("UPDATE document_heats SET credential_id = ? WHERE id = ?", (credential_id, heat_id))
    conn.execute(
        "INSERT INTO uii_bindings (id, credential_id, uii_code, created_at) VALUES (?, ?, ?, ?)",
        (uuid.uuid4().hex, credential_id, credential_id, issued_at),
    )
    audit.record(conn, "credential", credential_id, "issued", actor=REVIEWER, detail={"credential_type": credential_type})
    return credential_id


def main() -> None:
    init_db()
    conn = get_connection()

    issuer = conn.execute("SELECT * FROM issuers WHERE name = ?", (ISSUER_NAME,)).fetchone()
    if issuer is not None:
        existing_batch = conn.execute(
            "SELECT id FROM credentials WHERE issuer_id = ? AND credential_type = 'sintered_ndfeb_batch'",
            (issuer["id"],),
        ).fetchone()
        if existing_batch is not None:
            print(f"Already seeded. Sintered batch credential id: {existing_batch['id']}")
            print(f"Look it up: curl http://localhost:8000/passport/{existing_batch['id']}")
            return
        issuer_id = issuer["id"]
        private_key_path = issuer["private_key_path"]
    else:
        issuer_id = uuid.uuid4().hex
        public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
        created_at = now_iso()
        conn.execute(
            "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
            (issuer_id, ISSUER_NAME, public_key_b64, private_key_path, created_at),
        )
        # Mirrors exactly what db._migrate_issuer_keys does for a
        # pre-existing issuer -- created inline here rather than relying
        # on that migration to catch it on the next process start, so a
        # freshly-seeded issuer's own credentials are verifiable
        # immediately, not just after a restart.
        conn.execute(
            """
            INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
            VALUES (?, ?, ?, ?, NULL, NULL, 'seed', ?)
            """,
            (issuer_id, LEGACY_KEY_ID, public_key_b64, created_at, created_at),
        )
        conn.commit()

    if conn.execute("SELECT id FROM users WHERE email = ?", (ORG_USER_EMAIL,)).fetchone() is None:
        conn.execute(
            "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, 'org_user', ?)",
            (uuid.uuid4().hex, issuer_id, ORG_USER_EMAIL, auth.hash_password(ORG_USER_PASSWORD), now_iso()),
        )
    if conn.execute("SELECT id FROM users WHERE email = ?", (ADMIN_EMAIL,)).fetchone() is None:
        conn.execute(
            "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, NULL, ?, ?, 'platform_admin', ?)",
            (uuid.uuid4().hex, ADMIN_EMAIL, auth.hash_password(ADMIN_PASSWORD), now_iso()),
        )
    conn.commit()

    lot1_heat_id = seed_document_with_heat(
        conn, issuer_id, SCRAP_LOT_1_TEXT, "RGM-SCRAP-2026-0091", "United States", 410.0
    )
    lot2_heat_id = seed_document_with_heat(
        conn, issuer_id, SCRAP_LOT_2_TEXT, "RGM-SCRAP-2026-0092", "United States", 165.0
    )
    batch_heat_id = seed_document_with_heat(
        conn, issuer_id, SINTERED_BATCH_TEXT, "RGM-NDFEB-2026-0412", "United States", 182.5,
        alloy_composition={"Nd": 29.5, "Fe": 68.2, "B": 1.0, "Dy": 1.3},
        segregation_attested=True,
        segregation_note=(
            "Dedicated single-line sintering process; tooling purged and "
            "lot-tagged between production runs; no shared feedstock with "
            "non-domestic or non-qualifying material."
        ),
    )
    conn.commit()

    lot1_id = issue_credential(
        conn, issuer_id, private_key_path, "collected_scrap_lot",
        subject={
            "material_type": "Domestically Collected NdFeB Scrap (decommissioned motors)",
            "origin_country": "United States",
            "mass_kg": 410.0,
            "heat_number": "RGM-SCRAP-2026-0091",
            "supplier_name": ISSUER_NAME,
        },
        heat_id=lot1_heat_id, sources=[],
    )
    lot2_id = issue_credential(
        conn, issuer_id, private_key_path, "collected_scrap_lot",
        subject={
            "material_type": "Domestically Collected NdFeB Scrap (HDD magnets)",
            "origin_country": "United States",
            "mass_kg": 165.0,
            "heat_number": "RGM-SCRAP-2026-0092",
            "supplier_name": ISSUER_NAME,
        },
        heat_id=lot2_heat_id, sources=[],
    )
    batch_id = issue_credential(
        conn, issuer_id, private_key_path, "sintered_ndfeb_batch",
        subject={
            "material_type": "Sintered NdFeB Magnet Alloy (N42)",
            "origin_country": "United States",
            "mass_kg": 182.5,
            "heat_number": "RGM-NDFEB-2026-0412",
            "supplier_name": ISSUER_NAME,
        },
        heat_id=batch_heat_id, sources=[lot1_id, lot2_id],
        segregation_attested=True,
        segregation_attested_by=REVIEWER,
        segregation_note=(
            "Dedicated single-line sintering process; tooling purged and "
            "lot-tagged between production runs; no shared feedstock with "
            "non-domestic or non-qualifying material."
        ),
    )
    conn.commit()

    print(f"Seeded issuer: {ISSUER_NAME} ({issuer_id})")
    print(f"Seeded collected_scrap_lot credentials: {lot1_id}, {lot2_id}")
    print(f"Seeded sintered_ndfeb_batch credential: {batch_id}")
    print(f"Look it up (no login needed): curl http://localhost:8000/passport/{batch_id}")
    print()
    print("Dev login accounts (DEV ONLY, not real credentials):")
    print(f"  org_user:       {ORG_USER_EMAIL} / {ORG_USER_PASSWORD}  (Rio Grande Magnetics)")
    print(f"  platform_admin: {ADMIN_EMAIL} / {ADMIN_PASSWORD}")


if __name__ == "__main__":
    main()
