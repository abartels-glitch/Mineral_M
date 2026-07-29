"""Append-only audit log helper.

Every upload, review, credential issuance, and passport lookup writes a
row here — the spec (section 3) calls this out as itself an artifact an
auditor may want to see, not just an internal debugging aid.
"""
import json
import sqlite3
import uuid
from datetime import datetime, timezone


def record(
    conn: sqlite3.Connection,
    entity_type: str,
    entity_id: str,
    action: str,
    actor: str,
    detail: dict | None = None,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_log (id, entity_type, entity_id, action, actor, detail_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid.uuid4().hex,
            entity_type,
            entity_id,
            action,
            actor,
            json.dumps(detail or {}),
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
