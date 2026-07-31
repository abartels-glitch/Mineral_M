"""Recursive credential-graph compiler.

Walks a credential's `sources` graph (per spec section 1: graph-native via
a JSON array of parent ids, not a single-parent tree) and produces a
pass / fail / insufficient_data verdict. Never collapses "we don't know"
into "fail" silently (spec section 4.6) — missing/out-of-scope data on an
otherwise-valid credential yields insufficient_data, not fail.
"""
import hashlib
import json
import sqlite3

import storage
from crypto_utils import credential_signable_payload, verify_signature

BANNED_ORIGIN_COUNTRIES = {
    "china",
    "people's republic of china",
    "prc",
    "russia",
    "russian federation",
    "iran",
    "islamic republic of iran",
    "north korea",
    "democratic people's republic of korea",
    "dprk",
}

# DFARS rare-earth scope this compliance engine actually checks — not the
# broader "motors, batteries, ESCs" language from the pitch deck.
COVERED_MATERIAL_KEYWORDS = (
    "samarium-cobalt",
    "samarium cobalt",
    "smco",
    "ndfeb",
    "neodymium",
    "tantalum",
    "tungsten",
)


def _material_in_scope(material_type: str) -> bool:
    lowered = material_type.lower()
    return any(keyword in lowered for keyword in COVERED_MATERIAL_KEYWORDS)


def _evaluate_node(conn: sqlite3.Connection, credential_id: str) -> tuple[dict, list[str]]:
    """Returns (node_result_dict, parent_credential_ids)."""
    row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if row is None:
        return (
            {
                "credential_id": credential_id,
                "credential_type": "unknown",
                "material_type": None,
                "origin_country": None,
                "node_status": "fail",
                "reasons": ["referenced credential id does not exist"],
            },
            [],
        )

    issuer = conn.execute("SELECT * FROM issuers WHERE id = ?", (row["issuer_id"],)).fetchone()
    subject = json.loads(row["subject_json"])
    sources = json.loads(row["sources_json"])
    material_type = subject.get("material_type")
    origin_country = subject.get("origin_country")

    reasons: list[str] = []
    node_status = "pass"

    def downgrade(new_status: str) -> None:
        nonlocal node_status
        # revoked outranks fail: an explicit retraction is the most
        # authoritative reason not to trust a credential, worth
        # headlining even alongside an independently-failing check
        # (e.g. a stale signature) — both reasons still show either way.
        rank = {"pass": 0, "insufficient_data": 1, "fail": 2, "revoked": 3}
        if rank[new_status] > rank[node_status]:
            node_status = new_status

    if issuer is None:
        reasons.append("issuer record missing — cannot verify signature")
        downgrade("fail")
    else:
        payload = credential_signable_payload(
            id=row["id"],
            issuer_id=row["issuer_id"],
            credential_type=row["credential_type"],
            subject=subject,
            sources=sources,
            segregation_attested=bool(row["segregation_attested"]),
            segregation_attested_by=row["segregation_attested_by"],
            segregation_note=row["segregation_note"],
            document_id=row["document_id"],
            document_content_hash=row["document_content_hash"],
            issued_at=row["issued_at"],
        )
        if not verify_signature(issuer["public_key"], payload, row["signature"]):
            reasons.append("signature does not verify")
            downgrade("fail")

    if row["document_id"] and row["document_content_hash"]:
        document = conn.execute("SELECT * FROM documents WHERE id = ?", (row["document_id"],)).fetchone()
        if document is None:
            reasons.append("source document record is missing")
            downgrade("fail")
        else:
            try:
                current_hash = hashlib.sha256(storage.read_object(document["object_key"])).hexdigest()
            except FileNotFoundError:
                reasons.append("source document object is missing from storage")
                downgrade("fail")
            else:
                if current_hash != row["document_content_hash"]:
                    reasons.append("source document has been modified since this credential was signed")
                    downgrade("fail")

    if row["revoked_at"]:
        if row["superseded_by"]:
            reasons.append(
                f"revoked at {row['revoked_at']}, superseded by {row['superseded_by']} "
                "— re-run the passport against the superseding credential"
            )
        else:
            reasons.append(f"revoked at {row['revoked_at']} with no superseding credential")
        downgrade("revoked")

    norm_origin = (origin_country or "").strip().lower()
    if not origin_country:
        reasons.append("origin country not recorded")
        downgrade("insufficient_data")
    elif norm_origin in BANNED_ORIGIN_COUNTRIES:
        reasons.append(f"origin country '{origin_country}' is FEOC-covered")
        downgrade("fail")

    if not material_type:
        reasons.append("material_type not recorded")
        downgrade("insufficient_data")
    elif not _material_in_scope(material_type):
        reasons.append(
            f"material_type '{material_type}' is outside the DFARS rare-earth scope "
            "this engine checks (samarium-cobalt, NdFeB, tantalum, tungsten)"
        )
        downgrade("insufficient_data")

    if len(sources) >= 2:
        attested_by = (row["segregation_attested_by"] or "").strip()
        note = (row["segregation_note"] or "").strip()
        if not (row["segregation_attested"] and attested_by and note):
            reasons.append(
                "credential combines 2+ sources but lacks a valid segregation attestation "
                "(requires segregation_attested=true, a named attestor, and a control description)"
            )
            downgrade("fail")

    if not reasons:
        reasons.append("all checks passed")

    return (
        {
            "credential_id": row["id"],
            "credential_type": row["credential_type"],
            "material_type": material_type,
            "origin_country": origin_country,
            "node_status": node_status,
            "reasons": reasons,
        },
        sources,
    )


def compile_passport(conn: sqlite3.Connection, root_credential_id: str) -> dict:
    visited: set[str] = set()
    nodes: list[dict] = []

    def visit(credential_id: str) -> None:
        if credential_id in visited:
            return
        visited.add(credential_id)
        node, parent_ids = _evaluate_node(conn, credential_id)
        nodes.append(node)
        for parent_id in parent_ids:
            visit(parent_id)

    visit(root_credential_id)

    if any(n["node_status"] == "revoked" for n in nodes):
        verdict = "revoked"
    elif any(n["node_status"] == "fail" for n in nodes):
        verdict = "fail"
    elif any(n["node_status"] == "insufficient_data" for n in nodes):
        verdict = "insufficient_data"
    else:
        verdict = "pass"

    problem_summaries = [
        f"{n['credential_id']} ({n['credential_type']}): {'; '.join(n['reasons'])}"
        for n in nodes
        if n["node_status"] != "pass"
    ]
    reasons = problem_summaries or ["all credentials in the graph passed every check"]

    return {
        "credential_id": root_credential_id,
        "verdict": verdict,
        "reasons": reasons,
        "nodes": nodes,
    }
