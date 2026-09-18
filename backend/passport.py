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

import org_config
import storage
from crypto_utils import credential_signable_payload, verify_signature

BANNED_ORIGIN_COUNTRIES = {
    "china",
    "people's republic of china",
    "prc",  # thinnest entry in this set: a bare 3-letter substring, kept
            # because no realistic origin-country string collides with it
    "russia",
    "russian federation",
    "iran",
    "islamic republic of iran",
    "north korea",
    "democratic people's republic of korea",
    "dprk",
}

# Taiwan's official name, "Republic of China", contains "china" as a
# substring but is not FEOC-covered — without this carve-out, is_banned_origin
# below would misflag legitimate Taiwan-origin material.
_NOT_BANNED_DESPITE_SUBSTRING = (
    "republic of china",
    "taiwan",
    "chinese taipei",
)


def _normalize_origin(origin_country: str) -> str:
    return " ".join((origin_country or "").split()).lower()


def is_banned_origin(origin_country: str) -> bool:
    """True if origin_country names or contains a FEOC-covered country.

    Substring, not exact-equality: origin_country is meant to name a
    single country, but a concatenated/blended value (a botched
    correction leaving "ChinaUnited States", or a genuine blended-origin
    string like "60% US / 40% Russia") should still trip this — an
    exact match only catches the field being precisely one banned name
    and nothing else.

    Shared by main.py's extraction/correction-time flagging and this
    module's own verification-time recheck (_evaluate_node below), so
    the two can't independently drift on what counts as covered — same
    principle as crypto_utils.credential_signable_payload being shared
    between issuance and verification.
    """
    normalized = _normalize_origin(origin_country)
    if not normalized:
        return False
    if "people's republic of china" in normalized:
        return True
    remaining = normalized
    for exception in _NOT_BANNED_DESPITE_SUBSTRING:
        remaining = remaining.replace(exception, " ")
    return any(banned in remaining for banned in BANNED_ORIGIN_COUNTRIES)


# DFARS rare-earth scope this compliance engine actually checks — not the
# broader "motors, batteries, ESCs" language from the pitch deck. Was a
# hardcoded module constant here; now per-org (org_config.py's
# "materials_scope"), keyed off whichever org issued the credential being
# evaluated (see _evaluate_node) — see org_config.py's module docstring for
# why materials scope specifically was safe to externalize with no
# structural coupling risk, unlike the extraction schema's field names.


def _material_in_scope(material_type: str, materials_scope: list[str]) -> bool:
    lowered = material_type.lower()
    return any(keyword in lowered for keyword in materials_scope)


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

    # Narrow SELECT: only the columns needed to check "was this specific
    # key valid for this issuer when this credential was signed" and to
    # verify against its public key. This function is reachable from
    # the public, unauthenticated /passport/{id} and /passport/{id}/pdf
    # endpoints, so it must never pull anything sensitive into memory
    # here (there's nothing sensitive in issuer_keys either way — only
    # public_key, same discipline as the old issuers.public_key lookup
    # this replaces).
    key = conn.execute(
        "SELECT public_key, valid_from, valid_to, revoked_at FROM issuer_keys WHERE issuer_id = ? AND key_id = ?",
        (row["issuer_id"], row["key_id"]),
    ).fetchone()
    subject = json.loads(row["subject_json"])
    sources = json.loads(row["sources_json"])
    material_type = subject.get("material_type")
    origin_country = subject.get("origin_country")
    # Materials scope is the issuing org's, not a single global list — a
    # composite credential can combine sources from different orgs, and
    # each node is checked against whichever org actually issued it.
    org_cfg = org_config.load_config_for_issuer(conn, row["issuer_id"])

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

    if key is None:
        reasons.append("signing key record missing — cannot verify signature")
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
        # The structural fix: was THIS key_id valid for this issuer at
        # the time THIS credential was signed -- not "is this the
        # issuer's current public_key" (today's bug: a routine rotation
        # would retroactively break every credential signed under the
        # previous key, since verification always checked whatever
        # public_key currently happened to be on file). valid_to IS
        # NULL means still active; the upper bound is exclusive so a
        # credential signed in the same instant a new key takes over
        # unambiguously belongs to one key or the other, never both.
        was_valid = key["valid_from"] <= row["issued_at"] and (key["valid_to"] is None or row["issued_at"] < key["valid_to"])
        if not was_valid:
            reasons.append(f"signing key {row['key_id']} was not valid for this issuer at {row['issued_at']}")
            downgrade("fail")
        elif not verify_signature(key["public_key"], payload, row["signature"]):
            reasons.append("signature does not verify")
            downgrade("fail")
        # Retroactive per the pinned decision: a key reported compromised
        # can't be trusted to distinguish "signed before the leak" from
        # "signed after" -- revoked_at is a detection-time proxy, not the
        # true compromise time, so every credential this key ever signed
        # is flagged, not just ones issued after revoked_at. "revoked"
        # outranks "fail" via downgrade() above, so this headlines even
        # when the signature/window checks above also failed.
        if key["revoked_at"]:
            reasons.append(f"signing key was revoked at {key['revoked_at']} — issuer reported this key as compromised")
            downgrade("revoked")

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

    if not origin_country:
        reasons.append("origin country not recorded")
        downgrade("insufficient_data")
    elif is_banned_origin(origin_country):
        reasons.append(f"origin country '{origin_country}' is FEOC-covered")
        downgrade("fail")

    if not material_type:
        reasons.append("material_type not recorded")
        downgrade("insufficient_data")
    elif not _material_in_scope(material_type, org_cfg["materials_scope"]):
        # Generated from the same list actually checked above, not a
        # separately hardcoded display string — the two can't drift the
        # way the old module-constant-plus-hardcoded-string pair could.
        scope_display = ", ".join(org_cfg["materials_scope"])
        reasons.append(
            f"material_type '{material_type}' is outside the DFARS rare-earth scope "
            f"this engine checks for {org_cfg['org_name']} ({scope_display})"
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
            "sources": sources,
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
