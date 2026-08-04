"""FastAPI app: upload -> extract -> review (per heat) -> issue credential (per heat) -> compile passport.

Serves the no-build-step frontend/ directory as static files alongside the
API (spec section 1). Auth: server-side session cookie, three roles
(org_user, buyer_auditor, platform_admin) — see auth.py and README.

A certificate of conformance / MTR can cover one heat/melt (the common
case) or several (a consolidated multi-heat certificate) — see
llm_extractor.py. Each heat is independently reviewed and can become its
own credential; passport.py's compliance checks are unchanged, they just
now read a subject the reviewer confirmed from a specific heat's data
rather than a flat per-document field set.
"""
import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from fastapi.staticfiles import StaticFiles

import audit
import auth
import crypto_utils
import llm_extractor
import ocr
import passport as passport_engine
import pdf_export
import review_flags
import storage
import uii
from db import get_db, init_db
from models import (
    CreateUserRequest,
    CredentialIssueRequest,
    CredentialResponse,
    DocumentDetail,
    DocumentUploadResponse,
    FieldCorrectionRequest,
    HeatOut,
    HeatReviewRequest,
    LoginRequest,
    PassportResult,
    SublotOut,
    UserOut,
)

load_dotenv()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

init_db()
app = FastAPI(title="FEOC Compliance Passport (MVP)")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _evaluate_sublot_flag(sublot: dict, sublot_id: Optional[str] = None) -> list[dict]:
    """Deterministic sub-lot flagging, reusing passport.py's own banned-
    country list so extraction-time flagging and the compliance engine
    never disagree about what counts as covered. Returns structured
    review_flags.Flag dicts (source='compliance_engine') rather than a
    bare reason string — same rules as before, just structured output.

    `sublot_id` is stamped onto the flag when the caller has one (a
    persisted heat_sublots row id) — callers evaluating a not-yet-inserted
    sub-lot (upload_document, review_heat, before their INSERT) pass None
    and stamp it in themselves once the id exists; correct_field already
    knows the row id and passes it straight through."""
    origin = (sublot.get("origin_country") or "").strip()
    if not origin:
        return [
            review_flags.make_flag(
                "missing_field", "origin country not stated", source="compliance_engine",
                field_name="origin_country", sublot_id=sublot_id,
            ).model_dump()
        ]
    if origin.lower() in passport_engine.BANNED_ORIGIN_COUNTRIES:
        return [
            review_flags.make_flag(
                "compliance_violation",
                f"origin country '{origin}' is FEOC-covered",
                source="compliance_engine",
                field_name="origin_country",
                sublot_id=sublot_id,
            ).model_dump()
        ]
    if (sublot.get("origin_confidence") or "").lower() == "low":
        return [
            review_flags.make_flag(
                "low_confidence_extraction",
                "origin confidence marked low",
                source="compliance_engine",
                field_name="origin_confidence",
                sublot_id=sublot_id,
            ).model_dump()
        ]
    return []


# Field-level correction allowlist: field_name (the API/HeatOut attribute
# name a flag's field_name and the frontend both use) -> (column_name,
# python_type). Column name is spelled out separately from field_name
# because it isn't always the same string: alloy_composition/test_results
# are stored as alloy_composition_json/test_results_json (see db.py's
# schema) — every other correctable field today happens to have identical
# field/column names, which is why this used to be a bare field_name ->
# type dict, but that shape can't express the _json-suffixed columns.
#
# alloy_composition/test_results are full-value replaces here, same as
# every other field this dict lists. nonconformance_refs still isn't
# included — not because nothing targets it by field_name (that's a
# free-text string the LLM can set to anything, including this; that
# assumption is exactly what turned out to be wrong for
# alloy_composition/test_results before this dict grew to cover them),
# but because it's genuinely a different shape: a list of strings
# (llm_extractor.HEAT_SCHEMA's nonconformance_refs is `{"type": "array",
# "items": {"type": "string"}}`), not a dict at all. Neither
# buildKeyValueEditor's flat map nor buildTestResultsEditor's
# name->{value,result} map fits a bare string list — it would need its
# own add/remove-row-of-strings editor, which is out of scope for this
# pass. /review's full-replace form remains the only way to change it
# until that's built.
_HEAT_CORRECTABLE_FIELDS: dict[str, tuple[str, type]] = {
    "heat_id": ("heat_id", str),
    "mass_kg": ("mass_kg", float),
    "alloy_composition": ("alloy_composition_json", dict),
    "test_results": ("test_results_json", dict),
}
_SUBLOT_CORRECTABLE_FIELDS: dict[str, tuple[str, type]] = {
    "sublot_id": ("sublot_id", str),
    "blend_pct": ("blend_pct", float),
    "origin_country": ("origin_country", str),
    "origin_confidence": ("origin_confidence", str),
    "notes": ("notes", str),
}

# Bound on correct_field's compare-and-swap retry loop (see its use
# below) — two concurrent corrections to different fields on the same
# heat both read-modify-write the shared flags_json blob, so a retry is
# needed to avoid a silent lost update; real contention this deep is
# essentially never sustained, so exhausting this is a signal something
# else is wrong, not routine load.
_CAS_MAX_RETRIES = 5


def _coerce_corrected_value(raw: Optional[str | dict], field_type: type):
    if field_type is dict:
        if raw is not None and not isinstance(raw, dict):
            raise HTTPException(400, "corrected_value must be an object for this field")
        return raw
    if raw is None or raw == "":
        return None
    if field_type is float:
        try:
            return float(raw)
        except ValueError:
            raise HTTPException(400, f"'{raw}' is not a valid number") from None
    return raw


def _resolve_open_flags_for_field(flags: list[dict], field_name: str, actor: str, resolved_at: str) -> bool:
    """Marks every open flag about `field_name` resolved, in place.
    Returns whether anything changed (useful only for tests/debugging;
    callers recompute openness from the list itself afterward)."""
    changed = False
    for f in flags:
        if f.get("field_name") == field_name and f.get("status", "open") == "open":
            f["status"] = "resolved"
            f["resolved_by"] = actor
            f["resolved_at"] = resolved_at
            changed = True
    return changed


def _any_open(flags: list[dict]) -> bool:
    return any(f.get("status", "open") == "open" for f in flags)


def _any_open_blocking(flags: list[dict]) -> bool:
    # severity is stored on the flag itself (set once by review_flags.
    # make_flag, never recomputed), so checking it directly is equivalent
    # to checking issue_type membership in review_flags._BLOCKING_ISSUE_
    # TYPES -- simpler, and it can't drift from that set since nothing
    # ever mutates severity after creation.
    return any(f.get("status", "open") == "open" and f.get("severity") == "blocking" for f in flags)


def _heat_has_open_blocking_flag(conn, heat_row: dict) -> bool:
    """Whether this heat currently has any open blocking flag -- its own
    (excluding the flattened sub-lot duplicate, same reasoning as
    _heat_own_flags below: that copy can be stale) or any of its
    sub-lots' own, real flags_json. Mirrors exactly the pattern
    _row_to_heat's `any_open`/`fully_addressed` and the correction CAS
    loops already use for "is this heat actually addressed" -- this is
    the same question, just narrowed to blocking severity."""
    heat_flags = json.loads(heat_row["flags_json"])
    if _any_open_blocking(_heat_own_flags(heat_flags)):
        return True
    sublot_rows = conn.execute("SELECT flags_json FROM heat_sublots WHERE heat_id = ?", (heat_row["id"],)).fetchall()
    return any(_any_open_blocking(json.loads(r["flags_json"])) for r in sublot_rows)


def _heat_own_flags(heat_flags: list[dict]) -> list[dict]:
    """document_heats.flags_json is written at upload/`/review` time as
    extraction_flags + a flattened copy of every sub-lot's
    compliance_engine flags (see upload_document). Aggregation
    (flagged_for_review, fully_addressed) never trusts those flattened
    copies — correct_field keeps them in sync for *display* (see
    _resolve_open_sublot_duplicate_flags below, which can now do that
    precisely because compliance_engine flags carry sublot_id), but
    sub-lot rows stay the sole source of truth for whether a heat is
    actually addressed. Belt and suspenders: even a stale or
    legacy (pre-sublot_id) duplicate sitting here can never block a
    heat from reading as addressed once the owning sub-lot is fixed."""
    return [f for f in heat_flags if f.get("source") != "compliance_engine"]


# The only field_name substrings a heat-level (sublot_id=None) flag can
# carry that concern data with genuinely no heat-level home: origin is
# inherently per-sub-lot (a heat can blend several, each with a
# different origin), so there's no column on document_heats it could
# ever map to. Substring match, not exact equality: the LLM's flag
# schema leaves field_name as free text ("e.g. 'heat_id',
# 'origin_country'" is a description, not an enum), so it sometimes
# produces indexed/compound phrasing like
# "feedstock_sublots[0].origin_country" instead of the plain name.
_ORIGIN_FIELD_MARKERS = ("origin_country", "origin_confidence")


def _is_origin_related_field_name(field_name: Optional[str]) -> bool:
    return bool(field_name) and any(marker in field_name for marker in _ORIGIN_FIELD_MARKERS)


def _resolve_heat_level_origin_flags_if_all_sublots_clear(
    heat_flags: list[dict], all_sublot_flags: list[list[dict]], actor: str, resolved_at: str
) -> None:
    """The LLM's own heat-level flags (source='extraction', sublot_id=
    None) can never be corrected directly when they concern origin data
    — see _ORIGIN_FIELD_MARKERS above — and the LLM's flag schema can't
    attach a sublot_id to its own flags in the first place (sub-lot rows
    don't have ids yet at the point extraction runs — see
    review_flags.py). Without this, such a flag could stay open forever
    even after the real, underlying compliance problem was fixed: it's
    blocking severity (compliance_violation), so a heat could become
    permanently unissuable with no path forward for a reviewer, despite
    having genuinely fixed the data.

    The compliance_engine's own per-sub-lot check is the actual,
    resolvable, authoritative signal for this concern — deterministic,
    freshly re-evaluated on every correction. Once every sub-lot is
    clear of an open compliance_engine flag, the LLM's own aggregate
    observation about the same topic is, by definition, no longer true,
    so it's marked resolved too. Safe in both directions: this only
    ever transitions open -> resolved, never the reverse, so if a later
    correction reintroduces a bad origin, the compliance_engine's own
    fresh sub-lot flag reopens the gate independently (_append_fresh_
    flags appends a new open flag rather than un-resolving this one) —
    this resolution doesn't create a hole, it just stops a dead end."""
    all_sublots_clear = not any(
        f.get("status", "open") == "open" and f.get("source") == "compliance_engine"
        for flags in all_sublot_flags
        for f in flags
    )
    if not all_sublots_clear:
        return
    for f in heat_flags:
        if (
            f.get("source") == "extraction"
            and f.get("sublot_id") is None
            and f.get("status", "open") == "open"
            and _is_origin_related_field_name(f.get("field_name"))
        ):
            f["status"] = "resolved"
            f["resolved_by"] = actor
            f["resolved_at"] = resolved_at


def _resolve_open_sublot_duplicate_flags(
    heat_flags: list[dict], field_name: str, sublot_id: str, actor: str, resolved_at: str
) -> bool:
    """Resolves document_heats.flags_json's flattened copy of one
    specific sub-lot's flag. Requires an exact sublot_id match (not just
    field_name), which is what makes this safe now that compliance_engine
    flags carry sublot_id — correcting one sub-lot can no longer resolve
    a sibling sub-lot's still-open flag of the identical shape. Legacy
    flags written before sublot_id existed have sublot_id=None, which
    never matches a real row id, so they're left alone rather than
    guessed at (they just fall back on _heat_own_flags excluding them
    from aggregation, same as before this fix)."""
    changed = False
    for f in heat_flags:
        if f.get("field_name") == field_name and f.get("sublot_id") == sublot_id and f.get("status", "open") == "open":
            f["status"] = "resolved"
            f["resolved_by"] = actor
            f["resolved_at"] = resolved_at
            changed = True
    return changed


def _append_fresh_flags(flags: list[dict], fresh_flags: list[dict], match_sublot: bool) -> None:
    """Appends each freshly re-evaluated flag unless an open flag of the
    identical shape is already present, so re-running the check against
    an unchanged corrected value doesn't pile up duplicate entries.
    `match_sublot=True` additionally requires sublot_id to match — used
    against the heat-level flattened list, where more than one sub-lot's
    flags coexist and content alone can't tell them apart."""
    for fresh in fresh_flags:
        duplicate_open = any(
            f.get("status", "open") == "open"
            and f["issue_type"] == fresh["issue_type"]
            and f["field_name"] == fresh["field_name"]
            and f["human_readable_reason"] == fresh["human_readable_reason"]
            and (not match_sublot or f.get("sublot_id") == fresh.get("sublot_id"))
            for f in flags
        )
        if not duplicate_open:
            flags.append(dict(fresh))


def _revoke_stale_credential(conn, heat_credential_id: Optional[str], actor: str, revoked_at: str, reason: str) -> None:
    """Any correction to a heat (or one of its sub-lots) that already
    has an issued credential revokes that credential — deliberately not
    scoped to "only fields that plausibly matter": the credential's
    subject is a free-typed dict at issuance, not schema-validated
    against heat/sub-lot fields, so there's no reliable way to map a
    correction's field_name onto "did this actually change the signed
    subject." A false-positive revoke costs a reviewer a quick reissue;
    a false-negative leaves a stale PASS live. Idempotent — a credential
    already revoked (by an earlier correction to the same heat) is left
    alone rather than re-stamped or re-audited.

    Two concurrent corrections on the same heat can both reach this
    function with the same heat_credential_id, each independently
    deciding it needs revoking. `WHERE revoked_at IS NULL`, checked via
    rowcount, is the actual guard against a duplicate revoke — not a
    prior SELECT. (A separate read-then-write here would happen to be
    safe today too, because of where this call sits inside the caller's
    already-open transaction relative to correct_field's own earlier
    writes — but that's incidental to call order, not a guarantee, and
    isn't something to depend on.) Only the request whose UPDATE
    actually matched a row writes the audit entry, so a race never
    produces two 'revoked' entries for one credential."""
    if heat_credential_id is None:
        return
    cas = conn.execute(
        "UPDATE credentials SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        (revoked_at, heat_credential_id),
    )
    if cas.rowcount == 0:
        return
    audit.record(
        conn, "credential", heat_credential_id, "revoked", actor=actor,
        detail={"reason": reason},
    )


def _row_to_sublot(row) -> SublotOut:
    return SublotOut(
        id=row["id"],
        sublot_id=row["sublot_id"],
        blend_pct=row["blend_pct"],
        origin_country=row["origin_country"],
        origin_confidence=row["origin_confidence"],
        notes=row["notes"],
        flagged=bool(row["flagged"]),
        flags=json.loads(row["flags_json"]),
    )


def _fetch_sublots(conn, heat_id: str) -> list[SublotOut]:
    rows = conn.execute("SELECT * FROM heat_sublots WHERE heat_id = ? ORDER BY id", (heat_id,)).fetchall()
    return [_row_to_sublot(r) for r in rows]


def _row_to_heat(conn, row) -> HeatOut:
    sublots = _fetch_sublots(conn, row["id"])
    heat_flags = json.loads(row["flags_json"])
    any_open = _any_open(_heat_own_flags(heat_flags)) or any(f.status == "open" for s in sublots for f in s.flags)
    return HeatOut(
        id=row["id"],
        document_id=row["document_id"],
        heat_id=row["heat_id"],
        alloy_composition=json.loads(row["alloy_composition_json"]) if row["alloy_composition_json"] else None,
        test_results=json.loads(row["test_results_json"]) if row["test_results_json"] else None,
        nonconformance_refs=json.loads(row["nonconformance_refs_json"]),
        segregation_attested=bool(row["segregation_attested"]),
        segregation_attested_by=row["segregation_attested_by"],
        segregation_note=row["segregation_note"],
        mass_kg=row["mass_kg"],
        confidence=row["confidence"],
        source=row["source"],
        extraction_source=row["extraction_source"],
        flagged_for_review=bool(row["flagged_for_review"]),
        flags=heat_flags,
        reviewed=bool(row["reviewed"]),
        reviewed_by=row["reviewed_by"],
        reviewed_at=row["reviewed_at"],
        credential_id=row["credential_id"],
        sublots=sublots,
        fully_addressed=not any_open,
    )


def _fetch_heats(conn, document_id: str) -> list[HeatOut]:
    rows = conn.execute("SELECT * FROM document_heats WHERE document_id = ? ORDER BY id", (document_id,)).fetchall()
    return [_row_to_heat(conn, r) for r in rows]


# --- ownership helpers ----------------------------------------------------
#
# These are the *only* sanctioned way to fetch a document/heat/credential
# by id anywhere in this file. A route that needs one of these rows must
# go through the corresponding function below — there is no other path
# to the row that doesn't also run the org-ownership check. This exists
# because org-isolation gaps kept getting introduced by routes fetching a
# row directly and either hand-rolling their own ownership check (drift
# risk: two implementations of the same rule) or simply forgetting one
# (GET /credentials, /credentials/issue's sources[] — see git history).
#
# Each resource has two forms:
#   require_owned_*  — a plain function, for use inside a route body
#                       (loops over a body-supplied list of ids, or an id
#                       that isn't a path parameter at all).
#   owned_*           — a FastAPI dependency wrapping the same function,
#                       for routes where the id *is* a path parameter:
#                       declaring it in the route signature is the only
#                       way that route can obtain the row at all.


def require_owned_document(conn, current_user: dict, document_id: str) -> dict:
    row = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, row["org_id"])
    return dict(row)


def owned_document(document_id: str, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)) -> dict:
    return require_owned_document(conn, current_user, document_id)


def require_owned_heat(conn, current_user: dict, document_id: str, heat_id: str) -> dict:
    """document_id and heat_id both known up front (path-param routes).
    Scoping the heat fetch itself to document_id means a heat_id that
    exists but belongs to a different document 404s here too, same as
    before this helper existed."""
    require_owned_document(conn, current_user, document_id)
    row = conn.execute(
        "SELECT * FROM document_heats WHERE id = ? AND document_id = ?", (heat_id, document_id)
    ).fetchone()
    if row is None:
        raise HTTPException(404, "heat not found")
    return dict(row)


def owned_heat(
    document_id: str, heat_id: str, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)
) -> dict:
    return require_owned_heat(conn, current_user, document_id, heat_id)


def require_owned_heat_by_id(conn, current_user: dict, heat_id: str) -> dict:
    """heat_id only, no document_id in scope — /credentials/issue's
    body.heat_id shape. Fetches the heat first and derives its owning
    document from the row, then applies the identical org check."""
    heat = conn.execute("SELECT * FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    if heat is None:
        raise HTTPException(404, "heat not found")
    require_owned_document(conn, current_user, heat["document_id"])
    return dict(heat)


def require_owned_credential(conn, current_user: dict, credential_id: str) -> dict:
    row = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if row is None:
        raise HTTPException(404, f"credential {credential_id} not found")
    auth.require_org_match(current_user, row["issuer_id"])
    return dict(row)


def owned_credential(
    credential_id: str, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)
) -> dict:
    return require_owned_credential(conn, current_user, credential_id)


def _user_out(conn, user: dict) -> UserOut:
    org_name = None
    if user.get("org_id"):
        org_row = conn.execute("SELECT name FROM issuers WHERE id = ?", (user["org_id"],)).fetchone()
        org_name = org_row["name"] if org_row else None
    return UserOut(id=user["id"], org_id=user.get("org_id"), org_name=org_name, email=user["email"], role=user["role"])


# --- auth ---------------------------------------------------------------


@app.post("/auth/login", response_model=UserOut)
def login(body: LoginRequest, response: Response, conn=Depends(get_db)):
    row = conn.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()
    if row is None or not auth.verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "invalid email or password")
    user = dict(row)
    raw_token = auth.create_session(conn, user["id"])
    response.set_cookie(
        auth.COOKIE_NAME, raw_token, httponly=True, samesite="lax", secure=False,
        max_age=auth.SESSION_TTL_DAYS * 24 * 3600, path="/",
    )
    audit.record(conn, "user", user["id"], "login", actor=user["email"])
    return _user_out(conn, user)


@app.post("/auth/logout")
def logout(request: Request, response: Response, conn=Depends(get_db)):
    raw_token = request.cookies.get(auth.COOKIE_NAME)
    if raw_token:
        auth.delete_session(conn, raw_token)
    response.delete_cookie(auth.COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/auth/me", response_model=UserOut)
def me(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    return _user_out(conn, current_user)


@app.post("/admin/users", response_model=UserOut)
def create_user(body: CreateUserRequest, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    auth.require_role(current_user, "platform_admin")
    if body.role == "org_user" and not body.org_id:
        raise HTTPException(400, "org_user requires org_id")
    if body.org_id:
        org = conn.execute("SELECT id FROM issuers WHERE id = ?", (body.org_id,)).fetchone()
        if org is None:
            raise HTTPException(404, "org not found")

    user_id = uuid.uuid4().hex
    conn.execute(
        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, body.org_id, body.email, auth.hash_password(body.password), body.role, now_iso()),
    )
    conn.commit()
    audit.record(conn, "user", user_id, "created", actor=current_user["email"], detail={"role": body.role})
    return _user_out(conn, {"id": user_id, "org_id": body.org_id, "email": body.email, "role": body.role})


@app.get("/admin/extraction-stats")
def extraction_stats(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    """How often extraction flagged a heat for review, by extraction
    path — the signal for when it's safe to loosen the mandatory-review
    gate later (spec section 4.1). Reports flagged-rate rather than an
    exact field-level override diff: with nested composition/sub-lot
    data, "did the reviewer actually change anything" isn't a single
    yes/no per field anymore the way it was for the old flat schema."""
    auth.require_role(current_user, "platform_admin")

    def _rate(total: int, count: int) -> float | None:
        return round(count / total, 4) if total else None

    rows = conn.execute(
        """
        SELECT extraction_source, COUNT(*) AS total, SUM(flagged_for_review) AS flagged, SUM(reviewed) AS reviewed
        FROM document_heats WHERE extraction_source IN ('llm', 'regex') GROUP BY extraction_source
        """
    ).fetchall()
    return {
        "overall": [
            {
                "extraction_source": r["extraction_source"],
                "total": r["total"],
                "flagged": r["flagged"],
                "flagged_rate": _rate(r["total"], r["flagged"]),
                "reviewed": r["reviewed"],
            }
            for r in rows
        ],
    }


# --- documents / heats ------------------------------------------------------


def _document_upload_response(conn, document_id: str, filename: str, document_type: str, structured: dict) -> DocumentUploadResponse:
    return DocumentUploadResponse(
        id=document_id,
        filename=filename,
        document_type=document_type,
        status="extracted",
        certificate_id=structured.get("certificate_id"),
        supplier_id=structured.get("supplier_id"),
        heats=_fetch_heats(conn, document_id),
    )


@app.post("/documents/upload", response_model=DocumentUploadResponse)
async def upload_document(
    file: UploadFile = File(...),
    document_type: str = Form("mtr_coc"),
    current_user: dict = Depends(auth.get_current_user),
    conn=Depends(get_db),
):
    auth.require_role(current_user, "org_user")
    raw_bytes = await file.read()

    document_id = uuid.uuid4().hex
    object_key = f"{document_id}/{file.filename}"
    storage.save_object(object_key, raw_bytes)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    raw_text = ocr.extract_text(raw_bytes, file.filename)

    structured = llm_extractor.extract_structured(raw_text)

    uploaded_at = now_iso()
    conn.execute(
        """
        INSERT INTO documents (
            id, org_id, filename, document_type, object_key, content_hash, raw_text,
            certificate_id, supplier_id, signatures_json, status, uploaded_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'extracted', ?)
        """,
        (
            document_id, current_user["org_id"], file.filename, document_type, object_key, content_hash, raw_text,
            structured.get("certificate_id"), structured.get("supplier_id"),
            json.dumps(structured.get("signatures") or []), uploaded_at,
        ),
    )
    audit.record(
        conn, "document", document_id, "uploaded",
        actor=current_user["email"], detail={"filename": file.filename, "content_hash": content_hash},
    )

    for heat in structured["heats"]:
        sublots = heat.get("feedstock_sublots") or []
        # Row ids generated up front (rather than inline in the INSERT
        # below) so _evaluate_sublot_flag can stamp each flag with the
        # sub-lot id it actually belongs to — see review_flags.Flag's
        # sublot_id field.
        sublot_ids = [uuid.uuid4().hex for _ in sublots]
        sublot_flag_lists = [
            _evaluate_sublot_flag(s, sublot_id=sid) for s, sid in zip(sublots, sublot_ids, strict=True)
        ]  # list[list[dict]], compliance_engine
        extraction_flags = heat.get("flags") or []  # source='extraction', from the LLM/regex path
        heat_flags = extraction_flags + [f for flist in sublot_flag_lists for f in flist]
        heat_flagged = bool(heat_flags)

        heat_row_id = uuid.uuid4().hex
        conn.execute(
            """
            INSERT INTO document_heats (
                id, document_id, heat_id, alloy_composition_json, test_results_json, nonconformance_refs_json,
                segregation_attested, segregation_attested_by, segregation_note, mass_kg, confidence,
                source, extraction_source, flagged_for_review, flags_json, reviewed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                heat_row_id, document_id, heat.get("heat_id"),
                json.dumps(heat["alloy_composition"]) if heat.get("alloy_composition") is not None else None,
                json.dumps(heat["test_results"]) if heat.get("test_results") is not None else None,
                json.dumps(heat.get("nonconformance_refs") or []),
                1 if heat.get("segregation_attested") else 0,
                heat.get("segregation_note"),
                heat.get("mass_kg"),
                heat.get("confidence"),
                heat["source"], heat["source"],
                1 if heat_flagged else 0,
                json.dumps(heat_flags),
            ),
        )
        for sid, sublot, sublot_flags in zip(sublot_ids, sublots, sublot_flag_lists, strict=True):
            conn.execute(
                """
                INSERT INTO heat_sublots (id, heat_id, sublot_id, blend_pct, origin_country, origin_confidence, notes, flagged, flags_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid, heat_row_id, sublot.get("sublot_id"), sublot.get("blend_pct"),
                    sublot.get("origin_country"), sublot.get("origin_confidence"), sublot.get("notes"),
                    1 if sublot_flags else 0, json.dumps(sublot_flags),
                ),
            )
    conn.commit()
    audit.record(conn, "document", document_id, "extracted", actor="system")
    extraction_failure = structured.get("extraction_failure")
    if extraction_failure is not None:
        # Durable, queryable record of the degradation -- category
        # ("transient"/"permanent"/"malformed", see llm_extractor.py) is
        # the field to filter on directly; exception_class/message ride
        # along for diagnostics, not meant to be cross-referenced by
        # hand. Distinct from the heat-level extraction_unavailable
        # flag (which a reviewer sees in the UI) -- this is the
        # operational/audit-trail side of the same event.
        audit.record(conn, "document", document_id, "extraction_degraded", actor="system", detail=extraction_failure)

    return _document_upload_response(conn, document_id, file.filename, document_type, structured)


@app.get("/documents", response_model=list[DocumentDetail])
def list_documents(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    auth.require_role(current_user, "org_user", "platform_admin")
    if auth.is_cross_org_reader(current_user):
        rows = conn.execute("SELECT * FROM documents ORDER BY uploaded_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM documents WHERE org_id = ? ORDER BY uploaded_at DESC", (current_user["org_id"],)
        ).fetchall()
    return [
        DocumentDetail(
            id=r["id"],
            filename=r["filename"],
            document_type=r["document_type"],
            raw_text=r["raw_text"],
            status=r["status"],
            uploaded_at=r["uploaded_at"],
            certificate_id=r["certificate_id"],
            supplier_id=r["supplier_id"],
            heats=_fetch_heats(conn, r["id"]),
        )
        for r in rows
    ]


@app.get("/documents/{document_id}", response_model=DocumentDetail)
def get_document(
    document_id: str,
    current_user: dict = Depends(auth.get_current_user),
    doc: dict = Depends(owned_document),
    conn=Depends(get_db),
):
    auth.require_role(current_user, "org_user", "platform_admin")
    return DocumentDetail(
        id=doc["id"],
        filename=doc["filename"],
        document_type=doc["document_type"],
        raw_text=doc["raw_text"],
        status=doc["status"],
        uploaded_at=doc["uploaded_at"],
        certificate_id=doc["certificate_id"],
        supplier_id=doc["supplier_id"],
        heats=_fetch_heats(conn, document_id),
    )


@app.post("/documents/{document_id}/heats/{heat_id}/review", response_model=HeatOut)
def review_heat(
    document_id: str,
    heat_id: str,
    body: HeatReviewRequest,
    current_user: dict = Depends(auth.get_current_user),
    heat: dict = Depends(owned_heat),
    conn=Depends(get_db),
):
    auth.require_role(current_user, "org_user")
    if heat["reviewed"]:
        raise HTTPException(409, "heat already reviewed; a new review cycle is required to change it")

    sublot_dicts = [s.model_dump() for s in body.sublots]
    # Upsert by id, not a blind drop-and-reinsert: a submitted sublot whose
    # `id` matches an existing row for this heat gets updated in place (its
    # row id stays stable across this /review call — a client that already
    # holds that id, e.g. from a prior GET, doesn't need to refetch before
    # a later /correct call references it). No id, or an id that doesn't
    # match, is a new sub-lot and gets a fresh one. Any existing row not
    # referenced by this submission is removed below, preserving full-
    # replace semantics for a reviewer who drops a sub-lot.
    existing_sublot_ids = {row["id"] for row in conn.execute("SELECT id FROM heat_sublots WHERE heat_id = ?", (heat_id,))}
    sublot_row_ids: list[str] = []
    sublot_is_update: list[bool] = []
    claimed_ids: set[str] = set()
    for sublot in sublot_dicts:
        candidate = sublot.get("id")
        if candidate and candidate in existing_sublot_ids and candidate not in claimed_ids:
            sublot_row_ids.append(candidate)
            sublot_is_update.append(True)
        else:
            sublot_row_ids.append(uuid.uuid4().hex)
            sublot_is_update.append(False)
        claimed_ids.add(sublot_row_ids[-1])

    sublot_flag_lists = [
        _evaluate_sublot_flag(s, sublot_id=sid) for s, sid in zip(sublot_dicts, sublot_row_ids, strict=True)
    ]
    # Heat-level (sublot_id is None) flags — anything the LLM itself
    # noticed at extraction, as opposed to a sub-lot-level compliance_engine
    # check — must survive this UPDATE, not just sub-lot flags. They used
    # to be silently dropped: this function rebuilt flags_json from sub-lot
    # checks alone, so any heat-level flag vanished the moment /review was
    # submitted, whether or not the reviewer ever addressed it, with
    # nothing in the audit log to show it happened. Reading them straight
    # from the current row (not some earlier snapshot) means a resolution
    # already applied via /correct before this call is respected as-is,
    # not reverted — /correct's field-target branch resolves flags on this
    # exact flags_json in place, so whatever's there now already reflects
    # that. Sub-lot-level flags are still fully recomputed below, since
    # that path was never broken — sublot ids can also legitimately change
    # (the upsert-by-id logic above), so re-deriving them fresh against
    # current sub-lot data, rather than trying to carry old copies forward,
    # is correct, not a shortcut.
    existing_flags = json.loads(heat["flags_json"])
    existing_heat_level_flags = [f for f in existing_flags if not f.get("sublot_id")]
    heat_flags = existing_heat_level_flags + [f for flist in sublot_flag_lists for f in flist]
    reviewed_at = now_iso()
    # A heat-level extraction flag about origin data (see
    # _resolve_heat_level_origin_flags_if_all_sublots_clear) has no
    # direct correction path of its own -- if every sub-lot submitted in
    # this review is clean, resolve it here too, not just when a later
    # /correct call touches a sub-lot. Otherwise a reviewer who fixes a
    # sub-lot's origin directly in this form (rather than via the
    # correction panel afterward) would hit the same dead end.
    _resolve_heat_level_origin_flags_if_all_sublots_clear(heat_flags, sublot_flag_lists, current_user["email"], reviewed_at)
    # _any_open, not bool(heat_flags): a preserved heat-level flag can be
    # resolved (its status carried over as-is from the row above), so the
    # list being non-empty no longer means there's an open issue — unlike
    # before this fix, when heat_flags only ever held freshly-computed
    # sub-lot flags, which are always open by construction.
    still_flagged = _any_open(heat_flags)
    # Compare-and-swap, not a blind UPDATE: `reviewed = 0` blocks a second
    # concurrent /review submission on the same heat from also winning
    # (both would otherwise read reviewed=0 before either commits and
    # both apply, silently overwriting each other with two duplicate
    # 'reviewed' audit entries). `heat_id IS ? AND mass_kg IS ? AND
    # flags_json = ?` additionally guards the two columns /correct can
    # independently touch on this same row: if a correction lands
    # concurrently and changes any of them, this WHERE no longer matches
    # the row this review was actually written against, and the
    # reviewer's now-stale full-replace form is rejected with a 409
    # instead of silently clobbering the correction. Values are exactly
    # what `heat` (read once, at request start) held — the row's own
    # current state doubles as its version, no schema change needed.
    cas = conn.execute(
        """
        UPDATE document_heats
        SET heat_id = ?, alloy_composition_json = ?, test_results_json = ?, nonconformance_refs_json = ?,
            segregation_attested = ?, segregation_attested_by = ?, segregation_note = ?, mass_kg = ?,
            source = 'human', flagged_for_review = ?, flags_json = ?,
            reviewed = 1, reviewed_by = ?, reviewed_at = ?
        WHERE id = ? AND reviewed = 0 AND heat_id IS ? AND mass_kg IS ? AND flags_json = ?
        """,
        (
            body.heat_id,
            json.dumps(body.alloy_composition) if body.alloy_composition is not None else None,
            json.dumps(body.test_results) if body.test_results is not None else None,
            json.dumps(body.nonconformance_refs),
            1 if body.segregation_attested else 0,
            body.segregation_attested_by,
            body.segregation_note,
            body.mass_kg,
            1 if still_flagged else 0,
            json.dumps(heat_flags),
            current_user["email"],
            reviewed_at,
            heat_id,
            heat["heat_id"],
            heat["mass_kg"],
            heat["flags_json"],
        ),
    )
    if cas.rowcount == 0:
        conn.rollback()
        raise HTTPException(
            409,
            "heat was modified by a concurrent review or correction; refresh and resubmit the review",
        )
    stale_sublot_ids = existing_sublot_ids - claimed_ids
    for stale_id in stale_sublot_ids:
        conn.execute("DELETE FROM heat_sublots WHERE id = ?", (stale_id,))
    for sid, sublot, sublot_flags, is_update in zip(
        sublot_row_ids, sublot_dicts, sublot_flag_lists, sublot_is_update, strict=True
    ):
        if is_update:
            conn.execute(
                """
                UPDATE heat_sublots
                SET sublot_id = ?, blend_pct = ?, origin_country = ?, origin_confidence = ?, notes = ?,
                    flagged = ?, flags_json = ?
                WHERE id = ?
                """,
                (
                    sublot["sublot_id"], sublot["blend_pct"], sublot["origin_country"], sublot["origin_confidence"],
                    sublot["notes"], 1 if sublot_flags else 0, json.dumps(sublot_flags), sid,
                ),
            )
        else:
            conn.execute(
                """
                INSERT INTO heat_sublots (id, heat_id, sublot_id, blend_pct, origin_country, origin_confidence, notes, flagged, flags_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sid, heat_id, sublot["sublot_id"], sublot["blend_pct"],
                    sublot["origin_country"], sublot["origin_confidence"], sublot["notes"],
                    1 if sublot_flags else 0, json.dumps(sublot_flags),
                ),
            )
    conn.commit()
    # Records open-flag state on both sides of this submission — the
    # heat-level flag-drop bug this guards against existed specifically
    # because nothing in the audit trail showed a review's effect on
    # flags_json, only that "reviewed" happened.
    def _open_flag_summary(flags):
        return [
            {"issue_type": f["issue_type"], "field_name": f.get("field_name"), "sublot_id": f.get("sublot_id")}
            for f in flags
            if f.get("status") != "resolved"
        ]

    audit.record(
        conn, "document_heat", heat_id, "reviewed", actor=current_user["email"],
        detail={
            "open_flags_before": _open_flag_summary(existing_flags),
            "open_flags_after": _open_flag_summary(heat_flags),
        },
    )

    updated = conn.execute("SELECT * FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    return _row_to_heat(conn, updated)


@app.post("/documents/{document_id}/heats/{heat_id}/correct", response_model=HeatOut)
def correct_field(
    document_id: str,
    heat_id: str,
    body: FieldCorrectionRequest,
    current_user: dict = Depends(auth.get_current_user),
    heat: dict = Depends(owned_heat),
    conn=Depends(get_db),
):
    """Corrects one field in place — unlike /review, this is allowed any
    number of times and regardless of the heat's `reviewed` lock, since a
    correction is its own audited event, not a re-review. A resolved flag
    is kept (status flips to 'resolved'), never deleted, and a sub-lot
    correction re-runs the same deterministic check extraction/`/review`
    use, so a corrected origin_country picks up a fresh compliance_violation
    flag exactly as if it had been that way from the start."""
    auth.require_role(current_user, "org_user")
    actor = current_user["email"]
    corrected_at = now_iso()
    sublot_row_id = None

    if body.target == "heat":
        if body.field_name not in _HEAT_CORRECTABLE_FIELDS:
            raise HTTPException(400, f"heat field '{body.field_name}' cannot be corrected here")
        column_name, field_type = _HEAT_CORRECTABLE_FIELDS[body.field_name]
        corrected_value = _coerce_corrected_value(body.corrected_value, field_type)
        # dict-typed fields (alloy_composition/test_results) are stored
        # as a _json-suffixed TEXT column — everything from here down
        # binds/reads bound_value, never corrected_value directly, so a
        # scalar field's bound_value is just corrected_value unchanged.
        bound_value = json.dumps(corrected_value) if field_type is dict else corrected_value

        # Compare-and-swap on flags_json, retried on conflict rather than
        # surfaced as an error: two /correct calls targeting DIFFERENT
        # fields on the same heat both read-modify-write this one shared
        # JSON blob (see upload_document), so whichever commits last can
        # silently discard the other's flag resolution even though
        # neither request did anything wrong — they aren't a real
        # conflict, they just share storage. Re-reading fresh and
        # retrying, instead of a 409 like review_heat's CAS below, means
        # both corrections land correctly without either caller ever
        # seeing an error for something that wasn't their fault.
        for _attempt in range(_CAS_MAX_RETRIES):
            current = conn.execute("SELECT * FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
            raw_previous = current[column_name]
            previous_value = json.loads(raw_previous) if field_type is dict and raw_previous is not None else raw_previous
            heat_flags = json.loads(current["flags_json"])
            _resolve_open_flags_for_field(heat_flags, body.field_name, actor, corrected_at)
            sibling_sublot_rows = conn.execute(
                "SELECT flags_json FROM heat_sublots WHERE heat_id = ?", (heat_id,)
            ).fetchall()
            heat_still_flagged = _any_open(_heat_own_flags(heat_flags)) or any(
                _any_open(json.loads(r["flags_json"])) for r in sibling_sublot_rows
            )

            cas = conn.execute(
                f"""
                UPDATE document_heats
                SET {column_name} = ?, source = 'human', flags_json = ?, flagged_for_review = ?
                WHERE id = ? AND flags_json = ?
                """,
                (
                    bound_value, json.dumps(heat_flags), 1 if heat_still_flagged else 0,
                    heat_id, current["flags_json"],
                ),
            )
            if cas.rowcount == 1:
                break
            conn.rollback()
        else:
            raise HTTPException(409, "too many concurrent corrections on this heat; please retry")
    else:
        if body.sublot_id is None:
            raise HTTPException(400, "sublot_id is required when target is 'sublot'")
        if body.field_name not in _SUBLOT_CORRECTABLE_FIELDS:
            raise HTTPException(400, f"sub-lot field '{body.field_name}' cannot be corrected here")
        sublot_column_name, sublot_field_type = _SUBLOT_CORRECTABLE_FIELDS[body.field_name]
        corrected_value = _coerce_corrected_value(body.corrected_value, sublot_field_type)

        # Same compare-and-swap-with-retry shape as the heat branch
        # above, applied to both flags_json copies this branch writes:
        # the sub-lot's own, and document_heats' flattened duplicate of
        # it. A conflict on either re-reads and retries the whole
        # attempt, so the two writes stay consistent with each other —
        # a partial application (sub-lot updated but the heat-level copy
        # not synced to match) would itself be a new inconsistency.
        for _attempt in range(_CAS_MAX_RETRIES):
            sublot = conn.execute(
                "SELECT * FROM heat_sublots WHERE id = ? AND heat_id = ?", (body.sublot_id, heat_id)
            ).fetchone()
            if sublot is None:
                raise HTTPException(404, "sub-lot not found")
            previous_value = sublot[sublot_column_name]

            sublot_flags = json.loads(sublot["flags_json"])
            _resolve_open_flags_for_field(sublot_flags, body.field_name, actor, corrected_at)

            # Re-run the same deterministic check extraction/`/review`
            # use, against the corrected value — this is what makes a
            # corrected origin_country pick up (or drop) a
            # compliance_violation flag live, rather than just clearing
            # whatever was flagged before.
            updated_sublot = dict(sublot)
            updated_sublot[sublot_column_name] = corrected_value
            fresh_flags = _evaluate_sublot_flag(updated_sublot, sublot_id=body.sublot_id)
            _append_fresh_flags(sublot_flags, fresh_flags, match_sublot=False)
            sublot_still_flagged = _any_open(sublot_flags)

            sublot_cas = conn.execute(
                f"UPDATE heat_sublots SET {sublot_column_name} = ?, flags_json = ?, flagged = ? WHERE id = ? AND flags_json = ?",
                (
                    corrected_value, json.dumps(sublot_flags), 1 if sublot_still_flagged else 0,
                    body.sublot_id, sublot["flags_json"],
                ),
            )
            if sublot_cas.rowcount == 0:
                conn.rollback()
                continue

            # document_heats.flags_json holds a flattened copy of this same
            # flag (see upload_document/review_heat) — now that compliance_engine
            # flags carry sublot_id, that copy can be resolved/refreshed
            # precisely, without risking touching a sibling sub-lot's flag of
            # the identical shape. flagged_for_review itself still never
            # trusts this list directly (_heat_own_flags), only the sub-lot
            # rows queried below — this sync is for accurate display only.
            current_heat = conn.execute("SELECT flags_json FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
            heat_flags = json.loads(current_heat["flags_json"])
            _resolve_open_sublot_duplicate_flags(heat_flags, body.field_name, body.sublot_id, actor, corrected_at)
            _append_fresh_flags(heat_flags, fresh_flags, match_sublot=True)

            all_sublot_rows = conn.execute("SELECT flags_json FROM heat_sublots WHERE heat_id = ?", (heat_id,)).fetchall()
            all_sublot_flags = [json.loads(r["flags_json"]) for r in all_sublot_rows]
            # See _resolve_heat_level_origin_flags_if_all_sublots_clear:
            # a heat-level extraction flag about origin data has no
            # direct correction of its own -- this is what stops it from
            # staying open (and blocking issuance) forever after the
            # real sub-lot data has been fixed.
            _resolve_heat_level_origin_flags_if_all_sublots_clear(heat_flags, all_sublot_flags, actor, corrected_at)
            heat_still_flagged = _any_open(_heat_own_flags(heat_flags)) or any(_any_open(flags) for flags in all_sublot_flags)
            heat_cas = conn.execute(
                "UPDATE document_heats SET source = 'human', flags_json = ?, flagged_for_review = ? WHERE id = ? AND flags_json = ?",
                (json.dumps(heat_flags), 1 if heat_still_flagged else 0, heat_id, current_heat["flags_json"]),
            )
            if heat_cas.rowcount == 0:
                conn.rollback()
                continue
            sublot_row_id = body.sublot_id
            break
        else:
            raise HTTPException(409, "too many concurrent corrections on this heat; please retry")

    audit.record(
        conn, "document_heat", heat_id, "field_corrected", actor=actor,
        detail={
            "target": body.target,
            "sublot_id": sublot_row_id,
            "field_name": body.field_name,
            "previous_value": previous_value,
            "corrected_value": corrected_value,
        },
    )
    _revoke_stale_credential(
        conn, heat["credential_id"], actor, corrected_at,
        reason=f"source heat data corrected: {body.target} field '{body.field_name}'",
    )
    conn.commit()

    updated = conn.execute("SELECT * FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    return _row_to_heat(conn, updated)


@app.get("/documents/{document_id}/heats/{heat_id}/audit-trail")
def get_heat_audit_trail(
    document_id: str,
    heat_id: str,
    current_user: dict = Depends(auth.get_current_user),
    heat: dict = Depends(owned_heat),
    conn=Depends(get_db),
):
    """Reviewed/corrected events for one heat, independent of whether a
    credential has been issued from it yet — the review-queue UI shows
    this directly under the heat card, so a reviewer can confirm a
    correction landed without first issuing a credential just to reach
    /credentials/{id}/audit-trail's Timeline."""
    auth.require_role(current_user, "org_user", "platform_admin")
    rows = conn.execute(
        "SELECT action, actor, detail_json, created_at FROM audit_log WHERE entity_type = 'document_heat' AND entity_id = ? ORDER BY created_at",
        (heat_id,),
    ).fetchall()
    return [
        {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
        for r in rows
    ]


# --- issuers / credentials -------------------------------------------------


@app.get("/issuers")
def list_issuers(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    auth.require_role(current_user, "platform_admin")
    rows = conn.execute("SELECT id, name, public_key, created_at FROM issuers ORDER BY name").fetchall()
    return [dict(r) for r in rows]


@app.get("/credentials")
def list_credentials(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    if auth.is_cross_org_reader(current_user):
        rows = conn.execute("SELECT * FROM credentials ORDER BY issued_at DESC").fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM credentials WHERE issuer_id = ? ORDER BY issued_at DESC", (current_user["org_id"],)
        ).fetchall()
    return [
        {
            "id": r["id"],
            "credential_type": r["credential_type"],
            "subject": json.loads(r["subject_json"]),
            "sources": json.loads(r["sources_json"]),
            "issued_at": r["issued_at"],
            "revoked_at": r["revoked_at"],
        }
        for r in rows
    ]


@app.post("/credentials/issue", response_model=CredentialResponse)
def issue_credential(
    body: CredentialIssueRequest,
    current_user: dict = Depends(auth.get_current_user),
    conn=Depends(get_db),
):
    auth.require_role(current_user, "org_user")
    issuer_id = current_user["org_id"]
    issuer = conn.execute("SELECT * FROM issuers WHERE id = ?", (issuer_id,)).fetchone()
    if issuer is None:
        raise HTTPException(404, "issuer not found")

    document_id = None
    document_content_hash = None
    supersedes_credential_id = None
    if body.heat_id is not None:
        heat = require_owned_heat_by_id(conn, current_user, body.heat_id)
        if not heat["reviewed"]:
            raise HTTPException(400, "heat must be reviewed before a credential can be issued from it")
        # reviewed=True only means the review form was submitted once —
        # it does not mean every flag is resolved (see HeatOut.fully_
        # addressed, computed independently). A heat with an open
        # blocking flag (e.g. an unresolved compliance_violation) must
        # not be issuable, regardless of what the client's `subject`
        # claims — this only ever applied to `body.heat_id` (fresh,
        # uncorrected data), not to `body.sources`: an already-issued
        # source credential's own compliance state is deferred to
        # passport-compile-time re-evaluation, same as a revoked source
        # already isn't blocked from being cited here today.
        if _heat_has_open_blocking_flag(conn, heat):
            raise HTTPException(
                409,
                "heat has an open blocking flag (e.g. an unresolved compliance violation) — "
                "resolve it before issuing a credential",
            )
        if heat["credential_id"]:
            # A credential already exists for this heat — only an
            # explicit reissue (the existing one revoked, e.g. by a
            # correction landing on this heat after it was signed) is
            # allowed to proceed. This is the deliberate "explicit
            # reissue" step: nothing here reuses the old subject or
            # auto-fills anything — the reviewer fills out this same
            # form again with the corrected data.
            #
            # Fast-path check only, not the actual guard: two concurrent
            # issuances from the same heat would both read credential_id
            # as unset/revoked here before either commits. The real
            # guard is the conditional UPDATE further down (checked via
            # rowcount, not this read) — see its comment.
            existing = conn.execute(
                "SELECT id, revoked_at FROM credentials WHERE id = ?", (heat["credential_id"],)
            ).fetchone()
            if existing and not existing["revoked_at"]:
                raise HTTPException(409, "a credential has already been issued from this heat")
            supersedes_credential_id = heat["credential_id"]
        # Already ownership-verified by require_owned_heat_by_id above —
        # this is just the plain document row for its content_hash.
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (heat["document_id"],)).fetchone()
        document_id = doc["id"]
        document_content_hash = doc["content_hash"]

    for source_id in body.sources:
        # Same-org-only for now: without this, this org's new credential
        # could cite another org's real credential as a parent with no
        # consent from the org that actually issued it. A real cross-org
        # composite-credential workflow would need an explicit
        # consent/transfer step that doesn't exist yet; until it does,
        # sourcing stays same-org-only.
        require_owned_credential(conn, current_user, source_id)

    credential_id = uuid.uuid4().hex
    issued_at = now_iso()
    payload = crypto_utils.credential_signable_payload(
        id=credential_id,
        issuer_id=issuer_id,
        credential_type=body.credential_type,
        subject=body.subject,
        sources=body.sources,
        segregation_attested=body.segregation_attested,
        segregation_attested_by=body.segregation_attested_by,
        segregation_note=body.segregation_note,
        document_id=document_id,
        document_content_hash=document_content_hash,
        issued_at=issued_at,
    )
    signature, payload_hash = crypto_utils.sign_payload(issuer["private_key_path"], payload)

    conn.execute(
        """
        INSERT INTO credentials (
            id, issuer_id, credential_type, subject_json, sources_json,
            segregation_attested, segregation_attested_by, segregation_note,
            document_id, document_content_hash, heat_id, payload_hash, signature, superseded_by, revoked_at, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
        """,
        (
            credential_id,
            issuer_id,
            body.credential_type,
            json.dumps(body.subject),
            json.dumps(body.sources),
            1 if body.segregation_attested else 0,
            body.segregation_attested_by,
            body.segregation_note,
            document_id,
            document_content_hash,
            body.heat_id,
            payload_hash,
            signature,
            issued_at,
        ),
    )
    if body.heat_id is not None:
        # The actual guard against two credentials being issued from the
        # same heat: succeeds only if the heat still has no active
        # (unrevoked) credential right now, not as of the read above.
        # Two concurrent requests both attempting this UPDATE serialize
        # at the database level (SQLite today, Postgres unchanged after
        # the planned migration — this is standard row-level locking,
        # nothing SQLite-specific) — whichever commits first wins the
        # claim, and the second's WHERE clause then simply fails to
        # match the now-claimed row. rowcount, not the earlier SELECT,
        # is the source of truth for whether this request won.
        claim = conn.execute(
            """
            UPDATE document_heats
            SET credential_id = ?
            WHERE id = ?
              AND (
                credential_id IS NULL
                OR credential_id IN (SELECT id FROM credentials WHERE revoked_at IS NOT NULL)
              )
            """,
            (credential_id, body.heat_id),
        )
        if claim.rowcount == 0:
            conn.rollback()
            raise HTTPException(409, "a credential has already been issued from this heat")
    # A real Construct #1 UII needs the issuer's registered iac+enterprise_id
    # (see db.py's issuers migration) — until that's set for a given issuer,
    # falling back to the bare credential_id as uii_code is deliberate, not
    # an oversight: it's exactly the legacy shape uii.parse_uii already
    # resolves via its bare-credential_id fallback stage, so nothing here
    # breaks for an issuer that hasn't registered a UII prefix yet.
    if issuer["iac"] and issuer["enterprise_id"]:
        uii_code = uii.generate_uii(issuer["iac"], issuer["enterprise_id"], credential_id)
    else:
        uii_code = credential_id
    conn.execute(
        "INSERT INTO uii_bindings (id, credential_id, uii_code, created_at) VALUES (?, ?, ?, ?)",
        (uuid.uuid4().hex, credential_id, uii_code, issued_at),
    )
    if supersedes_credential_id is not None:
        conn.execute("UPDATE credentials SET superseded_by = ? WHERE id = ?", (credential_id, supersedes_credential_id))
        audit.record(
            conn, "credential", supersedes_credential_id, "superseded",
            actor=current_user["email"], detail={"superseded_by": credential_id},
        )
    conn.commit()
    audit.record(
        conn, "credential", credential_id, "issued", actor=current_user["email"],
        detail={"credential_type": body.credential_type, "supersedes": supersedes_credential_id},
    )

    return CredentialResponse(
        id=credential_id,
        issuer_id=issuer_id,
        credential_type=body.credential_type,
        subject=body.subject,
        sources=body.sources,
        segregation_attested=body.segregation_attested,
        segregation_attested_by=body.segregation_attested_by,
        segregation_note=body.segregation_note,
        document_id=document_id,
        document_content_hash=document_content_hash,
        heat_id=body.heat_id,
        payload_hash=payload_hash,
        signature=signature,
        superseded_by=None,
        revoked_at=None,
        issued_at=issued_at,
    )


def _scan_payload_for_binding(binding) -> str:
    # uii_bindings.uii_code holds the bare canonical UII value (or, for an
    # issuer with no registered iac/enterprise_id yet, the bare
    # credential_id — see the fallback in issue_credential). Only the
    # former should be wrapped in the ISO/IEC 15434 envelope for scanning;
    # a legacy binding is never a real IAC+EID+serial triple, so it stays
    # unwrapped, unchanged from today's behavior. A real generated UII can
    # never equal the raw credential_id (it's always at least iac+eid
    # longer and uppercased), so this equality check is a sound way to
    # tell the two apart without a new column.
    if binding["uii_code"] == binding["credential_id"]:
        return binding["uii_code"]
    return uii.wrap_scan_payload(binding["uii_code"])


def _passport_url(request: Request, scan_payload: str) -> str:
    # scan_payload is the full scanned/printed form — a real Construct #1
    # UII's ISO/IEC 15434 envelope (containing control chars and
    # punctuation like `[`, `)`, `>`) or a legacy bare credential_id.
    # quote() is required now that this can be the former: an un-encoded
    # 25S envelope isn't valid inside a URL query string.
    return f"{str(request.base_url).rstrip('/')}/passport.html?id={quote(scan_payload, safe='')}"


@app.get("/credentials/{credential_id}/uii")
def get_uii_binding(credential_id: str, request: Request, conn=Depends(get_db)):
    binding = conn.execute("SELECT * FROM uii_bindings WHERE credential_id = ?", (credential_id,)).fetchone()
    if binding is None:
        raise HTTPException(404, "no UII binding for this credential")
    return {
        "uii_code": binding["uii_code"],
        "credential_id": binding["credential_id"],
        "created_at": binding["created_at"],
        "passport_url": _passport_url(request, _scan_payload_for_binding(binding)),
        "image_url": f"/credentials/{credential_id}/uii/image",
    }


@app.get("/credentials/{credential_id}/uii/image")
def get_uii_image(credential_id: str, request: Request, conn=Depends(get_db)):
    binding = conn.execute("SELECT * FROM uii_bindings WHERE credential_id = ?", (credential_id,)).fetchone()
    if binding is None:
        raise HTTPException(404, "no UII binding for this credential")
    png_bytes = uii.generate_datamatrix_png(_passport_url(request, _scan_payload_for_binding(binding)))
    return Response(content=png_bytes, media_type="image/png")


@app.get("/credentials/{credential_id}/audit-trail")
def get_audit_trail(credential_id: str, credential: dict = Depends(owned_credential), conn=Depends(get_db)):
    """Everything the public /passport/{id} view doesn't show: who
    reviewed/issued this credential and when, and (if it came from a
    document) the originating heat's extraction/review detail — original
    confidence, whether it was flagged, and its sub-lot table. Login-
    only — the extra depth is what makes buyer_auditor's role
    meaningfully more than the public passport lookup."""
    audit_rows = conn.execute(
        "SELECT action, actor, detail_json, created_at FROM audit_log WHERE entity_type = 'credential' AND entity_id = ? ORDER BY created_at",
        (credential_id,),
    ).fetchall()

    document_audit_rows = []
    heat_audit_rows = []
    heat_out = None
    if credential["document_id"]:
        document_audit_rows = conn.execute(
            "SELECT action, actor, detail_json, created_at FROM audit_log WHERE entity_type = 'document' AND entity_id = ? ORDER BY created_at",
            (credential["document_id"],),
        ).fetchall()
        # Looked up by credentials.heat_id (permanent, set once at
        # issuance) rather than document_heats.credential_id (which
        # always points at whichever credential is *currently* active
        # for that heat) — a revoked/superseded credential would
        # otherwise lose track of its originating heat the moment a
        # successor is issued.
        heat_row = conn.execute("SELECT * FROM document_heats WHERE id = ?", (credential["heat_id"],)).fetchone()
        if heat_row is not None:
            heat_out = _row_to_heat(conn, heat_row).model_dump()
            # Reviewed/field_corrected events — same entity_type='document_heat'
            # rows /documents/{id}/heats/{id}/audit-trail reads, so a
            # correction made before this credential ever existed still
            # shows up here once one is issued.
            heat_audit_rows = conn.execute(
                "SELECT action, actor, detail_json, created_at FROM audit_log WHERE entity_type = 'document_heat' AND entity_id = ? ORDER BY created_at",
                (heat_row["id"],),
            ).fetchall()

    # The chain in both directions: what this credential replaced (if
    # it's a reissue) and what replaced it (if it's since been revoked
    # and reissued again) — superseded_by lives on the old row and
    # points forward, so "what did I replace" is a reverse lookup.
    predecessor = conn.execute(
        "SELECT id, revoked_at, issued_at FROM credentials WHERE superseded_by = ?", (credential_id,)
    ).fetchone()

    return {
        "credential_id": credential_id,
        "revoked_at": credential["revoked_at"],
        "superseded_by": credential["superseded_by"],
        "supersedes": dict(predecessor) if predecessor else None,
        "audit_log": [
            {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
            for r in audit_rows
        ],
        "document_audit_log": [
            {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
            for r in document_audit_rows
        ],
        "heat_audit_log": [
            {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
            for r in heat_audit_rows
        ],
        "heat": heat_out,
    }


# --- passport (public) ------------------------------------------------------


def _known_issuer_prefixes(conn) -> dict[str, tuple[str, str]]:
    return {
        f"{row['iac']}{row['enterprise_id']}": (row["iac"], row["enterprise_id"])
        for row in conn.execute(
            "SELECT iac, enterprise_id FROM issuers WHERE iac IS NOT NULL AND enterprise_id IS NOT NULL"
        )
    }


def _resolve_credential_for_lookup(conn, lookup_key: str) -> tuple[str, bool]:
    """Runs uii.parse_uii on whatever a passport lookup was given —
    a real Construct #1 UII, a legacy bare credential_id (today's shape,
    and still what an issuer with no registered iac/enterprise_id
    produces), or garbage — and returns (credential_id, is_legacy) on a
    match. Raises the two distinct failure modes as distinct HTTP codes:
    malformed/unsupported-construct (not even a valid UII) is a 400, a
    well-formed UII or legacy id with no match is a 404 — collapsing
    those back into one status would hide "rescan, bad photo" from
    "this genuinely isn't registered"."""
    def resolve_uii(code: str) -> Optional[str]:
        row = conn.execute("SELECT credential_id FROM uii_bindings WHERE uii_code = ?", (code,)).fetchone()
        return row["credential_id"] if row else None

    def resolve_legacy_credential_id(text: str) -> Optional[str]:
        row = conn.execute("SELECT id FROM credentials WHERE id = ?", (text,)).fetchone()
        return row["id"] if row else None

    result = uii.parse_uii(lookup_key, _known_issuer_prefixes(conn), resolve_uii, resolve_legacy_credential_id)
    if result.outcome in ("malformed", "unsupported_construct"):
        raise HTTPException(400, f"malformed UII: {result.reason}")
    if result.outcome == "not_found":
        raise HTTPException(404, "credential not found")
    return result.credential_id, result.is_legacy


@app.get("/passport/{lookup_key}", response_model=PassportResult)
def get_passport(lookup_key: str, conn=Depends(get_db)):
    credential_id, is_legacy = _resolve_credential_for_lookup(conn, lookup_key)
    result = passport_engine.compile_passport(conn, credential_id)
    audit.record(
        conn, "credential", credential_id, "passport_viewed", actor="unauthenticated",
        detail={"is_legacy": True} if is_legacy else {},
    )
    return PassportResult(**result)


def _revocation_reason(conn, credential_id: str) -> Optional[str]:
    """The revocation reason lives only in audit_log (main.py's
    _revoke_stale_credential writes it there, never onto the credentials
    row itself) — deliberately pulls just detail.reason and discards
    `actor`, which is a reviewer identity and out of the compliance
    record's scope (see get_passport_pdf's provenance-gathering note)."""
    row = conn.execute(
        """
        SELECT detail_json FROM audit_log
        WHERE entity_type = 'credential' AND entity_id = ? AND action = 'revoked'
        ORDER BY created_at DESC LIMIT 1
        """,
        (credential_id,),
    ).fetchone()
    if row is None:
        return None
    return json.loads(row["detail_json"] or "{}").get("reason")


@app.get("/passport/{lookup_key}/pdf")
def get_passport_pdf(lookup_key: str, request: Request, conn=Depends(get_db)):
    credential_id, is_legacy = _resolve_credential_for_lookup(conn, lookup_key)
    result = passport_engine.compile_passport(conn, credential_id)
    audit.record(
        conn, "credential", credential_id, "passport_pdf_exported", actor="unauthenticated",
        detail={"is_legacy": True} if is_legacy else {},
    )
    # Everything below is fetched separately rather than added to
    # compile_passport's return shape — that keeps compile_passport (and
    # the JSON /passport API response built from it) completely
    # untouched by this. No new schema either: issuer identity,
    # issuance/revocation timestamps, and the supersession pointer are
    # all already on existing rows — compile_passport's node dicts just
    # never carried them.
    node_ids = [n["credential_id"] for n in result["nodes"]]

    cred_rows = (
        conn.execute(
            f"SELECT id, issuer_id, issued_at, revoked_at, superseded_by FROM credentials "
            f"WHERE id IN ({','.join('?' * len(node_ids))})",
            node_ids,
        ).fetchall()
        if node_ids
        else []
    )
    credential_provenance = {row["id"]: dict(row) for row in cred_rows}

    issuer_ids = {row["issuer_id"] for row in cred_rows}
    issuer_rows = (
        conn.execute(
            f"SELECT id, name, iac, enterprise_id FROM issuers WHERE id IN ({','.join('?' * len(issuer_ids))})",
            list(issuer_ids),
        ).fetchall()
        if issuer_ids
        else []
    )
    issuers_by_id = {row["id"]: dict(row) for row in issuer_rows}

    for node_id, cred in credential_provenance.items():
        cred["issuer"] = issuers_by_id.get(cred["issuer_id"])
        cred["revocation_reason"] = _revocation_reason(conn, node_id) if cred["revoked_at"] else None

    # uii_bindings lookup extended to also cover any superseded_by ids —
    # a successor credential isn't itself a node in this passport's
    # source graph, but its UII is exactly what a reader needs to find
    # "the current valid version" (see pdf_export's chain-of-custody
    # section).
    lookup_ids = set(node_ids) | {c["superseded_by"] for c in credential_provenance.values() if c["superseded_by"]}
    uii_rows = (
        conn.execute(
            f"SELECT credential_id, uii_code FROM uii_bindings WHERE credential_id IN ({','.join('?' * len(lookup_ids))})",
            list(lookup_ids),
        ).fetchall()
        if lookup_ids
        else []
    )
    uii_codes = {row["credential_id"]: row["uii_code"] for row in uii_rows}
    # Plain, unwrapped credential_id — this is the human-readable link
    # a contracting officer would actually copy/click to look up full
    # audit history, not the enveloped scan payload (which is unreadable
    # control-character text, fine for a Data Matrix, useless in a
    # printed footer).
    passport_url = _passport_url(request, credential_id)
    pdf_bytes = pdf_export.render_passport_pdf(result, uii_codes, credential_provenance, passport_url)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="passport-{credential_id}.pdf"'},
    )


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
