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


# Field-level correction allowlist: field_name -> (column, python type).
# Deliberately scalar-only — alloy_composition/test_results/nonconformance_refs
# stay on the full-replace review form (HeatReviewRequest); those are
# structured/nested and the LLM's flags never target them by field_name
# anyway (see llm_extractor.FLAG_SCHEMA's field_name description).
_HEAT_CORRECTABLE_FIELDS: dict[str, type] = {"heat_id": str, "mass_kg": float}
_SUBLOT_CORRECTABLE_FIELDS: dict[str, type] = {
    "sublot_id": str,
    "blend_pct": float,
    "origin_country": str,
    "origin_confidence": str,
    "notes": str,
}


def _coerce_corrected_value(raw: Optional[str], field_type: type):
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
    alone rather than re-stamped or re-audited."""
    if heat_credential_id is None:
        return
    credential = conn.execute("SELECT revoked_at FROM credentials WHERE id = ?", (heat_credential_id,)).fetchone()
    if credential is None or credential["revoked_at"]:
        return
    conn.execute("UPDATE credentials SET revoked_at = ? WHERE id = ?", (revoked_at, heat_credential_id))
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

    return _document_upload_response(conn, document_id, file.filename, document_type, structured)


@app.get("/documents", response_model=list[DocumentDetail])
def list_documents(current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    auth.require_role(current_user, "org_user", "platform_admin")
    if current_user["role"] == "platform_admin":
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
def get_document(document_id: str, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    auth.require_role(current_user, "org_user", "platform_admin")
    row = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, row["org_id"])
    return DocumentDetail(
        id=row["id"],
        filename=row["filename"],
        document_type=row["document_type"],
        raw_text=row["raw_text"],
        status=row["status"],
        uploaded_at=row["uploaded_at"],
        certificate_id=row["certificate_id"],
        supplier_id=row["supplier_id"],
        heats=_fetch_heats(conn, document_id),
    )


@app.post("/documents/{document_id}/heats/{heat_id}/review", response_model=HeatOut)
def review_heat(
    document_id: str,
    heat_id: str,
    body: HeatReviewRequest,
    current_user: dict = Depends(auth.get_current_user),
    conn=Depends(get_db),
):
    auth.require_role(current_user, "org_user")
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if doc is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, doc["org_id"])
    heat = conn.execute(
        "SELECT * FROM document_heats WHERE id = ? AND document_id = ?", (heat_id, document_id)
    ).fetchone()
    if heat is None:
        raise HTTPException(404, "heat not found")
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
    # _any_open, not bool(heat_flags): a preserved heat-level flag can be
    # resolved (its status carried over as-is from the row above), so the
    # list being non-empty no longer means there's an open issue — unlike
    # before this fix, when heat_flags only ever held freshly-computed
    # sub-lot flags, which are always open by construction.
    still_flagged = _any_open(heat_flags)

    reviewed_at = now_iso()
    conn.execute(
        """
        UPDATE document_heats
        SET heat_id = ?, alloy_composition_json = ?, test_results_json = ?, nonconformance_refs_json = ?,
            segregation_attested = ?, segregation_attested_by = ?, segregation_note = ?, mass_kg = ?,
            source = 'human', flagged_for_review = ?, flags_json = ?,
            reviewed = 1, reviewed_by = ?, reviewed_at = ?
        WHERE id = ?
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
        ),
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
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if doc is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, doc["org_id"])
    heat = conn.execute(
        "SELECT * FROM document_heats WHERE id = ? AND document_id = ?", (heat_id, document_id)
    ).fetchone()
    if heat is None:
        raise HTTPException(404, "heat not found")

    actor = current_user["email"]
    corrected_at = now_iso()
    sublot_row_id = None

    if body.target == "heat":
        if body.field_name not in _HEAT_CORRECTABLE_FIELDS:
            raise HTTPException(400, f"heat field '{body.field_name}' cannot be corrected here")
        previous_value = heat[body.field_name]
        corrected_value = _coerce_corrected_value(body.corrected_value, _HEAT_CORRECTABLE_FIELDS[body.field_name])

        heat_flags = json.loads(heat["flags_json"])
        _resolve_open_flags_for_field(heat_flags, body.field_name, actor, corrected_at)
        sibling_sublot_rows = conn.execute("SELECT flags_json FROM heat_sublots WHERE heat_id = ?", (heat_id,)).fetchall()
        heat_still_flagged = _any_open(_heat_own_flags(heat_flags)) or any(
            _any_open(json.loads(r["flags_json"])) for r in sibling_sublot_rows
        )

        conn.execute(
            f"""
            UPDATE document_heats
            SET {body.field_name} = ?, source = 'human', flags_json = ?, flagged_for_review = ?
            WHERE id = ?
            """,
            (corrected_value, json.dumps(heat_flags), 1 if heat_still_flagged else 0, heat_id),
        )
    else:
        if body.sublot_id is None:
            raise HTTPException(400, "sublot_id is required when target is 'sublot'")
        if body.field_name not in _SUBLOT_CORRECTABLE_FIELDS:
            raise HTTPException(400, f"sub-lot field '{body.field_name}' cannot be corrected here")
        sublot = conn.execute(
            "SELECT * FROM heat_sublots WHERE id = ? AND heat_id = ?", (body.sublot_id, heat_id)
        ).fetchone()
        if sublot is None:
            raise HTTPException(404, "sub-lot not found")
        previous_value = sublot[body.field_name]
        corrected_value = _coerce_corrected_value(body.corrected_value, _SUBLOT_CORRECTABLE_FIELDS[body.field_name])

        sublot_flags = json.loads(sublot["flags_json"])
        _resolve_open_flags_for_field(sublot_flags, body.field_name, actor, corrected_at)

        # Re-run the same deterministic check extraction/`/review` use,
        # against the corrected value — this is what makes a corrected
        # origin_country pick up (or drop) a compliance_violation flag
        # live, rather than just clearing whatever was flagged before.
        updated_sublot = dict(sublot)
        updated_sublot[body.field_name] = corrected_value
        fresh_flags = _evaluate_sublot_flag(updated_sublot, sublot_id=body.sublot_id)
        _append_fresh_flags(sublot_flags, fresh_flags, match_sublot=False)
        sublot_still_flagged = _any_open(sublot_flags)

        conn.execute(
            f"UPDATE heat_sublots SET {body.field_name} = ?, flags_json = ?, flagged = ? WHERE id = ?",
            (corrected_value, json.dumps(sublot_flags), 1 if sublot_still_flagged else 0, body.sublot_id),
        )

        # document_heats.flags_json holds a flattened copy of this same
        # flag (see upload_document/review_heat) — now that compliance_engine
        # flags carry sublot_id, that copy can be resolved/refreshed
        # precisely, without risking touching a sibling sub-lot's flag of
        # the identical shape. flagged_for_review itself still never
        # trusts this list directly (_heat_own_flags), only the sub-lot
        # rows queried below — this sync is for accurate display only.
        heat_flags = json.loads(heat["flags_json"])
        _resolve_open_sublot_duplicate_flags(heat_flags, body.field_name, body.sublot_id, actor, corrected_at)
        _append_fresh_flags(heat_flags, fresh_flags, match_sublot=True)

        all_sublot_rows = conn.execute("SELECT flags_json FROM heat_sublots WHERE heat_id = ?", (heat_id,)).fetchall()
        heat_still_flagged = _any_open(_heat_own_flags(heat_flags)) or any(
            _any_open(json.loads(r["flags_json"])) for r in all_sublot_rows
        )
        conn.execute(
            "UPDATE document_heats SET source = 'human', flags_json = ?, flagged_for_review = ? WHERE id = ?",
            (json.dumps(heat_flags), 1 if heat_still_flagged else 0, heat_id),
        )
        sublot_row_id = body.sublot_id

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
    conn=Depends(get_db),
):
    """Reviewed/corrected events for one heat, independent of whether a
    credential has been issued from it yet — the review-queue UI shows
    this directly under the heat card, so a reviewer can confirm a
    correction landed without first issuing a credential just to reach
    /credentials/{id}/audit-trail's Timeline."""
    auth.require_role(current_user, "org_user", "platform_admin")
    doc = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if doc is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, doc["org_id"])
    heat = conn.execute(
        "SELECT id FROM document_heats WHERE id = ? AND document_id = ?", (heat_id, document_id)
    ).fetchone()
    if heat is None:
        raise HTTPException(404, "heat not found")
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
    rows = conn.execute("SELECT * FROM credentials ORDER BY issued_at DESC").fetchall()
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
        heat = conn.execute("SELECT * FROM document_heats WHERE id = ?", (body.heat_id,)).fetchone()
        if heat is None:
            raise HTTPException(404, "heat not found")
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (heat["document_id"],)).fetchone()
        if doc["org_id"] != issuer_id:
            raise HTTPException(403, "heat belongs to a different organization")
        if not heat["reviewed"]:
            raise HTTPException(400, "heat must be reviewed before a credential can be issued from it")
        if heat["credential_id"]:
            # A credential already exists for this heat — only an
            # explicit reissue (the existing one revoked, e.g. by a
            # correction landing on this heat after it was signed) is
            # allowed to proceed. This is the deliberate "explicit
            # reissue" step: nothing here reuses the old subject or
            # auto-fills anything — the reviewer fills out this same
            # form again with the corrected data.
            existing = conn.execute(
                "SELECT id, revoked_at FROM credentials WHERE id = ?", (heat["credential_id"],)
            ).fetchone()
            if existing and not existing["revoked_at"]:
                raise HTTPException(409, "a credential has already been issued from this heat")
            supersedes_credential_id = heat["credential_id"]
        document_id = doc["id"]
        document_content_hash = doc["content_hash"]

    for source_id in body.sources:
        parent = conn.execute("SELECT id FROM credentials WHERE id = ?", (source_id,)).fetchone()
        if parent is None:
            raise HTTPException(404, f"source credential {source_id} not found")

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
        conn.execute("UPDATE document_heats SET credential_id = ? WHERE id = ?", (credential_id, body.heat_id))
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
def get_audit_trail(credential_id: str, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)):
    """Everything the public /passport/{id} view doesn't show: who
    reviewed/issued this credential and when, and (if it came from a
    document) the originating heat's extraction/review detail — original
    confidence, whether it was flagged, and its sub-lot table. Login-
    only — the extra depth is what makes buyer_auditor's role
    meaningfully more than the public passport lookup."""
    credential = conn.execute("SELECT * FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if credential is None:
        raise HTTPException(404, "credential not found")
    auth.require_org_match(current_user, credential["issuer_id"])

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
