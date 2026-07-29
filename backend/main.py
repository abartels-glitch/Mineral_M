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
import storage
import uii
from db import get_db, init_db
from models import (
    CreateUserRequest,
    CredentialIssueRequest,
    CredentialResponse,
    DocumentDetail,
    DocumentUploadResponse,
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


def _evaluate_sublot_flag(sublot: dict) -> tuple[bool, str | None]:
    """Deterministic sub-lot flagging, reusing passport.py's own banned-
    country list so extraction-time flagging and the compliance engine
    never disagree about what counts as covered."""
    origin = (sublot.get("origin_country") or "").strip()
    if not origin:
        return True, "origin country not stated"
    if origin.lower() in passport_engine.BANNED_ORIGIN_COUNTRIES:
        return True, f"origin country '{origin}' is FEOC-covered"
    if (sublot.get("origin_confidence") or "").lower() == "low":
        return True, "origin confidence marked low"
    return False, None


def _row_to_sublot(row) -> SublotOut:
    return SublotOut(
        id=row["id"],
        sublot_id=row["sublot_id"],
        blend_pct=row["blend_pct"],
        origin_country=row["origin_country"],
        origin_confidence=row["origin_confidence"],
        notes=row["notes"],
        flagged=bool(row["flagged"]),
        flagged_reason=row["flagged_reason"],
    )


def _fetch_sublots(conn, heat_id: str) -> list[SublotOut]:
    rows = conn.execute("SELECT * FROM heat_sublots WHERE heat_id = ? ORDER BY id", (heat_id,)).fetchall()
    return [_row_to_sublot(r) for r in rows]


def _row_to_heat(conn, row) -> HeatOut:
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
        flagged_reason=row["flagged_reason"],
        reviewed=bool(row["reviewed"]),
        reviewed_by=row["reviewed_by"],
        reviewed_at=row["reviewed_at"],
        credential_id=row["credential_id"],
        sublots=_fetch_sublots(conn, row["id"]),
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
        sublot_flags = [_evaluate_sublot_flag(s) for s in sublots]
        heat_flagged = bool(heat.get("flagged_for_review")) or any(f for f, _ in sublot_flags)
        reasons = []
        if heat.get("flagged_for_review") and heat.get("flagged_reason"):
            reasons.append(heat["flagged_reason"])
        reasons.extend(reason for flagged, reason in sublot_flags if flagged and reason)
        heat_flagged_reason = "; ".join(dict.fromkeys(reasons)) or None  # dedupe, preserve order

        heat_row_id = uuid.uuid4().hex
        conn.execute(
            """
            INSERT INTO document_heats (
                id, document_id, heat_id, alloy_composition_json, test_results_json, nonconformance_refs_json,
                segregation_attested, segregation_attested_by, segregation_note, mass_kg, confidence,
                source, extraction_source, flagged_for_review, flagged_reason, reviewed
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
                heat_flagged_reason,
            ),
        )
        for sublot, (flagged, reason) in zip(sublots, sublot_flags, strict=True):
            conn.execute(
                """
                INSERT INTO heat_sublots (id, heat_id, sublot_id, blend_pct, origin_country, origin_confidence, notes, flagged, flagged_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid.uuid4().hex, heat_row_id, sublot.get("sublot_id"), sublot.get("blend_pct"),
                    sublot.get("origin_country"), sublot.get("origin_confidence"), sublot.get("notes"),
                    1 if flagged else 0, reason,
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
    sublot_flags = [_evaluate_sublot_flag(s) for s in sublot_dicts]
    still_flagged = any(f for f, _ in sublot_flags)
    flagged_reason = "; ".join(dict.fromkeys(r for f, r in sublot_flags if f and r)) or None

    reviewed_at = now_iso()
    conn.execute(
        """
        UPDATE document_heats
        SET heat_id = ?, alloy_composition_json = ?, test_results_json = ?, nonconformance_refs_json = ?,
            segregation_attested = ?, segregation_attested_by = ?, segregation_note = ?, mass_kg = ?,
            source = 'human', flagged_for_review = ?, flagged_reason = ?,
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
            flagged_reason,
            current_user["email"],
            reviewed_at,
            heat_id,
        ),
    )
    conn.execute("DELETE FROM heat_sublots WHERE heat_id = ?", (heat_id,))
    for sublot, (flagged, reason) in zip(sublot_dicts, sublot_flags, strict=True):
        conn.execute(
            """
            INSERT INTO heat_sublots (id, heat_id, sublot_id, blend_pct, origin_country, origin_confidence, notes, flagged, flagged_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                uuid.uuid4().hex, heat_id, sublot["sublot_id"], sublot["blend_pct"],
                sublot["origin_country"], sublot["origin_confidence"], sublot["notes"],
                1 if flagged else 0, reason,
            ),
        )
    conn.commit()
    audit.record(conn, "document_heat", heat_id, "reviewed", actor=current_user["email"])

    updated = conn.execute("SELECT * FROM document_heats WHERE id = ?", (heat_id,)).fetchone()
    return _row_to_heat(conn, updated)


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
            raise HTTPException(409, "a credential has already been issued from this heat")
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
            document_id, document_content_hash, payload_hash, signature, superseded_by, revoked_at, issued_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)
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
            payload_hash,
            signature,
            issued_at,
        ),
    )
    if body.heat_id is not None:
        conn.execute("UPDATE document_heats SET credential_id = ? WHERE id = ?", (credential_id, body.heat_id))
    conn.execute(
        "INSERT INTO uii_bindings (id, credential_id, uii_code, created_at) VALUES (?, ?, ?, ?)",
        (uuid.uuid4().hex, credential_id, credential_id, issued_at),
    )
    conn.commit()
    audit.record(conn, "credential", credential_id, "issued", actor=current_user["email"], detail={"credential_type": body.credential_type})

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
        payload_hash=payload_hash,
        signature=signature,
        superseded_by=None,
        revoked_at=None,
        issued_at=issued_at,
    )


def _passport_url(request: Request, credential_id: str) -> str:
    return f"{str(request.base_url).rstrip('/')}/passport.html?id={credential_id}"


@app.get("/credentials/{credential_id}/uii")
def get_uii_binding(credential_id: str, request: Request, conn=Depends(get_db)):
    binding = conn.execute("SELECT * FROM uii_bindings WHERE credential_id = ?", (credential_id,)).fetchone()
    if binding is None:
        raise HTTPException(404, "no UII binding for this credential")
    return {
        "uii_code": binding["uii_code"],
        "credential_id": binding["credential_id"],
        "created_at": binding["created_at"],
        "passport_url": _passport_url(request, credential_id),
        "image_url": f"/credentials/{credential_id}/uii/image",
    }


@app.get("/credentials/{credential_id}/uii/image")
def get_uii_image(credential_id: str, request: Request, conn=Depends(get_db)):
    binding = conn.execute("SELECT * FROM uii_bindings WHERE credential_id = ?", (credential_id,)).fetchone()
    if binding is None:
        raise HTTPException(404, "no UII binding for this credential")
    png_bytes = uii.generate_datamatrix_png(_passport_url(request, credential_id))
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
    heat_out = None
    if credential["document_id"]:
        document_audit_rows = conn.execute(
            "SELECT action, actor, detail_json, created_at FROM audit_log WHERE entity_type = 'document' AND entity_id = ? ORDER BY created_at",
            (credential["document_id"],),
        ).fetchall()
        heat_row = conn.execute("SELECT * FROM document_heats WHERE credential_id = ?", (credential_id,)).fetchone()
        if heat_row is not None:
            heat_out = _row_to_heat(conn, heat_row).model_dump()

    return {
        "credential_id": credential_id,
        "audit_log": [
            {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
            for r in audit_rows
        ],
        "document_audit_log": [
            {"action": r["action"], "actor": r["actor"], "detail": json.loads(r["detail_json"] or "{}"), "created_at": r["created_at"]}
            for r in document_audit_rows
        ],
        "heat": heat_out,
    }


# --- passport (public) ------------------------------------------------------


@app.get("/passport/{credential_id}", response_model=PassportResult)
def get_passport(credential_id: str, conn=Depends(get_db)):
    row = conn.execute("SELECT id FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "credential not found")
    result = passport_engine.compile_passport(conn, credential_id)
    audit.record(conn, "credential", credential_id, "passport_viewed", actor="unauthenticated")
    return PassportResult(**result)


@app.get("/passport/{credential_id}/pdf")
def get_passport_pdf(credential_id: str, conn=Depends(get_db)):
    row = conn.execute("SELECT id FROM credentials WHERE id = ?", (credential_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "credential not found")
    result = passport_engine.compile_passport(conn, credential_id)
    audit.record(conn, "credential", credential_id, "passport_pdf_exported", actor="unauthenticated")
    pdf_bytes = pdf_export.render_passport_pdf(result)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'inline; filename="passport-{credential_id}.pdf"'},
    )


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
