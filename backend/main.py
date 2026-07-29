"""FastAPI app: upload -> extract -> review -> issue credential -> compile passport.

Serves the no-build-step frontend/ directory as static files alongside the
API (spec section 1). Auth: server-side session cookie, three roles
(org_user, buyer_auditor, platform_admin) — see auth.py and README.
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
    ExtractedFieldOut,
    LoginRequest,
    PassportResult,
    ReviewRequest,
    UserOut,
)

load_dotenv()

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

init_db()
app = FastAPI(title="FEOC Compliance Passport (MVP)")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_extracted_field(row) -> ExtractedFieldOut:
    return ExtractedFieldOut(
        field_name=row["field_name"],
        field_value=row["field_value"],
        confidence=row["confidence"],
        source=row["source"],
        overridden_by_human=bool(row["overridden_by_human"]),
    )


def _fetch_extracted_fields(conn, document_id: str) -> list[ExtractedFieldOut]:
    rows = conn.execute(
        "SELECT * FROM extracted_fields WHERE document_id = ? ORDER BY field_name", (document_id,)
    ).fetchall()
    return [_row_to_extracted_field(r) for r in rows]


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
    """How often a human corrected an auto-extracted field — the signal
    for when it's safe to loosen the mandatory-review gate later (spec
    section 4.1)."""
    auth.require_role(current_user, "platform_admin")

    def _rate(total: int, overridden: int) -> float | None:
        return round(overridden / total, 4) if total else None

    overall_rows = conn.execute(
        """
        SELECT extraction_source, COUNT(*) AS total, SUM(overridden_by_human) AS overridden
        FROM extracted_fields WHERE extraction_source IN ('llm', 'regex') GROUP BY extraction_source
        """
    ).fetchall()
    by_field_rows = conn.execute(
        """
        SELECT field_name, extraction_source, COUNT(*) AS total, SUM(overridden_by_human) AS overridden
        FROM extracted_fields WHERE extraction_source IN ('llm', 'regex') GROUP BY field_name, extraction_source
        """
    ).fetchall()
    return {
        "overall": [
            {"extraction_source": r["extraction_source"], "total": r["total"], "overridden": r["overridden"], "override_rate": _rate(r["total"], r["overridden"])}
            for r in overall_rows
        ],
        "by_field": [
            {
                "field_name": r["field_name"],
                "extraction_source": r["extraction_source"],
                "total": r["total"],
                "overridden": r["overridden"],
                "override_rate": _rate(r["total"], r["overridden"]),
            }
            for r in by_field_rows
        ],
    }


# --- documents ------------------------------------------------------------


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

    uploaded_at = now_iso()
    conn.execute(
        """
        INSERT INTO documents (id, org_id, filename, document_type, object_key, content_hash, raw_text, status, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'extracted', ?)
        """,
        (document_id, current_user["org_id"], file.filename, document_type, object_key, content_hash, raw_text, uploaded_at),
    )
    audit.record(conn, "document", document_id, "uploaded", actor=current_user["email"], detail={"filename": file.filename, "content_hash": content_hash})

    for field in llm_extractor.extract_fields(raw_text):
        conn.execute(
            """
            INSERT INTO extracted_fields (id, document_id, field_name, field_value, confidence, source, extraction_source, overridden_by_human)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (uuid.uuid4().hex, document_id, field["field_name"], field["field_value"], field["confidence"], field["source"], field["source"]),
        )
    conn.commit()
    audit.record(conn, "document", document_id, "extracted", actor="system")

    return DocumentUploadResponse(
        id=document_id,
        filename=file.filename,
        document_type=document_type,
        status="extracted",
        extracted_fields=_fetch_extracted_fields(conn, document_id),
    )


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
            reviewed_by=r["reviewed_by"],
            reviewed_at=r["reviewed_at"],
            extracted_fields=_fetch_extracted_fields(conn, r["id"]),
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
        reviewed_by=row["reviewed_by"],
        reviewed_at=row["reviewed_at"],
        extracted_fields=_fetch_extracted_fields(conn, document_id),
    )


@app.post("/documents/{document_id}/review", response_model=DocumentDetail)
def review_document(
    document_id: str, body: ReviewRequest, current_user: dict = Depends(auth.get_current_user), conn=Depends(get_db)
):
    auth.require_role(current_user, "org_user")
    row = conn.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
    if row is None:
        raise HTTPException(404, "document not found")
    auth.require_org_match(current_user, row["org_id"])
    if row["status"] == "reviewed":
        raise HTTPException(409, "document already reviewed; a new review cycle is required to change it")

    for field in body.fields:
        existing = conn.execute(
            "SELECT * FROM extracted_fields WHERE document_id = ? AND field_name = ?",
            (document_id, field.field_name),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO extracted_fields (id, document_id, field_name, field_value, confidence, source, extraction_source, overridden_by_human)
                VALUES (?, ?, ?, ?, 1.0, 'human', 'human', 1)
                """,
                (uuid.uuid4().hex, document_id, field.field_name, field.field_value),
            )
        else:
            overridden = existing["extraction_source"] in ("regex", "llm") and existing["field_value"] != field.field_value
            conn.execute(
                """
                UPDATE extracted_fields
                SET field_value = ?, source = 'human', overridden_by_human = ?
                WHERE id = ?
                """,
                (field.field_value, 1 if overridden else existing["overridden_by_human"], existing["id"]),
            )

    reviewed_at = now_iso()
    conn.execute(
        "UPDATE documents SET status = 'reviewed', reviewed_by = ?, reviewed_at = ? WHERE id = ?",
        (current_user["email"], reviewed_at, document_id),
    )
    conn.commit()
    audit.record(conn, "document", document_id, "reviewed", actor=current_user["email"])

    return get_document(document_id, current_user, conn)


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

    document_content_hash = None
    if body.document_id is not None:
        doc = conn.execute("SELECT * FROM documents WHERE id = ?", (body.document_id,)).fetchone()
        if doc is None:
            raise HTTPException(404, "document not found")
        if doc["org_id"] != issuer_id:
            raise HTTPException(403, "document belongs to a different organization")
        if doc["status"] != "reviewed":
            raise HTTPException(400, "document must be reviewed before a credential can be issued from it")
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
        document_id=body.document_id,
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
            body.document_id,
            document_content_hash,
            payload_hash,
            signature,
            issued_at,
        ),
    )
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
        document_id=body.document_id,
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
