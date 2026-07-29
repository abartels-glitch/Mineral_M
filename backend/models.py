"""Pydantic request/response schemas for the FastAPI routes."""
from typing import Literal, Optional

from pydantic import BaseModel


class SublotOut(BaseModel):
    id: str
    sublot_id: Optional[str]
    blend_pct: Optional[float]
    origin_country: Optional[str]
    origin_confidence: Optional[str]
    notes: Optional[str]
    flagged: bool
    flagged_reason: Optional[str]


class HeatOut(BaseModel):
    id: str
    document_id: str
    heat_id: Optional[str]
    alloy_composition: Optional[dict]
    test_results: Optional[dict]
    nonconformance_refs: list[str]
    segregation_attested: bool
    segregation_attested_by: Optional[str]
    segregation_note: Optional[str]
    mass_kg: Optional[float]
    confidence: Optional[float]
    source: str
    extraction_source: str
    flagged_for_review: bool
    flagged_reason: Optional[str]
    reviewed: bool
    reviewed_by: Optional[str]
    reviewed_at: Optional[str]
    credential_id: Optional[str]
    sublots: list[SublotOut]


class DocumentUploadResponse(BaseModel):
    id: str
    filename: str
    document_type: str
    status: str
    certificate_id: Optional[str]
    supplier_id: Optional[str]
    heats: list[HeatOut]


class DocumentDetail(BaseModel):
    id: str
    filename: str
    document_type: str
    raw_text: str
    status: str
    uploaded_at: str
    certificate_id: Optional[str]
    supplier_id: Optional[str]
    heats: list[HeatOut]


class SublotInput(BaseModel):
    sublot_id: Optional[str] = None
    blend_pct: Optional[float] = None
    origin_country: Optional[str] = None
    origin_confidence: Optional[str] = None
    notes: Optional[str] = None


class HeatReviewRequest(BaseModel):
    """Full replace, not a patch — mirrors how the old flat field review
    worked (resubmit the complete set), simpler than diffing individual
    sub-lot rows for an MVP reviewer UI."""

    heat_id: Optional[str] = None
    alloy_composition: Optional[dict] = None
    test_results: Optional[dict] = None
    nonconformance_refs: list[str] = []
    segregation_attested: bool = False
    segregation_attested_by: Optional[str] = None
    segregation_note: Optional[str] = None
    mass_kg: Optional[float] = None
    sublots: list[SublotInput] = []


class CredentialIssueRequest(BaseModel):
    credential_type: str
    subject: dict
    heat_id: Optional[str] = None
    sources: list[str] = []
    segregation_attested: bool = False
    segregation_attested_by: Optional[str] = None
    segregation_note: Optional[str] = None


class CredentialResponse(BaseModel):
    id: str
    issuer_id: str
    credential_type: str
    subject: dict
    sources: list[str]
    segregation_attested: bool
    segregation_attested_by: Optional[str]
    segregation_note: Optional[str]
    document_id: Optional[str]
    document_content_hash: Optional[str]
    payload_hash: str
    signature: str
    superseded_by: Optional[str]
    revoked_at: Optional[str]
    issued_at: str


class PassportNodeResult(BaseModel):
    credential_id: str
    credential_type: str
    material_type: Optional[str]
    origin_country: Optional[str]
    node_status: Literal["pass", "fail", "insufficient_data"]
    reasons: list[str]


class PassportResult(BaseModel):
    credential_id: str
    verdict: Literal["pass", "fail", "insufficient_data"]
    reasons: list[str]
    nodes: list[PassportNodeResult]


class LoginRequest(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: str
    org_id: Optional[str]
    org_name: Optional[str]
    email: str
    role: Literal["org_user", "buyer_auditor", "platform_admin"]


class CreateUserRequest(BaseModel):
    email: str
    password: str
    role: Literal["org_user", "buyer_auditor", "platform_admin"]
    org_id: Optional[str] = None
