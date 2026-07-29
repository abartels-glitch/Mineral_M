"""Pydantic request/response schemas for the FastAPI routes."""
from typing import Literal, Optional

from pydantic import BaseModel


class ExtractedFieldOut(BaseModel):
    field_name: str
    field_value: Optional[str]
    confidence: float
    source: str
    overridden_by_human: bool


class DocumentUploadResponse(BaseModel):
    id: str
    filename: str
    document_type: str
    status: str
    extracted_fields: list[ExtractedFieldOut]


class DocumentDetail(BaseModel):
    id: str
    filename: str
    document_type: str
    raw_text: str
    status: str
    uploaded_at: str
    reviewed_by: Optional[str]
    reviewed_at: Optional[str]
    extracted_fields: list[ExtractedFieldOut]


class ReviewFieldInput(BaseModel):
    field_name: str
    field_value: Optional[str]


class ReviewRequest(BaseModel):
    fields: list[ReviewFieldInput]


class CredentialIssueRequest(BaseModel):
    credential_type: str
    subject: dict
    document_id: Optional[str] = None
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
