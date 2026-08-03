"""Pydantic request/response schemas for the FastAPI routes."""
from typing import Literal, Optional

from pydantic import BaseModel

from review_flags import Flag


class SublotOut(BaseModel):
    id: str
    sublot_id: Optional[str]
    blend_pct: Optional[float]
    origin_country: Optional[str]
    origin_confidence: Optional[str]
    notes: Optional[str]
    flagged: bool
    flags: list[Flag]


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
    flags: list[Flag]
    reviewed: bool
    reviewed_by: Optional[str]
    reviewed_at: Optional[str]
    credential_id: Optional[str]
    sublots: list[SublotOut]
    # Derived, not stored: true iff no flag (this heat's own, or any of its
    # sub-lots') is still open. Distinct from `reviewed` — that only means
    # the one-shot review form was submitted once, which can happen while
    # a blocking flag is still outstanding. The review-queue badge uses
    # this (combined with `reviewed`) rather than `reviewed` alone.
    fully_addressed: bool


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
    # `id` is the heat_sublots row id (SublotOut.id) — optional and
    # separate from `sublot_id` (a human-readable business label like
    # "Sub-lot A1"). When a caller round-trips an id it already has (from
    # a prior GET), review_heat updates that row in place instead of
    # dropping and recreating it, so a sub-lot's row id stays stable
    # across a /review submission. Omit it (or leave it unmatched) for a
    # genuinely new sub-lot — existing callers that don't know about this
    # field are unaffected, they just don't get the stability.
    id: Optional[str] = None
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


class FieldCorrectionRequest(BaseModel):
    """One field, corrected in place — deliberately not the full-replace
    shape HeatReviewRequest uses. A reviewer fixing a single flagged
    field shouldn't have to resubmit everything else on the heat, and
    (unlike HeatReviewRequest) this is allowed to run more than once and
    after the heat is otherwise locked, since a correction is its own
    audited event rather than a re-review."""

    target: Literal["heat", "sublot"]
    sublot_id: Optional[str] = None
    field_name: str
    # str for every scalar-correctable field (heat_id, mass_kg, the
    # sub-lot fields); dict for alloy_composition/test_results, whose
    # correction is a full-value replace of the structured field, not a
    # single string.
    corrected_value: Optional[str | dict] = None


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
    heat_id: Optional[str]
    payload_hash: str
    signature: str
    superseded_by: Optional[str]
    revoked_at: Optional[str]
    issued_at: str


# "revoked" is a distinct outcome from "fail" — a fail means a check ran
# and found a real problem (banned origin, bad signature); revoked means
# the credential itself was retracted (its source data changed after
# signing) and, if reissued, a successor exists. Collapsing that into a
# generic fail would read identically to an actual compliance violation.
NodeStatus = Literal["pass", "fail", "insufficient_data", "revoked"]


class PassportNodeResult(BaseModel):
    credential_id: str
    credential_type: str
    material_type: Optional[str]
    origin_country: Optional[str]
    node_status: NodeStatus
    reasons: list[str]


class PassportResult(BaseModel):
    credential_id: str
    verdict: NodeStatus
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
