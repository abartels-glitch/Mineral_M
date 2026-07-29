"""Structured review-flag model shared by extraction (llm_extractor.py)
and the deterministic compliance checks in main.py, so both layers
speak one shape instead of a flat human-written reason string.

Two sources produce flags, and every flag downstream carries which one:
  - "extraction": the LLM's (or regex fallback's) own read of the
    document — it noticed something ambiguous, inconsistent, or
    otherwise worth a human's attention while structuring the text.
  - "compliance_engine": a deterministic rule this codebase applies
    itself (the FEOC banned-country check, a missing/low-confidence
    origin) — same rule fires the same way regardless of what the LLM
    thought, so extraction-time flagging and the compliance engine
    never disagree about what counts as covered.

Severity is derived from issue_type, not set by callers: only a
compliance_violation is `blocking` (a real, deterministic policy hit),
everything else is `needs_review` (worth a human's eyes, not a known
verdict).
"""
from typing import Literal, Optional

from pydantic import BaseModel

IssueType = Literal[
    "missing_field",
    "ambiguous_field",
    "inconsistent_data",
    "compliance_violation",
    "low_confidence_extraction",
]
Source = Literal["extraction", "compliance_engine"]
Severity = Literal["blocking", "needs_review"]

ISSUE_TYPES: tuple[str, ...] = (
    "missing_field",
    "ambiguous_field",
    "inconsistent_data",
    "compliance_violation",
    "low_confidence_extraction",
)

# Ordering for UI/display sort — blocking first.
SEVERITY_ORDER = {"blocking": 0, "needs_review": 1}

_BLOCKING_ISSUE_TYPES = {"compliance_violation"}


class Flag(BaseModel):
    issue_type: IssueType
    field_name: Optional[str] = None
    severity: Severity
    human_readable_reason: str
    source: Source


def severity_for(issue_type: str) -> Severity:
    return "blocking" if issue_type in _BLOCKING_ISSUE_TYPES else "needs_review"


def make_flag(
    issue_type: str,
    human_readable_reason: str,
    source: Source,
    field_name: Optional[str] = None,
) -> Flag:
    return Flag(
        issue_type=issue_type,
        field_name=field_name,
        severity=severity_for(issue_type),
        human_readable_reason=human_readable_reason,
        source=source,
    )
