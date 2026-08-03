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

Severity is derived from issue_type, not set by callers: `blocking` is
for compliance_violation (a real, deterministic policy hit) and
extraction_unavailable (the AI extraction pipeline genuinely failed —
not merely low confidence, essentially no real read of the document
happened, so it deserves the same "can't skip past this" weight as a
known policy violation, not the routine needs_review scalar of an
ordinary hedged/ambiguous field). Everything else is `needs_review`
(worth a human's eyes, not a known verdict).

A flag also carries a resolution `status`. Once a human corrects the
field a flag concerns (main.py's field-correction endpoint), the flag
is marked `resolved` in place — it is never removed from the list,
since "this was flagged and a human then fixed it" is itself
compliance history worth keeping. New flags default to `open`;
`resolved_by`/`resolved_at` stay null until resolution.

A compliance_engine flag also carries `sublot_id` — which physical
sub-lot row (heat_sublots.id) it's about. document_heats.flags_json
holds a flattened copy of every sub-lot's flags alongside the heat's
own (see main.py's upload_document), and without a sub-lot id two
sub-lots on the same heat with the identical issue (e.g. both missing
an origin) would be indistinguishable there — correcting one sub-lot
could otherwise resolve the wrong copy. Extraction-sourced flags stay
heat-scoped (`sublot_id=None`): the LLM's flag schema was never asked
to name a specific sub-lot, and sub-lot rows don't have ids yet at the
point extraction runs.
"""
from typing import Literal, Optional

from pydantic import BaseModel

IssueType = Literal[
    "missing_field",
    "ambiguous_field",
    "inconsistent_data",
    "compliance_violation",
    "low_confidence_extraction",
    "extraction_unavailable",
]
Source = Literal["extraction", "compliance_engine"]
Severity = Literal["blocking", "needs_review"]
FlagStatus = Literal["open", "resolved"]

ISSUE_TYPES: tuple[str, ...] = (
    "missing_field",
    "ambiguous_field",
    "inconsistent_data",
    "compliance_violation",
    "low_confidence_extraction",
    "extraction_unavailable",
)

# Ordering for UI/display sort — blocking first.
SEVERITY_ORDER = {"blocking": 0, "needs_review": 1}

_BLOCKING_ISSUE_TYPES = {"compliance_violation", "extraction_unavailable"}


class Flag(BaseModel):
    issue_type: IssueType
    field_name: Optional[str] = None
    severity: Severity
    human_readable_reason: str
    source: Source
    status: FlagStatus = "open"
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None
    sublot_id: Optional[str] = None


def severity_for(issue_type: str) -> Severity:
    return "blocking" if issue_type in _BLOCKING_ISSUE_TYPES else "needs_review"


def make_flag(
    issue_type: str,
    human_readable_reason: str,
    source: Source,
    field_name: Optional[str] = None,
    sublot_id: Optional[str] = None,
) -> Flag:
    return Flag(
        issue_type=issue_type,
        field_name=field_name,
        severity=severity_for(issue_type),
        human_readable_reason=human_readable_reason,
        source=source,
        sublot_id=sublot_id,
    )
