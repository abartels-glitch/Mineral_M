"""LLM structuring pass — the second step of the OCR-then-LLM pipeline.

Takes the raw text `ocr.py` pulled out of a document and asks Claude to
structure it into a per-heat schema: a certificate of conformance / MTR
can cover one heat (the common case) or several (a consolidated
multi-heat certificate), each with its own alloy composition, test
results, and a table of blended feedstock sub-lots with their own
origin/confidence. Uses forced tool use for reliable structured output.

Falls back to the regex extractor whenever `ANTHROPIC_API_KEY` is unset
or the API call fails — uploads should never break because an external
API had a bad moment, and this keeps the test suite offline and free.
The fallback can only ever produce one heat with no composition/sub-lot
data — it's wrapped as explicitly flagged for review, not silently
passed off as a clean extraction.

Failure taxonomy (see _classify_failure): every genuine API-failure
fallback (not the benign "no key configured" case) is classified into
exactly one of "transient" (rate limit, 5xx/529, timeout, connection —
the anthropic SDK's own client already retries these internally, so
seeing one here at all means its retry budget is already exhausted),
"permanent" (auth, bad request, not found, request-too-large,
unprocessable-entity — the SDK correctly never retries these itself,
since retrying an invalid request or a revoked key can't ever succeed),
or "malformed" (the API responded, but the response couldn't be turned
into usable structured data — retried once here, immediately, no
backoff, since model output isn't perfectly deterministic). Whichever
one it is, the resulting heat is flagged `extraction_unavailable`
(blocking severity — this is not the same thing as an ordinary
low-confidence read; essentially no real extraction happened) rather
than silently reading as a routine lower-confidence result, and the
caller (main.py's upload_document) records the category in the
document's audit trail so "how many documents were degraded by
permanent-config failures this week" is a direct query, not a
log-grep exercise.
"""
import logging
import os

import anthropic

import extractor
import org_config
import review_flags

logger = logging.getLogger(__name__)

# A second attempt is only ever taken for a "malformed" classification
# (see _classify_failure) -- a transient failure already exhausted the
# SDK's own internal retry budget by the time we see it, and retrying a
# permanent failure (bad key, bad request) can't ever succeed.
MAX_MALFORMED_RESPONSE_ATTEMPTS = 2


class MalformedResponseError(Exception):
    """The API responded successfully (a real 200), but its content
    couldn't be turned into usable structured data -- no tool_use block,
    or the tool_use input didn't match what upload_document expects.
    Distinct from every anthropic.APIError subclass: those all mean the
    request itself failed at the transport/API level; this means it
    succeeded and our own parsing is what failed."""

MODEL = "claude-haiku-4-5-20251001"

# Haiku 4.5 first-party API pricing, per million tokens.
INPUT_COST_PER_MTOK = 1.00
OUTPUT_COST_PER_MTOK = 5.00

BANNED_ORIGIN_COUNTRIES_HINT = "China, Russia, Iran, North Korea"

SUBLOT_SCHEMA = {
    "type": "object",
    "properties": {
        "sublot_id": {"type": ["string", "null"]},
        "blend_pct": {"type": ["number", "null"], "description": "Percent of this heat this sub-lot contributes, 0-100."},
        "origin_country": {"type": ["string", "null"]},
        "origin_confidence": {
            "type": ["string", "null"],
            "enum": ["high", "low", None],
            "description": (
                "How clearly and unambiguously the TEXT states this origin — not whether the origin "
                "itself is desirable or compliant. 'high' if the text plainly states the origin, "
                "regardless of which country it names. 'low' only if the text is hedged ('unconfirmed', "
                "'pending documentation', 'possibly'), contradictory, or the origin is genuinely absent/unverified."
            ),
        },
        "notes": {"type": ["string", "null"]},
    },
    "required": ["sublot_id", "blend_pct", "origin_country", "origin_confidence", "notes"],
}

FLAG_SCHEMA = {
    "type": "object",
    "properties": {
        "issue_type": {
            "type": "string",
            "enum": list(review_flags.ISSUE_TYPES),
            "description": (
                "missing_field: a value the certificate should have isn't present. "
                "ambiguous_field: text is present but hedged/unclear. "
                "inconsistent_data: two stated values contradict each other. "
                "compliance_violation: a covered country appears as an origin. "
                "low_confidence_extraction: an origin is unconfirmed or its confidence is low."
            ),
        },
        "field_name": {
            "type": ["string", "null"],
            "description": "The specific field this issue concerns, e.g. 'heat_id', 'origin_country'. Null if not about one specific field.",
        },
        "human_readable_reason": {"type": "string", "description": "Plain-language explanation for a human reviewer."},
    },
    "required": ["issue_type", "field_name", "human_readable_reason"],
}

def _build_heat_schema(heat_id_label_hint: str) -> dict:
    """heat_id's `description` is the one part of this schema that's
    genuinely org-specific (which label variants a given design partner's
    certificates actually use) rather than a fixed property of the
    "certificate of conformance / MTR" document type itself — see
    org_config.py's module docstring for why every other field name/shape
    here stays fixed Python code instead of also moving to org config."""
    return {
        "type": "object",
        "properties": {
            "heat_id": {
                "type": ["string", "null"],
                "description": heat_id_label_hint,
            },
            "alloy_composition": {
                "type": ["object", "null"],
                "additionalProperties": {"type": "number"},
                "description": 'Element symbol -> weight percent, e.g. {"Nd": 29.5, "Fe": 68.2, "B": 1.0}. Null if not present in the text.',
            },
            "test_results": {
                "type": ["object", "null"],
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "value": {"type": ["string", "number", "null"]},
                        "result": {"type": ["string", "null"], "enum": ["pass", "fail", "marginal", None]},
                    },
                    "required": ["value", "result"],
                },
                "description": "Test name -> {value, result}. Null if not present.",
            },
            "nonconformance_refs": {"type": "array", "items": {"type": "string"}},
            "feedstock_sublots": {"type": "array", "items": SUBLOT_SCHEMA},
            "segregation_attested": {"type": "boolean"},
            "segregation_note": {"type": ["string", "null"]},
            "mass_kg": {"type": ["number", "null"]},
            "confidence": {
                "type": "number",
                "description": (
                    "0.0-1.0 confidence that this heat's fields were read correctly from clear text — "
                    "NOT a judgment of whether the extracted facts are compliant or convenient. A heat "
                    "with a plainly-stated covered-country origin should score just as high as one with "
                    "a plainly-stated domestic origin. Only lower this for genuine textual ambiguity: "
                    "hedged language, contradictions, or missing data."
                ),
            },
            "flags": {
                "type": "array",
                "items": FLAG_SCHEMA,
                "description": (
                    "One entry per distinct issue you notice in this heat's data: a missing field, "
                    "hedged/ambiguous text, internally inconsistent values, a covered country "
                    f"({BANNED_ORIGIN_COUNTRIES_HINT}) appearing as an origin anywhere in the sub-lot "
                    "table, or a sub-lot with unconfirmed/low-confidence origin data. Empty array if "
                    "the heat's data is clean. Don't fold multiple distinct issues into one entry, and "
                    "don't let a compliance-sensitive fact (e.g. a covered-country origin) change how "
                    "confident you are in the data — that's a separate signal, tracked here, not in "
                    "`confidence`."
                ),
            },
        },
        "required": [
            "heat_id",
            "alloy_composition",
            "test_results",
            "nonconformance_refs",
            "feedstock_sublots",
            "segregation_attested",
            "segregation_note",
            "mass_kg",
            "confidence",
            "flags",
        ],
    }


def _build_tool(org_cfg: dict) -> dict:
    return {
        "name": "record_mtr_extraction",
        "description": (
            "Record structured data extracted from a certificate of conformance / mill test report, "
            "which may cover one heat or several (a consolidated multi-heat certificate)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "certificate_id": {"type": ["string", "null"]},
                "supplier_id": {"type": ["string", "null"]},
                "signatures": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": ["string", "null"]},
                            "title": {"type": ["string", "null"]},
                            "org": {"type": ["string", "null"]},
                            "role": {"type": ["string", "null"], "enum": ["issuer", "witness", None]},
                        },
                        "required": ["name", "title", "org", "role"],
                    },
                },
                "heats": {
                    "type": "array",
                    "items": _build_heat_schema(org_cfg["heat_id_label_hint"]),
                    "minItems": 1,
                },
            },
            "required": ["certificate_id", "supplier_id", "signatures", "heats"],
        },
    }

SYSTEM_PROMPT = (
    "You extract structured data from a certificate of conformance / mill test report (MTR) "
    "for metal/alloy materials. A certificate may cover one heat/melt or several. Only use "
    "information explicitly present in the provided text — never guess or infer a value that "
    "isn't stated; use null for anything not present, don't fabricate a plausible-looking value.\n\n"
    "Confidence (both the per-heat `confidence` field and each sub-lot's `origin_confidence`) "
    "measures ONLY how clearly and unambiguously the text states a fact — never how compliant, "
    "convenient, or comfortable that fact is. A sub-lot stating 'Country of Origin: China' in "
    "plain, direct language is HIGH confidence, exactly like one stating 'Country of Origin: "
    "United States' plainly — the country named is irrelevant to the confidence score. Confidence "
    "should only drop when the text itself is genuinely ambiguous, hedged ('unconfirmed', "
    "'pending documentation', 'possibly'), contradictory, or absent. Do not let a compliance-"
    "sensitive answer lower your confidence in what the text plainly says.\n\n"
    "Record every distinct issue you notice as its own entry in `flags`, classified by the "
    f"closest issue_type: a covered country ({BANNED_ORIGIN_COUNTRIES_HINT}) appearing anywhere in "
    "the sub-lot table is compliance_violation; an unconfirmed or low-confidence origin is "
    "low_confidence_extraction; a value that should be present but isn't is missing_field; "
    "internally contradictory values are inconsistent_data; anything else hedged or unclear is "
    "ambiguous_field. Flagging is separate from confidence: a plainly-stated covered-country "
    "origin is both HIGH confidence and a compliance_violation flag at the same time."
)

# Statuses the anthropic SDK's own internal retry logic already retries
# (its _should_retry: 408/409 timeouts, 429 rate limits, any 5xx) --
# matched here by status code rather than by hardcoding exception class
# names, so this can't silently go stale if Anthropic adds a new status
# code or a new named subclass for one that's currently generic. Seeing
# one of these at all means the SDK's own retry budget is already
# exhausted for this request.
_TRANSIENT_STATUS_CODES_MIN = 500


def _is_transient_status_error(exc: "anthropic.APIStatusError") -> bool:
    return exc.status_code in (408, 409, 429) or exc.status_code >= _TRANSIENT_STATUS_CODES_MIN


def _classify_failure(exc: Exception) -> str:
    """One of "transient", "permanent", "malformed" — see the module
    docstring's failure-taxonomy note. Anything neither an
    APIConnectionError nor an APIStatusError (including a totally
    unanticipated exception type) defaults to "malformed": a single
    extra attempt is cheap insurance, and assuming "permanent" for an
    error this code doesn't recognize would be the wrong default —
    "permanent" specifically means "retrying this exact request is
    known to be futile," which isn't a safe assumption for the unknown."""
    if isinstance(exc, anthropic.APIConnectionError):  # covers APITimeoutError, a subclass
        return "transient"
    if isinstance(exc, anthropic.APIStatusError):
        return "transient" if _is_transient_status_error(exc) else "permanent"
    return "malformed"


def _call_llm(raw_text: str, org_cfg: dict) -> dict:
    # max_retries/timeout made explicit rather than relying on the SDK's
    # defaults unstated — both already matched the SDK's own defaults at
    # the time this was written, but pinning them here is a deliberate,
    # documented choice rather than an accident of whatever the SDK
    # happens to default to on a future version bump.
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"], max_retries=2, timeout=60.0)
    tool = _build_tool(org_cfg)
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[tool],
        tool_choice={"type": "tool", "name": tool["name"]},
        messages=[{"role": "user", "content": raw_text}],
    )
    usage = response.usage
    cost = (
        usage.input_tokens * INPUT_COST_PER_MTOK
        + usage.output_tokens * OUTPUT_COST_PER_MTOK
    ) / 1_000_000
    logger.info(
        "llm_extractor call: model=%s input_tokens=%d output_tokens=%d cost=$%.5f",
        MODEL, usage.input_tokens, usage.output_tokens, cost,
    )
    for block in response.content:
        if block.type == "tool_use":
            return block.input
    raise MalformedResponseError("model response had no tool_use block")


def _regex_fallback(raw_text: str, failure: dict | None = None) -> dict:
    flat = {f["field_name"]: f["field_value"] for f in extractor.extract_fields(raw_text)}

    sublots = []
    if flat.get("origin_country"):
        sublots.append(
            {
                "sublot_id": None,
                "blend_pct": 100.0,
                "origin_country": flat["origin_country"],
                "origin_confidence": "low",  # regex can't cross-check this claim
                "notes": "regex fallback — origin taken at face value from document text, not cross-checked",
            }
        )

    mass_kg = None
    if flat.get("mass_kg"):
        try:
            mass_kg = float(flat["mass_kg"])
        except ValueError:
            mass_kg = None

    if failure is None:
        # Benign: no API key configured at all (expected in dev/test),
        # not a failed attempt -- stays exactly as before this change.
        flag = review_flags.make_flag(
            "low_confidence_extraction",
            "regex fallback — composition and sub-lot data not parsed, needs full manual review",
            source="extraction",
        )
    else:
        category = failure["category"]
        if category == "transient":
            reason = (
                "AI extraction failed after repeated attempts — the extraction service was "
                "temporarily unavailable. Regex fallback used; composition and sub-lot data not "
                "parsed, needs full manual review."
            )
        elif category == "permanent":
            reason = (
                "AI extraction failed due to a configuration or request problem, not a temporary "
                "outage — this likely affects every future extraction until it's fixed. Regex "
                "fallback used; composition and sub-lot data not parsed, needs full manual review."
            )
        else:
            reason = (
                "AI extraction returned an unusable response — regex fallback used; composition "
                "and sub-lot data not parsed, needs full manual review."
            )
        flag = review_flags.make_flag("extraction_unavailable", reason, source="extraction")

    heat = {
        "heat_id": flat.get("heat_number"),
        "alloy_composition": None,
        "test_results": None,
        "nonconformance_refs": [],
        "feedstock_sublots": sublots,
        "segregation_attested": False,
        "segregation_note": None,
        "mass_kg": mass_kg,
        "confidence": 0.5 if flat.get("heat_number") else 0.0,
        "flags": [flag.model_dump()],
        "source": "regex",
    }
    result = {
        "certificate_id": None,
        "supplier_id": flat.get("supplier_name"),
        "signatures": [],
        "heats": [heat],
    }
    if failure is not None:
        # Consumed by main.py's upload_document to write a durable,
        # queryable audit_log entry -- category is the clean, closed-enum
        # field to filter on; exception_class/message ride along for
        # diagnostics only, not meant to be cross-referenced by hand.
        result["extraction_failure"] = failure
    return result


def extract_structured(raw_text: str, org_cfg: dict | None = None) -> dict:
    """Returns {certificate_id, supplier_id, signatures, heats: [...]} —
    each heat dict carries a `source` key ('llm' on a successful model
    call, 'regex' when it fell back) so callers can record which path
    actually produced it, and a `flags` list of structured review_flags.Flag
    dicts (source='extraction') built from the model's raw issue_type/
    field_name/human_readable_reason entries — severity is derived here,
    not trusted to the model, so it's always consistent with issue_type.

    org_cfg is the per-org config dict from org_config.py (its
    heat_id_label_hint drives the one org-specific piece of the extraction
    schema — see _build_heat_schema). Defaults to org_config.DEFAULT_CONFIG
    when omitted, so every existing caller/test that predates per-org config
    keeps behaving exactly as before.

    A genuine API failure (as opposed to no key being configured at all)
    additionally carries a top-level `extraction_failure` key — see
    _regex_fallback and the module docstring's failure taxonomy."""
    if org_cfg is None:
        org_cfg = org_config.DEFAULT_CONFIG
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return _regex_fallback(raw_text)

    last_exc: Exception | None = None
    category = "malformed"
    for attempt in range(MAX_MALFORMED_RESPONSE_ATTEMPTS):
        try:
            result = _call_llm(raw_text, org_cfg)
            for heat in result["heats"]:
                heat["source"] = "llm"
                raw_flags = heat.pop("flags", []) or []
                heat["flags"] = [
                    review_flags.make_flag(
                        issue_type=f["issue_type"],
                        human_readable_reason=f["human_readable_reason"],
                        source="extraction",
                        field_name=f.get("field_name"),
                    ).model_dump()
                    for f in raw_flags
                ]
            return result
        except Exception as exc:  # classified immediately below via _classify_failure, never swallowed unclassified
            last_exc = exc
            category = _classify_failure(exc)
            if category == "malformed" and attempt < MAX_MALFORMED_RESPONSE_ATTEMPTS - 1:
                logger.warning("LLM extraction returned a malformed response (%s), retrying once immediately", exc)
                continue
            break

    logger.warning(
        "LLM extraction failed (%s: %s), category=%s — falling back to regex extractor",
        type(last_exc).__name__, last_exc, category,
    )
    return _regex_fallback(
        raw_text,
        failure={
            "category": category,
            "exception_class": type(last_exc).__name__,
            "exception_message": str(last_exc),
        },
    )
