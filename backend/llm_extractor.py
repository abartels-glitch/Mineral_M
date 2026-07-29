"""LLM structuring pass — the second step of the OCR-then-LLM pipeline.

Takes the raw text `ocr.py` pulled out of a document and asks Claude to
structure it into a per-heat schema: a certificate of conformance / MTR
can cover one heat (the common case) or several (a consolidated
multi-heat certificate), each with its own alloy composition, test
results, and a table of blended feedstock sub-lots with their own
origin/confidence. Uses forced tool use for reliable structured output.

Falls back to the regex extractor whenever `ANTHROPIC_API_KEY` is unset
or the API call fails for any reason (network, auth, rate limit,
malformed response) — uploads should never break because an external
API had a bad moment, and this keeps the test suite offline and free.
The fallback can only ever produce one heat with no composition/sub-lot
data — it's wrapped as explicitly flagged for review, not silently
passed off as a clean extraction.
"""
import logging
import os

import anthropic

import extractor

logger = logging.getLogger(__name__)

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

HEAT_SCHEMA = {
    "type": "object",
    "properties": {
        "heat_id": {
            "type": ["string", "null"],
            "description": "Normalize label variants: 'Heat No.', 'Melt Ref.', etc. all mean the same thing.",
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
        "flagged_for_review": {
            "type": "boolean",
            "description": (
                f"true if any sub-lot origin is unconfirmed/low-confidence, contradictory, or a "
                f"covered country ({BANNED_ORIGIN_COUNTRIES_HINT}) appears anywhere in this heat's "
                "sub-lot table — this is a human-review signal, not a compliance verdict."
            ),
        },
        "flagged_reason": {"type": ["string", "null"], "description": "Why flagged_for_review is true; null otherwise."},
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
        "flagged_for_review",
        "flagged_reason",
    ],
}

TOOL = {
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
            "heats": {"type": "array", "items": HEAT_SCHEMA, "minItems": 1},
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
    f"Flag a heat for review if any feedstock sub-lot has an unconfirmed or low-confidence origin, "
    f"contradictory origin data, or a covered country ({BANNED_ORIGIN_COUNTRIES_HINT}) anywhere in "
    "its sub-lot table — flagging for review is separate from confidence: a plainly-stated "
    "covered-country origin is both HIGH confidence and flagged for review at the same time."
)

RETRYABLE_ERRORS = (anthropic.APIError, RuntimeError, KeyError, ValueError, TypeError)


def _call_llm(raw_text: str) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=MODEL,
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        tools=[TOOL],
        tool_choice={"type": "tool", "name": TOOL["name"]},
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
    raise RuntimeError("model response had no tool_use block")


def _regex_fallback(raw_text: str) -> dict:
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
        "flagged_for_review": True,
        "flagged_reason": "regex fallback — composition and sub-lot data not parsed, needs full manual review",
        "source": "regex",
    }
    return {
        "certificate_id": None,
        "supplier_id": flat.get("supplier_name"),
        "signatures": [],
        "heats": [heat],
    }


def extract_structured(raw_text: str) -> dict:
    """Returns {certificate_id, supplier_id, signatures, heats: [...]} —
    each heat dict carries a `source` key ('llm' on a successful model
    call, 'regex' when it fell back) so callers can record which path
    actually produced it."""
    try:
        result = _call_llm(raw_text)
        for heat in result["heats"]:
            heat["source"] = "llm"
        return result
    except RETRYABLE_ERRORS as exc:
        logger.warning("LLM extraction failed (%s), falling back to regex extractor", exc)
        return _regex_fallback(raw_text)
