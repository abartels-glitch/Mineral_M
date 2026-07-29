"""LLM structuring pass — the second step of the OCR-then-LLM pipeline.

Takes the raw text `ocr.py` pulled out of a document and asks Claude to
structure it into the same fixed field set `extractor.py`'s regex used
to produce, with a per-field confidence score, via forced tool use for
reliable structured output.

Falls back to the regex extractor whenever `ANTHROPIC_API_KEY` is unset
or the API call fails for any reason (network, auth, rate limit,
malformed response) — uploads should never break because an external
API had a bad moment, and this keeps the test suite offline and free.
"""
import logging
import os

import anthropic

import extractor

logger = logging.getLogger(__name__)

MODEL = "claude-haiku-4-5-20251001"
FIELD_NAMES = list(extractor.FIELD_PATTERNS.keys())

TOOL = {
    "name": "record_extracted_fields",
    "description": (
        "Record the fields extracted from a certificate of conformance / "
        "mill test report, with a confidence score per field."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            name: {
                "type": "object",
                "properties": {
                    "value": {
                        "type": ["string", "null"],
                        "description": f"The extracted {name}, or null if not present in the text.",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "0.0-1.0 confidence this value is correct and explicitly stated in the text.",
                    },
                },
                "required": ["value", "confidence"],
            }
            for name in FIELD_NAMES
        },
        "required": FIELD_NAMES,
    },
}

SYSTEM_PROMPT = (
    "You extract structured fields from a certificate of conformance / mill test "
    "report (MTR) for metal/alloy materials. Only use information explicitly "
    "present in the provided text — never guess or infer a value that isn't "
    "stated. If a field isn't present, set value to null and confidence to 0.0."
)

RETRYABLE_ERRORS = (anthropic.APIError, RuntimeError, KeyError, ValueError, TypeError)


def _call_llm(raw_text: str) -> dict:
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        tools=[TOOL],
        tool_choice={"type": "tool", "name": TOOL["name"]},
        messages=[{"role": "user", "content": raw_text}],
    )
    for block in response.content:
        if block.type == "tool_use":
            return block.input
    raise RuntimeError("model response had no tool_use block")


def extract_fields(raw_text: str) -> list[dict]:
    """Returns {field_name, field_value, confidence, source} dicts —
    `source` is 'llm' on a successful model call, 'regex' when it fell
    back, so callers can record which path actually produced each field.
    """
    try:
        result = _call_llm(raw_text)
        fields = []
        for name in FIELD_NAMES:
            entry = result.get(name) or {}
            fields.append(
                {
                    "field_name": name,
                    "field_value": entry.get("value"),
                    "confidence": float(entry.get("confidence") or 0.0),
                    "source": "llm",
                }
            )
        return fields
    except RETRYABLE_ERRORS as exc:
        logger.warning("LLM extraction failed (%s), falling back to regex extractor", exc)
        return [{**field, "source": "regex"} for field in extractor.extract_fields(raw_text)]
