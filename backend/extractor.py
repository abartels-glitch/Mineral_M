"""Regex-based field extraction for certificate-of-conformance / MTR text.

Placeholder for the OCR + LLM structuring pass described in spec section
4.1. Confidence here is a fixed placeholder, not a real per-field model
score — every document still goes through mandatory human review
regardless of "confidence," so there's no threshold-gating logic yet.
That logic is additive once real confidence scores exist.
"""
import re

FIELD_PATTERNS = {
    "supplier_name": r"Supplier:\s*(.+)",
    "heat_number": r"Heat Number:\s*(.+)",
    "material_type": r"Material:\s*(.+)",
    "origin_country": r"Country of Origin:\s*(.+)",
    "mass_kg": r"Batch Mass:\s*([\d.]+)\s*kg",
}

MATCHED_CONFIDENCE = 0.95
UNMATCHED_CONFIDENCE = 0.0


def extract_fields(raw_text: str) -> list[dict]:
    """Returns a list of {field_name, field_value, confidence} dicts."""
    results = []
    for field_name, pattern in FIELD_PATTERNS.items():
        match = re.search(pattern, raw_text, re.IGNORECASE)
        if match:
            results.append(
                {
                    "field_name": field_name,
                    "field_value": match.group(1).strip(),
                    "confidence": MATCHED_CONFIDENCE,
                }
            )
        else:
            results.append(
                {
                    "field_name": field_name,
                    "field_value": None,
                    "confidence": UNMATCHED_CONFIDENCE,
                }
            )
    return results
