"""LLM structuring pass — mocks the Anthropic client entirely, no network
calls, so this stays offline and free like the rest of the suite."""
import types

import llm_extractor


class FakeToolUseBlock:
    def __init__(self, input_data):
        self.type = "tool_use"
        self.input = input_data


class FakeResponse:
    def __init__(self, content):
        self.content = content
        self.usage = types.SimpleNamespace(input_tokens=100, output_tokens=50)


def _fake_client(response=None, raises=None):
    def create(**kwargs):
        if raises:
            raise raises
        return response

    return types.SimpleNamespace(messages=types.SimpleNamespace(create=create))


def _heat(**overrides):
    heat = {
        "heat_id": "H-1",
        "alloy_composition": {"Nd": 29.5, "Fe": 68.2, "B": 1.0},
        "test_results": {"Br_kG": {"value": 13.2, "result": "pass"}},
        "nonconformance_refs": [],
        "feedstock_sublots": [],
        "segregation_attested": True,
        "segregation_note": "Dedicated line.",
        "mass_kg": 100.0,
        "confidence": 0.95,
        "flags": [],
    }
    heat.update(overrides)
    return heat


def _tool_response(heats, certificate_id="CERT-1", supplier_id="SUP-1"):
    data = {"certificate_id": certificate_id, "supplier_id": supplier_id, "signatures": [], "heats": heats}
    return FakeResponse([FakeToolUseBlock(data)])


def test_extract_structured_success_single_heat(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(_tool_response([_heat()])))

    result = llm_extractor.extract_structured("some raw text")

    assert result["certificate_id"] == "CERT-1"
    assert result["supplier_id"] == "SUP-1"
    assert len(result["heats"]) == 1
    heat = result["heats"][0]
    assert heat["source"] == "llm"
    assert heat["heat_id"] == "H-1"
    assert heat["alloy_composition"] == {"Nd": 29.5, "Fe": 68.2, "B": 1.0}
    assert heat["flags"] == []


def test_extract_structured_multi_heat_with_flagged_sublot(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    clean_heat = _heat(heat_id="H-1")
    flagged_heat = _heat(
        heat_id="H-2",
        # Raw shape as the LLM's tool_use.input would carry it — no
        # severity/source yet, those are added by extract_structured.
        flags=[
            {
                "issue_type": "compliance_violation",
                "field_name": "origin_country",
                "human_readable_reason": "covered-country sub-lot present",
            }
        ],
        feedstock_sublots=[
            {"sublot_id": "S1", "blend_pct": 80.0, "origin_country": "United States", "origin_confidence": "high", "notes": None},
            {"sublot_id": "S2", "blend_pct": 20.0, "origin_country": "China", "origin_confidence": "high", "notes": "broker-sourced"},
        ],
    )
    monkeypatch.setattr(
        llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(_tool_response([clean_heat, flagged_heat]))
    )

    result = llm_extractor.extract_structured("some raw text")

    assert len(result["heats"]) == 2
    assert result["heats"][0]["flags"] == []
    flag = result["heats"][1]["flags"][0]
    assert flag["issue_type"] == "compliance_violation"
    assert flag["field_name"] == "origin_country"
    assert flag["severity"] == "blocking"  # derived from issue_type, not trusted from the model
    assert flag["source"] == "extraction"
    assert len(result["heats"][1]["feedstock_sublots"]) == 2


def test_falls_back_to_regex_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text = (
        "Supplier: Rio Grande Magnetics, LLC\nHeat Number: X-1\n"
        "Material: NdFeB\nCountry of Origin: United States\nBatch Mass: 10 kg\n"
    )

    result = llm_extractor.extract_structured(text)

    assert result["supplier_id"] == "Rio Grande Magnetics, LLC"
    assert len(result["heats"]) == 1
    heat = result["heats"][0]
    assert heat["source"] == "regex"
    assert heat["heat_id"] == "X-1"
    assert heat["alloy_composition"] is None
    assert len(heat["flags"]) == 1
    assert heat["flags"][0]["issue_type"] == "low_confidence_extraction"
    assert heat["flags"][0]["severity"] == "needs_review"
    assert heat["flags"][0]["source"] == "extraction"
    assert heat["feedstock_sublots"] == [
        {
            "sublot_id": None,
            "blend_pct": 100.0,
            "origin_country": "United States",
            "origin_confidence": "low",
            "notes": "regex fallback — origin taken at face value from document text, not cross-checked",
        }
    ]


def test_falls_back_to_regex_on_api_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(raises=RuntimeError("network exploded"))
    )

    result = llm_extractor.extract_structured("Supplier: X\n")
    assert result["heats"][0]["source"] == "regex"
    assert len(result["heats"][0]["flags"]) == 1


def test_falls_back_when_response_has_no_tool_use_block(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(FakeResponse([])))

    result = llm_extractor.extract_structured("Supplier: X\n")
    assert result["heats"][0]["source"] == "regex"
