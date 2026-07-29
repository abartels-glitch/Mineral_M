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


def _fake_client(response=None, raises=None):
    def create(**kwargs):
        if raises:
            raise raises
        return response

    return types.SimpleNamespace(messages=types.SimpleNamespace(create=create))


def _tool_response(overrides=None):
    data = {name: {"value": f"value-for-{name}", "confidence": 0.95} for name in llm_extractor.FIELD_NAMES}
    if overrides:
        data.update(overrides)
    return FakeResponse([FakeToolUseBlock(data)])


def test_extract_fields_success(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(_tool_response()))

    fields = llm_extractor.extract_fields("some raw text")

    assert len(fields) == len(llm_extractor.FIELD_NAMES)
    for field in fields:
        assert field["source"] == "llm"
        assert field["field_value"] == f"value-for-{field['field_name']}"
        assert field["confidence"] == 0.95


def test_extract_fields_missing_field_defaults_null_zero(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    data = {name: {"value": None, "confidence": 0.0} for name in llm_extractor.FIELD_NAMES}
    response = FakeResponse([FakeToolUseBlock(data)])
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(response))

    fields = llm_extractor.extract_fields("blank document")
    assert all(f["field_value"] is None and f["confidence"] == 0.0 for f in fields)


def test_falls_back_to_regex_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text = (
        "Supplier: Rio Grande Magnetics, LLC\nHeat Number: X-1\n"
        "Material: NdFeB\nCountry of Origin: United States\nBatch Mass: 10 kg\n"
    )

    fields = llm_extractor.extract_fields(text)

    assert all(f["source"] == "regex" for f in fields)
    supplier = next(f for f in fields if f["field_name"] == "supplier_name")
    assert supplier["field_value"] == "Rio Grande Magnetics, LLC"


def test_falls_back_to_regex_on_api_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(
        llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(raises=RuntimeError("network exploded"))
    )

    fields = llm_extractor.extract_fields("Supplier: X\n")
    assert all(f["source"] == "regex" for f in fields)


def test_falls_back_when_response_has_no_tool_use_block(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda api_key: _fake_client(FakeResponse([])))

    fields = llm_extractor.extract_fields("Supplier: X\n")
    assert all(f["source"] == "regex" for f in fields)
