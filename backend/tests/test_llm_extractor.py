"""LLM structuring pass — mocks the Anthropic client entirely, no network
calls, so this stays offline and free like the rest of the suite."""
import types

import anthropic
import httpx

import llm_extractor

_REQ = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _status_error(cls, status_code, message="error"):
    return cls(message, response=httpx.Response(status_code, request=_REQ), body=None)


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


def _fake_client_sequence(*behaviors):
    """Each behavior is either a response object (returned) or an
    Exception instance (raised) -- one per call to .create(), in order.
    The last behavior repeats if .create() is called more times than
    there are behaviors."""
    calls = {"n": 0}

    def create(**kwargs):
        i = min(calls["n"], len(behaviors) - 1)
        calls["n"] += 1
        behavior = behaviors[i]
        if isinstance(behavior, Exception):
            raise behavior
        return behavior

    return types.SimpleNamespace(messages=types.SimpleNamespace(create=create), _calls=calls)


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
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: _fake_client(_tool_response([_heat()])))

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
        llm_extractor.anthropic, "Anthropic", lambda **kwargs: _fake_client(_tool_response([clean_heat, flagged_heat]))
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


# --- failure taxonomy: transient / permanent / malformed --------------------
#
# Real anthropic SDK exception instances, not a generic RuntimeError
# stand-in -- confirming the actual classification, not just that
# *something* falls back to regex.


def test_transient_failure_falls_back_with_extraction_unavailable_blocking_flag(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    exc = _status_error(anthropic.RateLimitError, 429, "rate limited")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: _fake_client(raises=exc))

    result = llm_extractor.extract_structured("Supplier: X\n")

    heat = result["heats"][0]
    assert heat["source"] == "regex"
    assert len(heat["flags"]) == 1
    flag = heat["flags"][0]
    assert flag["issue_type"] == "extraction_unavailable"
    assert flag["severity"] == "blocking"
    assert "temporarily unavailable" in flag["human_readable_reason"]

    failure = result["extraction_failure"]
    assert failure["category"] == "transient"
    assert failure["exception_class"] == "RateLimitError"


def test_permanent_failure_classified_distinctly_from_transient(monkeypatch):
    """A revoked/invalid API key must not read as a routine outage --
    this is the case most likely to affect every future extraction
    until an operator fixes it, so it needs its own, distinctly-labeled
    category, not just the same generic 'API had a bad moment' bucket."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    exc = _status_error(anthropic.AuthenticationError, 401, "invalid x-api-key")
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: _fake_client(raises=exc))

    result = llm_extractor.extract_structured("Supplier: X\n")

    flag = result["heats"][0]["flags"][0]
    assert flag["issue_type"] == "extraction_unavailable"
    assert flag["severity"] == "blocking"
    assert "configuration or request problem" in flag["human_readable_reason"]
    assert "every future extraction" in flag["human_readable_reason"]

    failure = result["extraction_failure"]
    assert failure["category"] == "permanent"
    assert failure["exception_class"] == "AuthenticationError"


def test_conflict_and_high_5xx_status_are_classified_transient_by_status_code():
    """Classification goes by status code (matching the SDK's own
    _should_retry), not a hardcoded exception-class allowlist -- 409 is
    a named ConflictError but the SDK retries it same as 429/5xx, and a
    529 OverloadedError must land the same bucket as a plain 500."""
    assert llm_extractor._classify_failure(_status_error(anthropic.ConflictError, 409)) == "transient"
    assert llm_extractor._classify_failure(_status_error(anthropic.OverloadedError, 529)) == "transient"
    assert llm_extractor._classify_failure(_status_error(anthropic.InternalServerError, 503)) == "transient"
    assert llm_extractor._classify_failure(_status_error(anthropic.BadRequestError, 400)) == "permanent"
    assert llm_extractor._classify_failure(_status_error(anthropic.NotFoundError, 404)) == "permanent"


def test_connection_and_timeout_errors_classified_transient():
    assert llm_extractor._classify_failure(anthropic.APIConnectionError(request=_REQ)) == "transient"
    assert llm_extractor._classify_failure(anthropic.APITimeoutError(request=_REQ)) == "transient"


def test_malformed_response_retries_once_and_recovers(monkeypatch):
    """Model output isn't perfectly deterministic -- an unusable
    response on the first attempt shouldn't fall all the way back to
    regex if an immediate retry gets a clean one."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    good_response = _tool_response([_heat()])
    client = _fake_client_sequence(FakeResponse([]), good_response)  # 1st: no tool_use block, 2nd: clean
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: client)

    result = llm_extractor.extract_structured("Supplier: X\n")

    assert result["heats"][0]["source"] == "llm"
    assert "extraction_failure" not in result
    assert client._calls["n"] == 2


def test_malformed_response_exhausted_after_one_retry_falls_back(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    client = _fake_client_sequence(FakeResponse([]), FakeResponse([]))  # unusable both times
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: client)

    result = llm_extractor.extract_structured("Supplier: X\n")

    assert client._calls["n"] == 2  # exactly one retry, not an unbounded loop
    heat = result["heats"][0]
    assert heat["source"] == "regex"
    flag = heat["flags"][0]
    assert flag["issue_type"] == "extraction_unavailable"
    assert flag["severity"] == "blocking"
    assert result["extraction_failure"]["category"] == "malformed"
    assert result["extraction_failure"]["exception_class"] == "MalformedResponseError"


def test_malformed_schema_mismatch_from_our_own_postprocessing_is_classified_malformed(monkeypatch):
    """A tool_use block missing a key our own code expects (e.g. no
    "heats" at all) raises a KeyError deep in extract_structured's own
    post-processing, not an anthropic exception -- must still land in
    the malformed bucket, not crash the upload."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    bad_response = FakeResponse([FakeToolUseBlock({"certificate_id": None, "supplier_id": None, "signatures": []})])
    client = _fake_client_sequence(bad_response, bad_response)
    monkeypatch.setattr(llm_extractor.anthropic, "Anthropic", lambda **kwargs: client)

    result = llm_extractor.extract_structured("Supplier: X\n")

    assert result["extraction_failure"]["category"] == "malformed"
    assert result["extraction_failure"]["exception_class"] == "KeyError"


def test_falls_back_to_regex_when_no_api_key_stays_benign_low_confidence(monkeypatch):
    """The one case that must NOT become extraction_unavailable/blocking:
    no key configured at all is an expected dev/test condition, not a
    failed attempt -- no extraction_failure key at all, same as before
    this change."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    result = llm_extractor.extract_structured("Supplier: X\n")

    heat = result["heats"][0]
    assert heat["flags"][0]["issue_type"] == "low_confidence_extraction"
    assert heat["flags"][0]["severity"] == "needs_review"
    assert "extraction_failure" not in result
