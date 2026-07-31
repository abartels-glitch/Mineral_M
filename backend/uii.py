"""UII / Data Matrix generation, plus MIL-STD-130 Construct #1 UII
generation and parsing.

`generate_datamatrix_png` is unrelated to the Construct #1 work below —
it just rasters whatever payload string it's given (today, and still
today, the full passport URL) into a Data Matrix PNG.

The Construct #1 support below (`generate_uii`/`wrap_scan_payload`/
`parse_uii`) is wired into issuance and the passport lookup path in
main.py. It's still built as an isolated, DB-free unit — `parse_uii`
takes the actual `uii_bindings` lookup and issuer-prefix table as
injected callables/data from the caller, rather than a DB connection,
so it stays testable on its own.

Scope is deliberately Construct #1 only (IAC + Enterprise Identifier +
Serial Number unique within the enterprise) — not Construct #2 (which
adds a part number). A message that looks like Construct #2 is rejected
distinctly as "unsupported_construct" rather than silently misparsed as
Construct #1; see parse_uii().

Format: ISO/IEC 15434 Format 06 envelope wrapping a single ANSI
MH10.8.2 data identifier "25S", whose value is the concatenated
IAC+EID+serial string (per the DoD Guide to Uniquely Identifying
Items). Example of the full scanned/printed form:

    [)><RS>06<GS>25SUN123456789RGM0000000123<RS><EOT>

`generate_uii()` returns just the bare "UN123456789RGM0000000123" part
— the canonical UII value, and what's stored as uii_bindings.uii_code.
`wrap_scan_payload()` adds the envelope around it for the actual
printed/scanned form. A legacy binding (no iac/enterprise_id
registered — see the fallback in main.py's issue_credential) is never
enveloped: its uii_code is just the raw credential_id, which isn't a
real IAC+EID+serial triple and shouldn't be dressed up as a 25S value.

Two design choices worth calling out:

- Serial number is derived from credential_id (uppercased hex), not a
  separate per-issuer counter — credential_id is already globally
  unique, which trivially satisfies "unique within the enterprise",
  without standing up new counter state.

- IAC/EID splitting uses a known-issuer-prefix table rather than a
  general MIL-STD-130 IAC registry lookup. Real IACs are 1-4 chars, so
  a flat concatenated string can't be split into IAC/EID without *some*
  registry — but since this system only ever needs to resolve items it
  itself issued, matching against our own issuers' registered
  IAC+EID prefixes both locates the split point and doubles as
  confirming the issuing enterprise is one we know, in one step.

Legacy compatibility: a pre-migration `uii_code` is just a raw
credential_id with no envelope at all. parse_uii() only falls through
to that legacy path when stage 1 finds no envelope attempt whatsoever
(as opposed to a broken one) — kept as an explicit separate final stage
rather than merged into the other four, so a caller can mark a legacy
resolution distinguishably (`is_legacy`) in the audit trail from a real
Construct #1 resolution.
"""
import re
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from pystrich.datamatrix import DataMatrixEncoder


def generate_datamatrix_png(payload: str) -> bytes:
    return DataMatrixEncoder(payload).get_imagedata()


# --- MIL-STD-130 UII Construct #1 -------------------------------------

_RS = "\x1e"  # Record Separator
_GS = "\x1d"  # Group Separator
_EOT = "\x04"  # End of Transmission
_ENVELOPE_HEADER = "[)>"
_FORMAT_NUMBER = "06"
_UII_DI = "25S"

# DI codes that most commonly appear when a message re-encodes a
# Construct #2 UII (splitting enterprise id and part number into their
# own elements, rather than Construct #1's single concatenated 25S) —
# a best-effort label for a friendlier error message, not an exhaustive
# Construct #2 recognizer. The actual safety property doesn't depend on
# this list being complete: _check_construct only ever accepts a lone,
# well-formed 25S element as Construct #1 — anything else is rejected,
# whether or not it happens to match one of these markers.
_CONSTRUCT_2_MARKERS = ("18V", "1P")

UIIOutcome = Literal["found", "not_found", "malformed", "unsupported_construct"]


@dataclass
class UIIParseResult:
    outcome: UIIOutcome
    reason: str
    is_legacy: bool = False
    credential_id: Optional[str] = None
    uii_code: Optional[str] = None
    iac: Optional[str] = None
    enterprise_id: Optional[str] = None
    serial: Optional[str] = None


def generate_uii(iac: str, enterprise_id: str, credential_id: str) -> str:
    """Builds the bare Construct #1 UII value (IAC+EID+serial, no
    transfer-syntax envelope) for `credential_id`, issued under
    `iac`/`enterprise_id`. See module docstring for the serial-number
    design choice.

    This bare value — not the enveloped form — is the canonical UII:
    it's what gets stored as uii_bindings.uii_code (a stable, control-
    character-free DB key), matching parse_uii's stage-4 lookup, which
    extracts this same bare value out of a scanned envelope before
    looking it up. Use wrap_scan_payload() to get the ISO/IEC 15434
    envelope actually printed/scanned."""
    serial = credential_id.upper()
    return f"{iac}{enterprise_id}{serial}"


def wrap_scan_payload(value_25s: str) -> str:
    """Wraps a bare Construct #1 UII value in the ISO/IEC 15434 Format 06
    envelope (DI 25S) — this is the string actually encoded into the
    printed Data Matrix / passport URL, i.e. what a scan decodes to and
    what parse_uii's stage 1 expects."""
    return f"{_ENVELOPE_HEADER}{_RS}{_FORMAT_NUMBER}{_GS}{_UII_DI}{value_25s}{_RS}{_EOT}"


def _check_envelope(text: str) -> tuple[str, object]:
    """("no_envelope", None) if `text` doesn't even attempt the ISO/IEC
    15434 Format 06 envelope — caller should try the legacy
    bare-credential_id path instead, not call this malformed.
    ("malformed", reason) if it attempts the envelope but is
    structurally broken. ("ok", segments) with the GS-split data
    elements if the envelope is well-formed."""
    if not text.startswith(_ENVELOPE_HEADER):
        return "no_envelope", None
    rest = text[len(_ENVELOPE_HEADER):]
    if not rest.startswith(_RS):
        return "malformed", "missing record separator after envelope header"
    rest = rest[len(_RS):]
    if not rest.startswith(_FORMAT_NUMBER):
        return "malformed", f"unsupported format number (expected '{_FORMAT_NUMBER}')"
    rest = rest[len(_FORMAT_NUMBER):]
    if not rest.startswith(_GS):
        return "malformed", "missing group separator after format number"
    rest = rest[len(_GS):]
    if not rest.endswith(_RS + _EOT):
        return "malformed", "missing trailing record-separator/EOT"
    rest = rest[: -len(_RS + _EOT)]
    if not rest:
        return "malformed", "envelope contains no data elements"
    return "ok", rest.split(_GS)


def _check_construct(segments: list[str]) -> tuple[str, object]:
    """("ok", value_25s) only when `segments` is exactly one element and
    it's a 25S data identifier — that's the entire Construct #1 shape.
    Anything else is rejected: ("unsupported_construct", reason) with a
    friendlier message when it looks like Construct #2, else
    ("malformed", reason)."""
    if len(segments) == 1 and segments[0].startswith(_UII_DI):
        return "ok", segments[0][len(_UII_DI):]
    if any(s.startswith(m) for s in segments for m in _CONSTRUCT_2_MARKERS):
        return "unsupported_construct", (
            "message carries Construct #2-style data identifiers (separate enterprise-id/part-number "
            "elements); only Construct #1 (a single concatenated 25S element) is supported"
        )
    return "malformed", "no single 25S (UII Construct #1) data identifier found"


def _validate_fields(
    value_25s: str, known_issuer_prefixes: dict[str, tuple[str, str]]
) -> tuple[str, object]:
    """Splits `value_25s` into (iac, enterprise_id, serial) by matching
    against `known_issuer_prefixes` (prefix string -> (iac,
    enterprise_id), built by the caller from the issuers table's
    iac/enterprise_id columns). Longest-prefix-first so a short prefix
    can't swallow part of a longer one that also matches."""
    for prefix in sorted(known_issuer_prefixes, key=len, reverse=True):
        if value_25s.startswith(prefix):
            serial = value_25s[len(prefix):]
            if not serial:
                return "malformed", "25S value has a recognized issuer prefix but no serial number"
            if not re.fullmatch(r"[A-Z0-9]+", serial):
                return "malformed", "serial number contains characters outside A-Z0-9"
            iac, enterprise_id = known_issuer_prefixes[prefix]
            return "ok", (iac, enterprise_id, serial)
    return "malformed", "IAC+EID prefix not recognized by any known issuer"


def parse_uii(
    text: str,
    known_issuer_prefixes: dict[str, tuple[str, str]],
    resolve_uii: Callable[[str], Optional[str]],
    resolve_legacy_credential_id: Callable[[str], Optional[str]],
) -> UIIParseResult:
    """Staged validation of a decoded scan payload:
      1. envelope check (ISO/IEC 15434 Format 06)
      2. data-identifier/construct check (rejects Construct #2 distinctly)
      3. field validation via known-issuer-prefix matching
      4. lookup, via the caller-supplied `resolve_uii`
    Only when stage 1 finds no envelope attempt at all does an explicit
    final fallback stage try `text` as a legacy bare credential_id via
    `resolve_legacy_credential_id` — kept separate from the four stages
    above (see module docstring) rather than folded in.

    `resolve_uii`/`resolve_legacy_credential_id` are injected rather
    than this module reading a DB connection directly, so the whole
    pipeline is a pure, isolated unit testable without any app/DB
    setup — main.py supplies the real lookups once this is wired in.
    """
    text = text.strip()
    if not text:
        return UIIParseResult(outcome="malformed", reason="empty scan payload")

    env_status, env_value = _check_envelope(text)
    if env_status == "no_envelope":
        credential_id = resolve_legacy_credential_id(text)
        if credential_id:
            return UIIParseResult(
                outcome="found",
                reason="resolved via legacy bare-credential_id lookup",
                is_legacy=True,
                credential_id=credential_id,
                uii_code=text,
            )
        return UIIParseResult(
            outcome="not_found",
            reason="no Construct #1 envelope detected and no matching legacy credential id",
            is_legacy=True,
            uii_code=text,
        )
    if env_status == "malformed":
        return UIIParseResult(outcome="malformed", reason=env_value)

    construct_status, construct_value = _check_construct(env_value)
    if construct_status != "ok":
        return UIIParseResult(outcome=construct_status, reason=construct_value)

    field_status, field_value = _validate_fields(construct_value, known_issuer_prefixes)
    if field_status != "ok":
        return UIIParseResult(outcome="malformed", reason=field_value)

    iac, enterprise_id, serial = field_value
    uii_code = construct_value
    credential_id = resolve_uii(uii_code)
    if credential_id:
        return UIIParseResult(
            outcome="found",
            reason="resolved via Construct #1 UII lookup",
            credential_id=credential_id,
            uii_code=uii_code,
            iac=iac,
            enterprise_id=enterprise_id,
            serial=serial,
        )
    return UIIParseResult(
        outcome="not_found",
        reason="well-formed Construct #1 UII, no matching credential",
        uii_code=uii_code,
        iac=iac,
        enterprise_id=enterprise_id,
        serial=serial,
    )
