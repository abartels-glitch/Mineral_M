"""Per-org configuration for document ingestion.

Externalizes what used to be hardcoded Rio Grande Magnetics-specific
constants directly in llm_extractor.py (the heat_id label-variant hint)
and passport.py (the DFARS materials-scope keyword list). Onboarding a
new design partner with different document terminology or a different
in-scope materials list is now a matter of adding config/orgs/<slug>.json
— see README.md's "Onboarding a new design partner" section.

What's deliberately NOT config-driven, and why (see also README + the
comment above llm_extractor.HEAT_SCHEMA): the *field names* extracted per
heat (heat_id, alloy_composition, test_results, mass_kg, ...) and per
sub-lot (sublot_id, blend_pct, origin_country, origin_confidence, notes)
are fixed Python-level schema keys, not config values. main.py's
ingestion code, the document_heats/heat_sublots SQL columns, and the
frontend's correction UI (index.html's HEAT_CORRECTABLE_FIELDS /
ORIGIN_FIELD_MARKERS) all read/write these exact key names — a config
file that renamed one would silently break the pipeline several layers
downstream with no error at the config-loading boundary. These field
names describe the "certificate of conformance / MTR" document TYPE
(shared by any org submitting one), not any one org's variation on it,
which is also why they stay Python-level rather than per-org: BUILD_SPEC
section 2 already flags "document *types*" (plural) as a bigger, later
piece of work than this pass. What genuinely varies per design partner
without that coupling risk: the descriptive label-variant text fed to
the LLM (depends on that org's actual document wording) and the
materials-scope list (depends on what that org actually produces) — both
pure data, no shape coupling to anything downstream.
"""
import json
import os
import re
from pathlib import Path

# FEOC_CONFIG_DIR override exists for the same reason db.py's FEOC_DATA_DIR
# does: tests need to point this at an isolated tmp dir without a real
# config/orgs/ directory existing there, same pattern as
# crypto_utils.KEYS_DIR / storage.OBJECTS_DIR being monkeypatchable per test.
CONFIG_DIR = Path(os.environ.get("FEOC_CONFIG_DIR") or Path(__file__).resolve().parent.parent / "config" / "orgs")

# Used whenever no config/orgs/<slug>.json exists for an org — keeps every
# existing test fixture (issuers named "Test Issuer", "Test-Issuer-2", etc.,
# none of which have or need a real config file) behaving exactly as it did
# before this refactor existed: same materials scope, same extraction hint,
# via a plain Python fallback rather than requiring a file on disk for every
# org a test happens to construct.
#
# TODO(org-config): this silent fallback is a correctness bug waiting to
# happen the moment a SECOND real design partner is onboarded, not just a
# convenience. Today there's exactly one real org (Rio Grande Magnetics,
# which has its own config/orgs/riograndemagnetics.json — this constant is
# only ever reached for orgs that were never onboarded with a file, i.e.
# test fixtures), so silently handing out Rio Grande's materials scope and
# extraction hint to "whoever has no file" is harmless: nobody real is
# affected. Once a second real org exists, a missing config file for a
# REAL org stops being "an org that was never onboarded" and starts being
# "onboarding was forgotten" — and silently running that org's documents
# against a different org's materials scope (wrong in-scope/out-of-scope
# calls) or extraction hint (wrong LLM guidance) is a live compliance bug,
# not a graceful degradation. At that point, load_config_for_issuer should
# raise/500 (or the caller should 400) for any REAL org with no config
# file, rather than falling through to DEFAULT_CONFIG — test fixtures would
# need their own explicit opt-in to the default instead of getting it for
# free. Not implemented now because it's premature with only one real org
# and would just make every test that doesn't bother with a config file
# start failing for no functional reason. Revisit when org #2 is onboarded.
DEFAULT_CONFIG = {
    "org_name": "(default — no org-specific config found)",
    "document_types": ["mtr_coc"],
    "heat_id_label_hint": "Normalize label variants: 'Heat No.', 'Melt Ref.', etc. all mean the same thing.",
    "materials_scope": [
        "samarium-cobalt",
        "samarium cobalt",
        "smco",
        "ndfeb",
        "neodymium",
        "tantalum",
        "tungsten",
    ],
}


def org_slug(org_name: str) -> str:
    """Derived, not stored as its own `issuers` column — lowercase, strip
    everything but letters/digits. Documented tradeoff, not an oversight:
    renaming an org's `name` after onboarding silently orphans its config
    file (lookup falls through to DEFAULT_CONFIG instead of erroring), since
    there's no separate stable identifier to key config lookup on today."""
    return re.sub(r"[^a-z0-9]", "", org_name.lower())


def load_config_for_org_name(org_name: str) -> dict:
    path = CONFIG_DIR / f"{org_slug(org_name)}.json"
    if not path.exists():
        # See the TODO(org-config) above DEFAULT_CONFIG: fine while there's
        # only one real org, a live bug once there's a second one with no
        # file of its own.
        return DEFAULT_CONFIG
    with open(path) as f:
        return json.load(f)


def load_config_for_issuer(conn, issuer_id: str) -> dict:
    """The lookup path actually used at runtime: an issuer_id (what
    documents/credentials/etc. all key on) resolves to the issuer's `name`,
    which resolves to a config slug. Falls back to DEFAULT_CONFIG if the
    issuer row itself is missing (shouldn't happen for a real FK-valid
    issuer_id, but this is reachable from the public, unauthenticated
    passport-lookup path via passport.py, so it must degrade rather than
    raise)."""
    row = conn.execute("SELECT name FROM issuers WHERE id = ?", (issuer_id,)).fetchone()
    if row is None:
        return DEFAULT_CONFIG
    return load_config_for_org_name(row["name"])
