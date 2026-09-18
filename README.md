# FEOC compliance passport — MVP scaffold

A supplier uploads a certificate of conformance / MTR, a human reviews the
extracted fields, a signed credential gets issued, and a recursive
"passport" compiler walks the resulting credential graph to determine
whether a part's material provenance is clean of Foreign Entities of
Concern (FEOC) under the DFARS rare-earth rule.

This is a first-pass scaffold, not the full MVP described in
`BUILD_SPEC.md` — see "Not built yet" below for what's deliberately
deferred and why.

## Pinned MVP decisions

These were open product questions in the original spec. They're resolved
here provisionally, against a synthetic design partner, so the schema and
compliance logic have something concrete to be built against. Revisit
with a real design partner before a real pilot.

| Decision | MVP call | Upgrade path |
|---|---|---|
| **Key custody** | Client-side, org-controlled: each org generates its own Ed25519 keypair in-browser (Web Crypto, non-extractable private key, IndexedDB-persisted) — the platform never sees or stores a private key. Keys are versioned (`issuer_keys`, one row per key with a validity window) so rotation doesn't retroactively invalidate credentials signed under a prior key; revocation is retroactive (flags every credential that key ever signed). First-key registration is `platform_admin`-witnessed (same checkpoint as org onboarding); rotation after that is self-service by the org's own account. **Known gap:** registration only proves the request came from an authenticated org session (role/org_id check + a password step-up re-auth) — not real-world identity. A compromised org account can still register an attacker-controlled key. | Move to hardware-backed custody (WebAuthn/FIDO2 security keys or an org-side HSM) and add real identity verification (notarization/KYC) behind first-key registration before handling real supplier trust relationships |
| **Document scope** | One document type: certificate of conformance / MTR. A certificate can cover one heat/melt (the common case) or several (a consolidated multi-heat certificate) — each heat is extracted, reviewed, and can become its own credential independently. Tightened after testing against `rio_grande_mtr_complex.pdf` (see below): single-heat is the working regression bar, multi-heat is the stretch target. | Add document *types* (not just heat counts) once the first one is proven against a real sample |
| **Segregation enforcement** | Self-reported, but with a floor: `segregation_attested` (bool) + `segregation_attested_by` (named person) + `segregation_note` (control description). No third-party evidence yet. | Add evidence upload (photos, process logs) and eventually third-party audit |
| **Materials scope** | Compliance engine only checks the actual DFARS rare-earth scope: samarium-cobalt magnets, NdFeB magnets, tantalum, tungsten. Anything else yields `insufficient_data`, not a silent pass. Per-org, not a single hardcoded list — see "Onboarding a new design partner" below. | Don't let product language ("motors, batteries, ESCs") outrun this without extending the engine first |

### Synthetic design partner: Rio Grande Magnetics (fictional)

The seed data (`backend/seed.py`) is built around a **fictional** profile
used only to make the schema and demo concrete — not a real company:

> A small, single-site NdFeB magnet recycler/manufacturer in Texas
> (modeled on the real-world Noveon/e-VAC pattern). Collects decommissioned
> motors and hard-drive magnets from domestic sources only, and reprocesses
> them into new sintered NdFeB magnets on one dedicated production line.
> No mixed-nationality ore blending — there's no ore, just US-collected
> scrap. That's what makes the material story provably traceable, which is
> the property a real first design partner should be selected for too.

Replace this with a real design partner's real document before treating
any output as more than a demo.

### Onboarding a new design partner

The parts of extraction/compliance that genuinely vary per design partner
(as opposed to being fixed by the certificate-of-conformance/MTR document
type itself — see the caveat below) are pulled out of Python and into
`config/orgs/<slug>.json`, keyed off the org's `issuers.name` lowercased
with everything but letters/digits stripped (`"Rio Grande Magnetics"` →
`riograndemagnetics.json`; `org_config.org_slug()` does the same
normalization at lookup time — there's no separate slug column). An org
with no config file on disk gets `org_config.DEFAULT_CONFIG` (today,
identical in content to Rio Grande's own file), so nothing breaks for an
org that hasn't been onboarded with a file yet.

To onboard a new design partner, add `config/orgs/<slug>.json` with:

```json
{
  "org_name": "Exact name as it appears in the issuers table",
  "document_types": ["mtr_coc"],
  "heat_id_label_hint": "Whatever this supplier's own certs call the heat/batch/lot number",
  "materials_scope": ["keyword", "keyword", "..."]
}
```

- **`document_types`** — accepted values for the upload endpoint's
  `document_type` field; `POST /documents/upload` now 400s with a message
  naming the org if it's given anything else (`main.py`'s `upload_document`).
- **`heat_id_label_hint`** — fed to the LLM extraction prompt as the
  description of the `heat_id` field (`llm_extractor._build_heat_schema`) —
  the one part of the extraction schema that's genuinely about this org's
  own document wording rather than the document type in general.
- **`materials_scope`** — substring keywords checked against each
  credential's `material_type` at passport-compile time
  (`passport._material_in_scope`), resolved **per issuing org** — a
  composite credential combining sources from two different orgs checks
  each source against its own issuer's scope, not one global list.

No code change in `llm_extractor.py` or `passport.py` is required for this
— see `backend/tests/test_org_config.py`, which proves the same claim with
a second, structurally unrelated fictional org ("Acme Tantalum Components")
whose materials scope shares no keywords with Rio Grande's.

**What's deliberately NOT config-driven**: the extracted field *names*
themselves (`heat_id`, `alloy_composition`, `test_results`, `mass_kg`,
sub-lot `sublot_id`/`blend_pct`/`origin_country`/`origin_confidence`) stay
fixed Python-level schema keys. They're load-bearing several layers past
extraction — `main.py`'s ingestion code, the `document_heats`/`heat_sublots`
SQL columns, and the frontend correction UI
(`index.html`'s `HEAT_CORRECTABLE_FIELDS`/`ORIGIN_FIELD_MARKERS`) all
read/write these exact keys — so a config file that renamed one would
silently break the pipeline downstream with no error at the config-loading
boundary. These names describe the certificate-of-conformance/MTR document
*type* (shared by any org submitting one), not any one org's variation on
it — genuinely adding a *different* document type (not just different
terminology for the same one) is BUILD_SPEC section 2's own larger,
later item, not something this config format takes on.

## Auth

Session-cookie auth with three roles, added ahead of the spec's own build
order (section 6 puts it at step 6 of 9) because an open API is an active
liability the moment real supplier data touches it, not just an
incompleteness.

| Decision | MVP call |
|---|---|
| **Session model** | Server-side session, httpOnly cookie holding a random token; only its SHA-256 hash is stored (`sessions` table). No JWT — the frontend is plain no-build-step JS, so there's no token-storage/refresh logic to build. |
| **Roles** | Collapsed to three, not the spec's literal four: `org_user` (upload/review/issue for their own org — covers supplier/reviewer/manufacturer for a single-org pilot), `buyer_auditor` (read-only, cross-org), `platform_admin` (creates orgs/users, no org of their own). |
| **Passport lookup** | Stays unauthenticated. Credential ids are unguessable UUIDs — possession of the id (e.g. from scanning a physical part) is the access model, like a shared link. |

Accounts are ops-created (`POST /admin/users`, `platform_admin` only) —
no public self-registration flow. Dev accounts from `seed.py`:

| Role | Email | Password |
|---|---|---|
| `org_user` (Rio Grande Magnetics) | `maria@riograndemagnetics.example` | `riograndemagnetics-dev` |
| `platform_admin` | `admin@feoc-passport.local` | `platform-admin-dev` |

**Not production-hardened**: no rate limiting on login, no password
reset, no HTTPS enforcement (`secure=False` on the cookie — fine over
local http, must flip before any real deployment), no self-registration/
email verification.

### Audit trail — what login actually buys you

`buyer_auditor` used to exist with no real capability beyond what an
anonymous visitor already gets from the public passport lookup. Rather
than gate the public lookup behind login (worse for the "scan a part in
the field" use case), logged-in users now get a second, additive layer:
`GET /credentials/{id}/audit-trail` — who reviewed/issued the credential
and when, plus (for document-backed credentials) the originating heat's
full extraction/review detail: alloy composition, segregation
attestation, and its sub-lot table with flagged/ok status per sub-lot.

- `org_user`: only credentials their own org issued (403 across orgs,
  same pattern as documents).
- `buyer_auditor` / `platform_admin`: any credential, any org — this is
  the actual point of the feature.
- Surfaced on `passport.html` as an "Audit trail" section that only
  appears for a logged-in session (`getCurrentUserOrNull()` in `app.js`
  — a non-redirecting variant of `requireAuth()`, since this page must
  stay fully public otherwise).

This is also why `document_heats.source` and `.extraction_source` are two
different columns: `source` reflects who currently owns the heat's data
and gets overwritten to `human` on review, while `extraction_source` is
written once at extraction time and never touched again — the audit
trail needs the permanent one to answer "was this heat ever
auto-extracted, and by which path."

## Document ingestion: object storage + two-step OCR/LLM extraction

Real file storage and real per-heat structuring, replacing the original
naive-UTF-8-decode-plus-flat-regex placeholder.

- **Object storage** (`backend/storage.py`): local filesystem under
  `data/objects/`, standing in for S3 — spec section 4.1's "S3 or
  local-equivalent for dev." Narrow `save_object`/`read_object`
  interface so a real S3 client later only means rewriting this one
  file. `documents` now carries `object_key` and a sha256
  `content_hash` of the uploaded bytes.
- **OCR step** (`backend/ocr.py`): PyMuPDF extracts a PDF's *embedded
  text layer*. **This is not image-based OCR** — this environment has no
  package manager available to install the Tesseract binary real OCR
  needs. It works well for digitally-generated certificates (most
  MTR/CoC documents), but a scanned/photographed paper document with no
  embedded text layer will come back empty. Real image OCR (Tesseract or
  a cloud OCR service) is a documented gap, not silently pretended away.
  Non-PDF uploads (e.g. the `.txt` demo samples) are decoded directly, as
  before.
- **LLM structuring step** (`backend/llm_extractor.py`): the OCR text
  goes to Claude (`claude-haiku-4-5-20251001`) via forced tool-use,
  targeting a **per-heat** schema — a certificate can cover multiple
  heats/melts, each with its own alloy composition, test results, and a
  table of blended feedstock sub-lots (sub-lot id, blend %, origin
  country, origin confidence). The model is told explicitly to return
  `null` rather than guess, and to flag a heat (`flagged_for_review`)
  when a sub-lot's origin is unconfirmed, contradictory, or a covered
  country appears anywhere in its table. `main.py` additionally
  re-checks every sub-lot deterministically against `passport.py`'s own
  banned-country list, so a heat gets flagged even if the model's
  own judgment misses it — belt-and-suspenders, not just LLM say-so.
  Two separate steps rather than one "LLM reads the PDF directly" call
  specifically so there's a raw, non-LLM-derived text artifact to check
  the model's structured output against — an auditability property, not
  just extra plumbing.
- **Three-state review UI, not two**: every field is found / not found /
  **flagged** — flagged is distinct from not-found and never collapses
  into it, per the spec's explicit requirement not to let a buried
  compliance problem (e.g. a covered-country sub-lot) get missed by a
  reviewer skimming a "not found" list. Every document still requires
  review regardless — this changes what the reviewer notices, not
  whether review happens.
- **Fallback**: if `ANTHROPIC_API_KEY` is unset or the API call fails for
  any reason, extraction falls back to the original regex extractor
  (`extractor.py`, unchanged) — but it can only ever produce **one**
  heat with no composition/sub-lot data, wrapped as explicitly
  `flagged_for_review`. Honest about what regex was never meant to
  do, rather than silently producing a clean-looking result. This is
  also what keeps `pytest` fully offline; no live API calls in the test
  suite.
- **Extraction accuracy tracking**: `document_heats.extraction_source`
  permanently records which path produced a heat (`llm`/`regex`) —
  separate from `source`, which reflects the *current* value owner and
  gets overwritten to `human` on review. `GET /admin/extraction-stats`
  (`platform_admin` only) reports flagged-rate and reviewed-count per
  extraction path. Simplified from the original flat-field version: with
  nested composition/sub-lot data, "did the reviewer change anything" is
  no longer a single yes/no per field, so this reports flagged-rate (a
  proxy for extraction difficulty) rather than an exact override diff —
  a documented simplification, not a silent scope cut.

### Sample fixtures + the regression/stretch bar

`backend/tests/fixtures/` — built with PyMuPDF, referenced by
`BUILD_SPEC.md` directly:

- `rio_grande_mtr_sample.pdf` — one clean heat, no sub-lots. The
  regression bar: must extract cleanly (heat id, composition, mass) on
  every change to the extraction pipeline.
- `rio_grande_mtr_complex.pdf` — three heats; one has a low-confidence
  "unconfirmed" sub-lot, another has a sub-lot from a covered country
  (China). The stretch target. **Without an API key**, the regex
  fallback (as documented above) only ever captures one flagged heat out
  of the three real ones — the correct, honest baseline to improve on
  once a real LLM key is exercised against it, not a bug.

### Credential issuance is per-heat

Each heat becomes its own issuable credential (`POST
/credentials/issue` takes `heat_id`, not `document_id`) — matches how
"heat" already functions as the batch/lot unit elsewhere, and means one
bad heat on a multi-heat certificate doesn't block or entangle the
others. A heat must be reviewed first, and can only be issued once
(`document_heats.credential_id` is 1:1). The credential's `subject` is
still a flat `{material_type, origin_country, mass_kg, ...}`, reviewer-
confirmed from the heat's richer data at issuance time — deliberately:
`passport.py`'s compliance checks read single scalar values, and making
them sub-lot-aware (a heat can genuinely blend multiple origin
countries) is explicitly a **later** item per the spec itself (4.4:
"generalize the graph walk... once mass-balance fields exist"). So
`passport.py`, `crypto_utils.py`, PDF export, and UII/scanning are all
unchanged by this — only extraction, review, and issuance-linkage are.

### Setting the API key

```bash
echo 'ANTHROPIC_API_KEY=sk-...' > backend/.env   # gitignored, never commit this
```

Loaded via `python-dotenv` at startup. Without it, uploads still work —
they just always take the regex-fallback path.

## Tamper-evidence check

`credentials.document_content_hash` snapshots the source document's
`content_hash` **at issuance time**, and is itself part of the signed
payload (`crypto_utils.credential_signable_payload`) — not just a DB
column that could be edited alongside a swapped file. The passport
compiler (`passport.py`) re-hashes the document's current object-store
bytes on every compile and compares it to what was actually signed. A
document edited after its credential was issued now fails the passport
with an explicit reason, rather than silently continuing to pass on
stale/tampered source material. Not yet wired: nothing currently *acts*
on a tamper failure beyond surfacing it (no automatic revocation).

## UII / Data Matrix + scanning

Every issued credential gets a `uii_bindings` row (spec section 3's
binding table) and a scannable MIL-STD-130-style Data Matrix code
(`backend/uii.py`, via `pystrich` — pure Python, no system dependencies).
Two simplifications from the full spec, both documented rather than
silently assumed:

- Every credential gets a UII, not just "part" credentials — the
  parts/products table (spec section 3) doesn't exist yet, and gating on
  a distinction that doesn't exist yet would be scope creep.
- The code encodes the **passport lookup URL** directly
  (`GET /credentials/{id}/uii/image`), not a formal DoD IUID string —
  that's its own numbering standard. Scanning it resolves straight to
  the passport view, which is the actual behavior the spec cares about.

`frontend/scan.html` resolves a scan via **device photo upload**, not a
live in-browser camera stream: `<input type="file" accept="image/*"
capture="environment">` opens the camera directly on a phone (or a file
picker on desktop), and decoding happens client-side via a vendored copy
of [ZXing](https://github.com/zxing-js/library)
(`frontend/vendor/zxing.min.js` — pulled via `npm install` and copied
in, not loaded from a CDN, to keep the frontend self-contained). The
photo is never sent to the server. Chosen over live camera streaming
both because it's better real-world UX (snap a photo of a part's label,
no fumbling a live viewfinder) and because it's actually verifiable
here — unlike a live camera feed, a static-image decode was tested
end-to-end with Playwright: a real generated Data Matrix resolves to its
passport correctly, and an image with no code shows a clean error
instead of hanging.

## PDF export

`GET /passport/{id}/pdf` (`backend/pdf_export.py`, via `reportlab`) —
same public, unauthenticated access as the existing JSON passport
endpoint, just a different rendering of the same data. Linked from
`passport.html` as "Download PDF report."

## Data model

SQLite (`backend/db.py`): `issuers` (doubles as the organizations table),
`documents` (`org_id`-scoped, `object_key`/`content_hash`,
`certificate_id`/`supplier_id`/`signatures_json`), `document_heats` (one
row per heat/melt on a certificate — composition, test results,
segregation, `extraction_source`/`source`, `flagged_for_review`,
`reviewed`, `credential_id` once issued), `heat_sublots` (one row per
feedstock sub-lot — origin, confidence, `flagged`), `credentials`
(graph-native via a `sources_json` array, not a single parent, with
`document_content_hash`), `uii_bindings`, `audit_log`, `users`,
`sessions`. `credentials` also carries `superseded_by` / `revoked_at` and
the segregation-attestation fields — added early because retrofitting
them later, once real credentials exist, is much more painful than
adding empty columns today.

## Running it

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

echo 'ANTHROPIC_API_KEY=sk-...' > .env   # optional — omit to use the regex fallback only
python seed.py                 # creates data/passport.db + Rio Grande Magnetics demo data + dev accounts
uvicorn main:app --reload      # http://localhost:8000

pytest                         # passport/auth/extraction logic, fully offline — no API calls, no server needed
```

Open `http://localhost:8000/login.html` and log in with the `org_user`
dev account above. `seed.py`'s demo credential was signed under a
legacy platform-held key (pre-dating client-side custody), which this
browser has no local private key for — visit `keys.html` first and
generate/register a new signing key for the org, then upload a document
and walk the upload → review → issue flow; issuance signs locally with
that browser-resident key. Open `http://localhost:8000/passport.html`
and look up the credential id printed by `seed.py` — no login needed —
to see a full passport compile.

## Not built yet

Deliberately out of scope for this pass — matches `BUILD_SPEC.md`
section 4 items not started. Not because they don't matter, but because
they either need a real design partner document, external
credentials/services, or are substantial standalone efforts:

- Real image-based OCR for scanned/photographed documents (Tesseract or
  a cloud OCR service — blocked on this environment having no package
  manager to install Tesseract; PyMuPDF's text-layer extraction covers
  digitally-generated PDFs only, see above)
- Sub-lot-aware compliance checking — a heat's sub-lot table is captured
  and flagged for human review, but the passport compiler still checks
  one flat `origin_country`/`material_type` per credential (the reviewer
  confirms these at issuance). Mass-balance/partial-quantity fields
  (spec section 3) need to exist first — explicitly a later item per the
  spec's own sequencing (4.4), not an oversight here.
- Parts/products table with stable part identity independent of which
  credential currently represents it (spec section 3) — every credential
  still gets a UII today regardless of this gap, see the UII section.
- Real W3C Verifiable Credentials library (currently raw Ed25519 —
  additive swap given the current payload shape)
- A formal MIL-STD-130 IUID numbering scheme (currently the Data Matrix
  encodes a passport URL, not a compliant IUID string)
- **Real S3 and Postgres — deliberately deferred, not blocked.** This is
  hosted locally for now; both are a "when this actually deploys
  somewhere with concurrent users" concern, not a local-dev one. SQLite
  handles moderate concurrent access fine, and `storage.py`'s narrow
  interface makes the S3 swap easy whenever it's actually needed. Site
  security (auth hardening, HTTPS enforcement, secrets management) is
  the real gate before shipping to any client — noted throughout this
  doc wherever it applies, not deferred to "later" vaguely.

CI (`.github/workflows/ci.yml`) is written and verified — full fresh-
environment simulation (install, lint, test) passes — but not yet
confirmed on a live GitHub Actions run since it hasn't been pushed.

Also out of scope per spec section 5: zero-knowledge proofs, PUF/NFC
hardware tags, FedRAMP/CMMC authorization, marketplace mechanics, ERP
push-integrations.

## Suggested next step

The synthetic sample PDFs get the extraction pipeline exercised end-to-
end, but they're still synthetic — per the spec's own build order, get
one *real* document from an actual candidate design partner through this
pipeline before investing further. It'll tell you how far off the
label-variant handling, composition parsing, and sub-lot table
assumptions actually are against a real certificate's real layout.
