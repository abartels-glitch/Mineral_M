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
| **Key custody** | Platform holds issuer private keys — one Ed25519 keypair per organization, unencrypted PEM under `data/keys/` | Move to supplier-held keys or HSM-backed platform custody before handling real supplier trust relationships |
| **Document scope** | One document type: certificate of conformance / MTR (heat number, alloy composition, country-of-origin declaration, supplier ID) | Add document types once the first one is proven against a real sample |
| **Segregation enforcement** | Self-reported, but with a floor: `segregation_attested` (bool) + `segregation_attested_by` (named person) + `segregation_note` (control description). No third-party evidence yet. | Add evidence upload (photos, process logs) and eventually third-party audit |
| **Materials scope** | Compliance engine only checks the actual DFARS rare-earth scope: samarium-cobalt magnets, NdFeB magnets, tantalum, tungsten. Anything else yields `insufficient_data`, not a silent pass. | Don't let product language ("motors, batteries, ESCs") outrun this without extending the engine first |

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

## Document ingestion: object storage + two-step OCR/LLM extraction

Real file storage and real structuring, replacing the original
naive-UTF-8-decode-plus-regex placeholder.

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
  goes to Claude (`claude-haiku-4-5-20251001`) via forced tool-use for
  reliable structured output — same five fields as before, now with a
  real per-field confidence score from the model instead of a fixed
  placeholder. Chosen as two separate steps rather than one "LLM reads
  the PDF directly" call specifically so there's a raw, non-LLM-derived
  text artifact to check the model's structured output against — an
  auditability property, not just extra plumbing.
- **Confidence threshold**: fields below `0.7` render as "low
  confidence — review carefully" (amber) in the reviewer UI instead of
  looking identical to a clean extraction. Every document still requires
  review regardless of confidence — this changes what the reviewer
  notices, not whether review happens.
- **Fallback**: if `ANTHROPIC_API_KEY` is unset or the API call fails for
  any reason, extraction falls back to the original regex extractor —
  logged, not silent, and uploads never 500 because of it. This is also
  what keeps `pytest` fully offline; no live API calls in the test suite.
- **Extraction accuracy tracking**: `extracted_fields.extraction_source`
  permanently records which path produced a field (`llm`/`regex`/`human`
  for reviewer-added fields) — separate from the `source` column, which
  reflects the *current* value owner and gets overwritten to `human` on
  every review. `GET /admin/extraction-stats` (`platform_admin` only)
  aggregates override rate overall and per field — the spec's "track how
  often humans override the model" bullet, built on data the schema
  already captured rather than new tracking machinery.

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

`frontend/scan.html` does camera-based scanning via a vendored copy of
[ZXing](https://github.com/zxing-js/library) (`frontend/vendor/zxing.min.js`
— pulled via `npm install` and copied in, not loaded from a CDN, to keep
the frontend self-contained like the rest of it). **This has not been
tested against a live camera in this environment** — no camera hardware
here. It's built against ZXing's documented `BrowserMultiFormatReader`
API; verify it yourself with a real device before relying on it.

## PDF export

`GET /passport/{id}/pdf` (`backend/pdf_export.py`, via `reportlab`) —
same public, unauthenticated access as the existing JSON passport
endpoint, just a different rendering of the same data. Linked from
`passport.html` as "Download PDF report."

## Data model

SQLite (`backend/db.py`): `issuers` (doubles as the organizations table),
`documents` (`org_id`-scoped, now with `object_key`/`content_hash`),
`extracted_fields` (with `extraction_source`, see above), `credentials`
(graph-native via a `sources_json` array, not a single parent, now with
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
dev account above to upload a document and walk the upload → review →
issue flow. Open `http://localhost:8000/passport.html` and look up the
credential id printed by `seed.py` — no login needed — to see a full
passport compile.

## Not built yet

Deliberately out of scope for this pass — matches `BUILD_SPEC.md`
section 4 items not started. Not because they don't matter, but because
they either need a real design partner document, external
credentials/services, or are substantial standalone efforts:

- Real image-based OCR for scanned/photographed documents (Tesseract or
  a cloud OCR service — blocked on this environment having no package
  manager to install Tesseract; PyMuPDF's text-layer extraction covers
  digitally-generated PDFs only, see above)
- Real W3C Verifiable Credentials library (currently raw Ed25519 —
  additive swap given the current payload shape)
- Live-camera testing of `scan.html` (see UII section above — no camera
  hardware in this environment)
- A formal MIL-STD-130 IUID numbering scheme (currently the Data Matrix
  encodes a passport URL, not a compliant IUID string)
- Real S3 (currently local-filesystem `storage.py`) + Postgres + CI

Also out of scope per spec section 5: zero-knowledge proofs, PUF/NFC
hardware tags, FedRAMP/CMMC authorization, marketplace mechanics, ERP
push-integrations.

## Suggested next step

Per the spec's own build order: get one *real* document from an actual
candidate design partner through this extraction pipeline, even with the
regex placeholder, before investing further — it'll tell you how far off
the field patterns and schema assumptions are.
