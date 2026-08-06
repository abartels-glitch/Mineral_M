"""Concurrency regression tests.

These fire genuinely simultaneous requests -- real OS threads,
real HTTP over loopback, real independent DB connections -- against a
real uvicorn subprocess, not FastAPI's TestClient against a single
shared in-memory connection. That distinction matters: the rest of this
suite's `conn` fixture is one sqlite3.Connection reused for every
request, which can't reproduce a race between two independent
connections the way production's per-request connection (db.get_db)
does. A subprocess bound to an isolated temp DB (via FEOC_DATA_DIR) is
the only way to exercise the actual locking/isolation behavior a real
deployment sees, matching the method used to find these four bugs live
against the dev server in the first place.

Each test proves a specific fix in main.py:
  - #3: issue_credential's conditional UPDATE claim on document_heats.credential_id
  - #2b/#2a: review_heat's compare-and-swap (reviewed=0 AND heat_id/mass_kg/flags_json match)
  - #1: correct_field's compare-and-swap-with-retry on flags_json
  - #4: _revoke_stale_credential's conditional UPDATE on revoked_at

Marked `slow` (see pyproject.toml) and excluded from the default `pytest`
run -- spinning up a real subprocess server adds ~20s on top of the rest
of the suite's ~70s, which isn't worth paying on every routine iteration.
Run explicitly with `pytest -m slow tests/test_concurrency.py`, or
`pytest -m ""` to run the whole suite including this file.
"""
import json
import os
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

from _issuance_helpers import issue_via_api

pytestmark = pytest.mark.slow

BACKEND_DIR = Path(__file__).resolve().parent.parent

MTR_TEXT = (
    "CERTIFICATE OF CONFORMANCE / MILL TEST REPORT\n"
    "Supplier: Rio Grande Magnetics, LLC\n"
    "Heat Number: {n}\n"
    "Material: Sintered NdFeB Magnet Alloy (N42)\n"
    "Country of Origin: United States\n"
    "Batch Mass: 50.0 kg\n"
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _bootstrap_org(data_dir: Path):
    """Creates the schema plus one issuer + one org_user + one real
    (non-legacy) active signing key directly via SQL, before the
    subprocess starts -- the same shape as the rest of the suite's
    make_issuer/make_user helpers, just against a real file DB instead
    of a shared in-memory one. Returns (key_id, private_key) so the
    tests driving the subprocess over HTTP can sign prepare's bytes
    themselves, exactly like Stage 5's browser will."""
    sys.path.insert(0, str(BACKEND_DIR))
    import base64

    import auth as auth_module
    import crypto_utils
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from db import SCHEMA

    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "passport.db"
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)

    orig_keys_dir = crypto_utils.KEYS_DIR
    crypto_utils.KEYS_DIR = data_dir / "keys"
    try:
        public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair("issuer-race-test")
    finally:
        crypto_utils.KEYS_DIR = orig_keys_dir

    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
        ("issuer-race-test", "Race Test Org", public_key_b64, private_key_path),
    )
    conn.execute(
        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, 'org_user', datetime('now'))",
        ("user-race-test", "issuer-race-test", "race@example.com", auth_module.hash_password("pw")),
    )

    key_id = "race-test-key-1"
    private_key = Ed25519PrivateKey.generate()
    signing_public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    conn.execute(
        """
        INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
        VALUES ('issuer-race-test', ?, ?, datetime('now'), NULL, NULL, 'test', datetime('now'))
        """,
        (key_id, signing_public_key_b64),
    )
    conn.commit()
    conn.close()
    return key_id, private_key


@pytest.fixture(scope="module")
def live_server(tmp_path_factory):
    """Yields (base_url, data_dir, key_id, private_key). data_dir is
    exposed so tests that need to seed state with no HTTP path (e.g.
    two independently open heat-level flags for the #1 CAS-retry test)
    can reach the same on-disk DB file the subprocess is serving,
    exactly as the live investigation did against the real dev DB.
    key_id/private_key are the real signing key _bootstrap_org seeded,
    needed by every test that issues a credential over HTTP."""
    data_dir = tmp_path_factory.mktemp("concurrency-data")
    key_id, private_key = _bootstrap_org(data_dir)
    port = _free_port()
    env = dict(os.environ)
    env["FEOC_DATA_DIR"] = str(data_dir)
    env.pop("ANTHROPIC_API_KEY", None)  # force the deterministic regex extractor
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=BACKEND_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                httpx.get(base_url, timeout=0.5)
                break
            except httpx.TransportError:
                time.sleep(0.1)
        else:
            proc.terminate()
            raise RuntimeError("live_server subprocess did not start in time")
        yield base_url, data_dir, key_id, private_key
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


@pytest.fixture
def client(live_server):
    base_url, _data_dir, _key_id, _private_key = live_server
    c = httpx.Client(base_url=base_url, timeout=10.0)
    r = c.post("/auth/login", json={"email": "race@example.com", "password": "pw"})
    assert r.status_code == 200, r.text
    return c


@pytest.fixture
def signing_key(live_server):
    """(key_id, private_key) for the one real signing key _bootstrap_org
    seeded -- every test that issues a credential over HTTP needs this
    now, same cutover as everywhere else in the suite."""
    _base_url, _data_dir, key_id, private_key = live_server
    return key_id, private_key


def _db_conn(live_server) -> sqlite3.Connection:
    _base_url, data_dir, _key_id, _private_key = live_server
    conn = sqlite3.connect(data_dir / "passport.db")
    conn.row_factory = sqlite3.Row
    return conn


def _upload(client, n):
    r = client.post(
        "/documents/upload",
        files={"file": (f"{n}.txt", MTR_TEXT.format(n=n).encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    return body["id"], body["heats"][0]["id"]


def _upload_review(client, n):
    doc_id, heat_id = _upload(client, n)
    r = client.post(
        f"/documents/{doc_id}/heats/{heat_id}/review",
        json={
            "heat_id": n,
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    assert r.status_code == 200, r.text
    return doc_id, heat_id


def _upload_review_issue(client, n, key_id, private_key):
    doc_id, heat_id = _upload_review(client, n)
    r = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        heat_id=heat_id,
        subject={
            "material_type": "Sintered NdFeB Magnet Alloy (N42)",
            "origin_country": "United States",
            "mass_kg": 50.0,
            "heat_number": n,
        },
        sources=[],
    )
    assert r.status_code == 200, r.text
    return doc_id, heat_id, r.json()["id"]


def _fire_concurrent(fns):
    n = len(fns)
    barrier = threading.Barrier(n)
    results = [None] * n

    def run(i, fn):
        barrier.wait()
        results[i] = fn()

    threads = [threading.Thread(target=run, args=(i, fn)) for i, fn in enumerate(fns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


# --- #3: two concurrent /credentials/issue from the same heat ---------------


def test_concurrent_credential_issue_only_one_wins(client, signing_key):
    key_id, private_key = signing_key
    doc_id, heat_id = _upload_review(client, "issue-race-" + str(id(client)))

    def issue(tag):
        return issue_via_api(
            client, private_key, key_id,
            credential_type="collected_scrap_lot",
            heat_id=heat_id,
            subject={
                "material_type": "Sintered NdFeB Magnet Alloy (N42)",
                "origin_country": "United States",
                "mass_kg": 50.0,
                "heat_number": tag,
            },
            sources=[],
        )

    # Fire enough concurrent attempts that the (narrow, timing-dependent)
    # race window from the live investigation is very likely hit at
    # least once even under CI scheduling jitter.
    results = _fire_concurrent([lambda: issue("A"), lambda: issue("B"), lambda: issue("C"), lambda: issue("D")])
    statuses = [r.status_code for r in results]
    successes = [r for r in results if r.status_code == 200]
    conflicts = [r for r in results if r.status_code == 409]

    assert len(successes) == 1, f"expected exactly one issuance to win, got statuses {statuses}"
    assert len(conflicts) == len(results) - 1, f"expected the rest to be rejected with 409, got {statuses}"

    winner_id = successes[0].json()["id"]
    heat_resp = client.get(f"/documents/{doc_id}").json()
    heat = next(h for h in heat_resp["heats"] if h["id"] == heat_id)
    assert heat["credential_id"] == winner_id


# --- #2b: two concurrent /review submissions on the same unreviewed heat ----


def test_concurrent_double_review_only_one_wins(client):
    doc_id, heat_id = _upload(client, "review-race-" + str(id(client)))

    def review(tag):
        return client.post(
            f"/documents/{doc_id}/heats/{heat_id}/review",
            json={
                "heat_id": f"REVIEW-{tag}",
                "mass_kg": 50.0,
                "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
            },
        )

    results = _fire_concurrent([lambda: review("A"), lambda: review("B")])
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 409], f"expected exactly one review to win and one to 409, got {statuses}"

    heat = client.get(f"/documents/{doc_id}").json()["heats"][0]
    assert heat["reviewed"] is True
    assert heat["heat_id"] in ("REVIEW-A", "REVIEW-B")  # whichever won, cleanly -- not a mix of both


# --- #2a: /correct racing /review's stale payload ----------------------------


def test_concurrent_correct_vs_review_correction_survives(client):
    doc_id, heat_id = _upload(client, "correct-vs-review-" + str(id(client)))

    def correct():
        return client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "heat_id", "corrected_value": "CORRECTED-BY-A"},
        )

    def review():
        # A stale payload: as if this reviewer's form was populated
        # before the concurrent correction above landed.
        return client.post(
            f"/documents/{doc_id}/heats/{heat_id}/review",
            json={
                "heat_id": "STALE-VALUE-FROM-B-FORM",
                "mass_kg": 50.0,
                "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
            },
        )

    results = _fire_concurrent([correct, review])
    correct_resp, review_resp = results
    assert correct_resp.status_code == 200, correct_resp.text

    heat = client.get(f"/documents/{doc_id}").json()["heats"][0]
    if review_resp.status_code == 200:
        # Review lost the CAS race entirely (didn't even see the
        # correction's committed state) -- fine, as long as it didn't
        # silently win and clobber the correction.
        assert heat["heat_id"] == "CORRECTED-BY-A", (
            f"review overwrote a concurrent correction's value: {heat['heat_id']!r}"
        )
    else:
        # Review lost the race honestly (409) -- the correction must
        # have survived.
        assert review_resp.status_code == 409, review_resp.text
        assert heat["heat_id"] == "CORRECTED-BY-A"


# --- #1: two /correct calls on different fields of the same heat ------------


def test_concurrent_corrections_on_different_fields_both_resolve_their_flag(client, live_server):
    doc_id, heat_id = _upload(client, "cas-retry-" + str(id(client)))

    # No HTTP path manufactures two independently open heat-level flags
    # on demand, so seed them directly in the DB the subprocess is
    # serving -- the same technique used during the live investigation
    # against the real dev DB.
    seeded_flags = [
        {
            "issue_type": "missing_field", "field_name": "heat_id", "severity": "needs_review",
            "human_readable_reason": "seeded for concurrency test", "source": "extraction", "status": "open",
        },
        {
            "issue_type": "missing_field", "field_name": "mass_kg", "severity": "needs_review",
            "human_readable_reason": "seeded for concurrency test", "source": "extraction", "status": "open",
        },
    ]
    conn = _db_conn(live_server)
    conn.execute(
        "UPDATE document_heats SET flags_json = ?, flagged_for_review = 1 WHERE id = ?",
        (json.dumps(seeded_flags), heat_id),
    )
    conn.commit()
    conn.close()

    results = _fire_concurrent([
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "heat_id", "corrected_value": "CONCURRENT-HEAT-ID"},
        ),
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "mass_kg", "corrected_value": "77.7"},
        ),
    ])
    for r in results:
        assert r.status_code == 200, r.text  # neither caller should ever see an error for this

    heat = client.get(f"/documents/{doc_id}").json()["heats"][0]
    assert heat["heat_id"] == "CONCURRENT-HEAT-ID"
    assert heat["mass_kg"] == 77.7
    flags_by_field = {f["field_name"]: f["status"] for f in heat["flags"]}
    assert flags_by_field == {"heat_id": "resolved", "mass_kg": "resolved"}, (
        f"one correction's flag resolution was lost to the other: {flags_by_field}"
    )


def test_concurrent_object_and_scalar_field_corrections_both_resolve_their_flag(client, live_server):
    """Same CAS-with-retry mechanism as the scalar-only case above, now
    exercising one of the two object-typed fields (alloy_composition) --
    confirms the dict-correction path added for the sub-form feature
    reuses the existing atomicity guarantee rather than a second, weaker
    code path, exactly as intended when it was designed."""
    doc_id, heat_id = _upload(client, "cas-retry-object-" + str(id(client)))

    seeded_flags = [
        {
            "issue_type": "ambiguous_field", "field_name": "alloy_composition", "severity": "needs_review",
            "human_readable_reason": "seeded for concurrency test", "source": "extraction", "status": "open",
        },
        {
            "issue_type": "missing_field", "field_name": "mass_kg", "severity": "needs_review",
            "human_readable_reason": "seeded for concurrency test", "source": "extraction", "status": "open",
        },
    ]
    conn = _db_conn(live_server)
    conn.execute(
        "UPDATE document_heats SET flags_json = ?, flagged_for_review = 1 WHERE id = ?",
        (json.dumps(seeded_flags), heat_id),
    )
    conn.commit()
    conn.close()

    corrected_composition = {"Nd": 29.5, "Fe": 68.2, "B": 1.0}
    results = _fire_concurrent([
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "alloy_composition", "corrected_value": corrected_composition},
        ),
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "mass_kg", "corrected_value": "77.7"},
        ),
    ])
    for r in results:
        assert r.status_code == 200, r.text

    heat = client.get(f"/documents/{doc_id}").json()["heats"][0]
    assert heat["alloy_composition"] == corrected_composition
    assert heat["mass_kg"] == 77.7
    flags_by_field = {f["field_name"]: f["status"] for f in heat["flags"]}
    assert flags_by_field == {"alloy_composition": "resolved", "mass_kg": "resolved"}, (
        f"one correction's flag resolution was lost to the other: {flags_by_field}"
    )
    assert heat["flagged_for_review"] is False


# --- #4: correction-triggered auto-revoke racing another correction ---------


def test_concurrent_corrections_revoke_credential_exactly_once(client, live_server, signing_key):
    key_id, private_key = signing_key
    doc_id, heat_id, cred_id = _upload_review_issue(client, "revoke-race-" + str(id(client)), key_id, private_key)

    results = _fire_concurrent([
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "heat_id", "corrected_value": "POST-ISSUE-A"},
        ),
        lambda: client.post(
            f"/documents/{doc_id}/heats/{heat_id}/correct",
            json={"target": "heat", "field_name": "mass_kg", "corrected_value": "99.9"},
        ),
    ])
    for r in results:
        assert r.status_code == 200, r.text

    conn = _db_conn(live_server)
    cred = conn.execute("SELECT revoked_at FROM credentials WHERE id = ?", (cred_id,)).fetchone()
    assert cred["revoked_at"] is not None

    revoke_audits = conn.execute(
        "SELECT id FROM audit_log WHERE entity_type = 'credential' AND entity_id = ? AND action = 'revoked'",
        (cred_id,),
    ).fetchall()
    assert len(revoke_audits) == 1, f"expected exactly one 'revoked' audit entry, got {len(revoke_audits)}"
    conn.close()

    passport = client.get(f"/passport/{cred_id}").json()
    assert passport["verdict"] == "revoked"
