"""Standing security regression: every route that reads or writes a
document, heat, or credential by id must either reject a second org's
session, or be an explicitly-documented public exception.

This exists because three separate org-isolation gaps were found in
this codebase by manual, one-off audits (a document-level bug fixed
earlier, then GET /credentials and /credentials/issue's sources[] found
in the same session) rather than by anything that runs in CI. The
pattern was always the same: a route fetched a row by id and either
forgot the ownership check or hand-rolled a one-off copy of it. See
main.py's "ownership helpers" section (owned_*/require_owned_*).

Rather than trust the next manual audit to catch the next gap, this
file does two things:

1. `test_every_parameterized_route_has_sweep_coverage` walks the live
   FastAPI route table (main.app.routes) and fails if any route with a
   path parameter isn't represented in SWEPT_ROUTES below — so a future
   route can't silently ship without a decision being made here about
   whether it needs org isolation.
2. `test_swept_route_is_org_isolated_or_intentionally_public` actually
   exercises every one of those routes against a second, unrelated org
   (or, for the public ones, with no session at all) and asserts the
   correct outcome.

sources[] (POST /credentials/issue) and GET /credentials are id-bearing
but the ids don't live in the URL path, so they can't be found by route
introspection — they're covered by their own dedicated tests below
instead, using the exact live-exploit shape (a second org attempting
exactly what was proven live against the dev server).
"""
import re
import sqlite3

import pytest
from fastapi.testclient import TestClient

import auth
import crypto_utils
import main
import storage
from _issuance_helpers import issue_via_api, make_issuer_key
from db import SCHEMA

MTR_TEXT = (
    "CERTIFICATE OF CONFORMANCE / MILL TEST REPORT\n"
    "Supplier: Test Recycler, LLC\n"
    "Heat Number: TR-0001\n"
    "Material: Sintered NdFeB Magnet Alloy (N42)\n"
    "Country of Origin: United States\n"
    "Batch Mass: 50.0 kg\n"
)


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(storage, "OBJECTS_DIR", tmp_path / "objects")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    c = sqlite3.connect(":memory:", check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    c.executescript(SCHEMA)
    yield c
    c.close()


@pytest.fixture
def client(conn):
    def override_get_db():
        yield conn

    main.app.dependency_overrides[main.get_db] = override_get_db
    yield TestClient(main.app)
    main.app.dependency_overrides.clear()


def make_issuer(conn, name):
    issuer_id = "issuer-" + name.lower().replace(" ", "-")
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, name, public_key_b64, private_key_path, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return issuer_id


def make_user(conn, email, password, role, org_id=None):
    user_id = "user-" + email.split("@")[0]
    conn.execute(
        "INSERT INTO users (id, org_id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, org_id, email, auth.hash_password(password), role, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return user_id


def _seed_org_a(client, conn):
    """A real, fully-issued credential graph for 'Org A' — upload,
    review, and issue via the actual HTTP routes, exactly the shape a
    live exploit would target. Logs out afterward so callers control
    whose session is active. Returns real ids: document_id, heat_id,
    credential_id."""
    org_a = make_issuer(conn, "Org A")
    make_user(conn, "a@example.com", "pw", "org_user", org_a)
    client.post("/auth/login", json={"email": "a@example.com", "password": "pw"})
    key_id, private_key = make_issuer_key(conn, org_a)

    upload = client.post(
        "/documents/upload",
        files={"file": ("mtr.txt", MTR_TEXT.encode(), "text/plain")},
        data={"document_type": "mtr_coc"},
    ).json()
    document_id = upload["id"]
    heat_id = upload["heats"][0]["id"]

    client.post(
        f"/documents/{document_id}/heats/{heat_id}/review",
        json={
            "heat_id": "TR-0001",
            "mass_kg": 50.0,
            "sublots": [{"origin_country": "United States", "origin_confidence": "high", "blend_pct": 100.0}],
        },
    )
    issued = issue_via_api(
        client, private_key, key_id,
        credential_type="collected_scrap_lot",
        heat_id=heat_id,
        subject={
            "material_type": "Sintered NdFeB Magnet Alloy (N42)",
            "origin_country": "United States",
            "mass_kg": 50.0,
            "heat_number": "TR-0001",
        },
        sources=[],
    )
    assert issued.status_code == 200, issued.text
    credential_id = issued.json()["id"]

    # A real (unconsumed) invite for org_a, seeded directly -- same
    # bypass-the-HTTP-endpoint spirit as make_issuer_key above, since the
    # point here is a token to exercise GET/POST /invite/{token}*
    # against, not proving POST /admin/invites itself (that's covered in
    # test_org_invites.py).
    invite_token = "sweep-test-invite-token"
    conn.execute(
        """
        INSERT INTO org_invites (id, org_id, email, role, token_hash, invited_by, created_at, expires_at)
        VALUES ('sweep-invite', ?, 'invitee@example.com', 'org_user', ?, 'admin@example.com',
                '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')
        """,
        (org_a, auth.hash_invite_token(invite_token)),
    )
    conn.commit()

    client.post("/auth/logout")
    return {
        "document_id": document_id,
        "heat_id": heat_id,
        "credential_id": credential_id,
        "issuer_id": org_a,
        "invite_token": invite_token,
    }


def _login_org_b(client, conn):
    org_b = make_issuer(conn, "Org B")
    make_user(conn, "b@example.com", "pw", "org_user", org_b)
    client.post("/auth/login", json={"email": "b@example.com", "password": "pw"})
    return org_b


# --- route registry -----------------------------------------------------
#
# Every entry maps a live (method, path-template) pair to how to call it
# and what a second org should get. "org_blocked" is called as org_b and
# must 403. "public" is called with no session at all (the real shape of
# a passport/scan lookup) and must succeed.

SWEPT_ROUTES = {
    ("GET", "/documents/{document_id}"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.get(f"/documents/{ids['document_id']}"),
    },
    ("POST", "/documents/{document_id}/heats/{heat_id}/review"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.post(
            f"/documents/{ids['document_id']}/heats/{ids['heat_id']}/review",
            json={"sublots": []},
        ),
    },
    ("POST", "/documents/{document_id}/heats/{heat_id}/correct"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.post(
            f"/documents/{ids['document_id']}/heats/{ids['heat_id']}/correct",
            json={"target": "heat", "field_name": "heat_id", "corrected_value": "HACKED"},
        ),
    },
    ("GET", "/documents/{document_id}/heats/{heat_id}/audit-trail"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.get(
            f"/documents/{ids['document_id']}/heats/{ids['heat_id']}/audit-trail"
        ),
    },
    ("GET", "/credentials/{credential_id}/audit-trail"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.get(f"/credentials/{ids['credential_id']}/audit-trail"),
    },
    ("GET", "/credentials/{credential_id}/uii"): {
        "expect": "public",
        "call": lambda client, ids: client.get(f"/credentials/{ids['credential_id']}/uii"),
    },
    ("GET", "/credentials/{credential_id}/uii/image"): {
        "expect": "public",
        "call": lambda client, ids: client.get(f"/credentials/{ids['credential_id']}/uii/image"),
    },
    ("GET", "/passport/{lookup_key}"): {
        "expect": "public",
        "call": lambda client, ids: client.get(f"/passport/{ids['credential_id']}"),
    },
    ("GET", "/passport/{lookup_key}/pdf"): {
        "expect": "public",
        "call": lambda client, ids: client.get(f"/passport/{ids['credential_id']}/pdf"),
    },
    # require_org_match rejects org B before the password/key-format
    # checks are ever reached, so a placeholder password/key here is
    # fine -- the point is confirming org B can't even get that far
    # against org A's issuer_id.
    ("POST", "/issuers/{issuer_id}/keys"): {
        "expect": "org_blocked",
        "call": lambda client, ids: client.post(
            f"/issuers/{ids['issuer_id']}/keys",
            json={"public_key": "irrelevant-blocked-before-validation", "password": "pw"},
        ),
    },
    # Deliberately public/pre-auth: the whole point of an invite link is
    # that the invitee has no session yet. What actually gates access
    # here is possession of the unguessable token, not org membership —
    # see test_org_invites.py for the single-use/expiry/wrong-org
    # coverage that's the real security boundary for this feature.
    ("GET", "/invite/{token}"): {
        "expect": "public",
        "call": lambda client, ids: client.get(f"/invite/{ids['invite_token']}"),
    },
    ("POST", "/invite/{token}/accept"): {
        "expect": "public",
        "call": lambda client, ids: client.post(
            f"/invite/{ids['invite_token']}/accept", json={"password": "a-real-password"}
        ),
    },
}


def _live_parameterized_routes():
    found = set()
    for route in main.app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", None)
        if not methods or not path:
            continue  # e.g. the mounted StaticFiles app, which has neither
        if not re.search(r"{\w+}", path):
            continue
        for method in methods - {"HEAD", "OPTIONS"}:
            found.add((method, path))
    return found


def test_every_parameterized_route_has_sweep_coverage():
    live = _live_parameterized_routes()
    missing = live - set(SWEPT_ROUTES)
    assert not missing, (
        f"Route(s) with a path-parameter id have no cross-org sweep coverage: {sorted(missing)}. "
        "Add an entry to SWEPT_ROUTES in tests/test_org_isolation_sweep.py — either exercising "
        "the org-block case (the route should use owned_*/require_owned_* from main.py) or "
        "explicitly marking it 'public' if it's deliberately unauthenticated, matching the "
        "'# --- passport (public) ---' section in main.py."
    )
    stale = set(SWEPT_ROUTES) - live
    assert not stale, f"SWEPT_ROUTES references route(s) that no longer exist: {sorted(stale)}"


@pytest.mark.parametrize("route_key", sorted(SWEPT_ROUTES))
def test_swept_route_is_org_isolated_or_intentionally_public(route_key, client, conn):
    entry = SWEPT_ROUTES[route_key]
    ids = _seed_org_a(client, conn)  # logs out after seeding
    if entry["expect"] == "public":
        resp = entry["call"](client, ids)
        assert resp.status_code == 200, (
            f"{route_key} is marked intentionally public but returned {resp.status_code}: {resp.text}"
        )
    else:
        _login_org_b(client, conn)
        resp = entry["call"](client, ids)
        assert resp.status_code == 403, (
            f"{route_key} should reject a different org's session with 403, got {resp.status_code}: {resp.text}"
        )


# --- id-bearing routes/fields that aren't URL path parameters -----------
#
# Route introspection can't find these: GET /credentials has no id in
# its path at all (it's a list, scoped by filtering), and
# /credentials/issue's sources[] id lives inside the JSON body as an
# array. Both are the exact two gaps this fix closes — covered here
# with the same live-exploit shape used to prove them against the real
# dev server (a second org, zero credentials of its own, targeting
# Org A's real credential id).


def test_credentials_list_is_org_scoped(client, conn):
    ids = _seed_org_a(client, conn)
    _login_org_b(client, conn)

    resp = client.get("/credentials")
    assert resp.status_code == 200
    visible_ids = {c["id"] for c in resp.json()}
    assert ids["credential_id"] not in visible_ids
    assert visible_ids == set()


def test_credentials_list_shows_admin_and_auditor_everything(client, conn):
    ids = _seed_org_a(client, conn)
    make_user(conn, "admin@example.com", "pw", "platform_admin")
    make_user(conn, "auditor@example.com", "pw", "buyer_auditor")

    for email in ("admin@example.com", "auditor@example.com"):
        client.post("/auth/login", json={"email": email, "password": "pw"})
        resp = client.get("/credentials")
        assert resp.status_code == 200
        visible_ids = {c["id"] for c in resp.json()}
        assert ids["credential_id"] in visible_ids
        client.post("/auth/logout")


def test_credential_issue_rejects_cross_org_source(client, conn):
    """sources[] previously only checked that each id existed, never
    who owned it — letting one org issue a signed credential citing
    another org's real credential as a parent with no consent. This is
    exactly what was proven live against the dev server.

    Calls /credentials/issue/prepare, not /credentials/issue — since
    the two-phase cutover, this ownership check runs in prepare (no
    signature exists yet to check anything against); submit re-runs
    the identical check via the same shared _validate_issuance_request,
    so this still covers the real enforcement point, not a bypassed one."""
    ids = _seed_org_a(client, conn)
    _login_org_b(client, conn)

    resp = client.post(
        "/credentials/issue/prepare",
        json={
            "credential_type": "sintered_ndfeb_batch",
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [ids["credential_id"]],
        },
    )
    assert resp.status_code == 403


def test_credential_issue_rejects_cross_org_heat_id(client, conn):
    """The heat_id check already worked (hand-rolled) before this fix;
    this locks in that it still works now that it's routed through the
    shared require_owned_heat_by_id instead of a one-off inline check.
    Calls prepare, see test_credential_issue_rejects_cross_org_source
    above for why."""
    ids = _seed_org_a(client, conn)
    _login_org_b(client, conn)

    resp = client.post(
        "/credentials/issue/prepare",
        json={
            "credential_type": "collected_scrap_lot",
            "heat_id": ids["heat_id"],
            "subject": {"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "United States"},
            "sources": [],
        },
    )
    assert resp.status_code == 403
