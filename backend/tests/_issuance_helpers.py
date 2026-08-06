"""Shared two-phase issuance helper for tests, post-Stage-3 cutover.

Every test that issues a credential over HTTP now needs a real,
registered signing key (the legacy platform-held key from Stage 1's
migration can't be used for *new* issuance — the whole point of the
hard cutover) and must sign the server-prepared bytes itself, mirroring
exactly what the browser will do in Stage 5. Leading underscore in the
filename so pytest doesn't try to collect this as a test module itself.
"""
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def make_issuer_key(conn, issuer_id: str, key_id: str = "test-key-1", registered_by: str = "test"):
    """Directly seeds a real (non-legacy) active issuer_keys row and
    returns (key_id, private_key) -- bypasses Stage 2's HTTP endpoint
    (platform_admin gate, step-up re-auth) on purpose, same spirit as
    make_issuer/make_user already inserting directly rather than going
    through /admin/users or a real onboarding flow. Assumes this is the
    issuer's first key (no prior active row to close out) -- true for
    every test issuer created via the usual make_issuer helpers, which
    never touch issuer_keys themselves."""
    private_key = Ed25519PrivateKey.generate()
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    conn.execute(
        """
        INSERT INTO issuer_keys (issuer_id, key_id, public_key, valid_from, valid_to, revoked_at, registered_by, created_at)
        VALUES (?, ?, ?, datetime('now'), NULL, NULL, ?, datetime('now'))
        """,
        (issuer_id, key_id, public_key_b64, registered_by),
    )
    conn.commit()
    return key_id, private_key


def make_issuer_key_synced_with_legacy_column(conn, issuer_id: str, key_id: str = "test-key-1", registered_by: str = "test"):
    """Same as make_issuer_key, but also overwrites issuers.public_key
    to match -- for test files whose subject is verdict/revocation
    semantics, not the key-custody transition itself.

    passport.py's verification (_evaluate_node) is unchanged until
    Stage 4: it checks a signature against issuers.public_key, not the
    issuer_keys row that actually signed it. That's a real, expected,
    temporary gap (see main.py's two-phase issuance docstrings) -- but
    a test suite about auto-revoke-on-correction and pass/revoked
    verdict transitions has no business being polluted by an unrelated
    transitional gap between two other stages. Keeping the two columns
    in sync here is a deliberate test-isolation choice, not a claim
    about production behavior: in production issuers.public_key stays
    frozen after Stage 1 forever, on purpose. Safe to fold back into
    plain make_issuer_key once Stage 4 ships and the two paths agree
    for real."""
    key_id, private_key = make_issuer_key(conn, issuer_id, key_id=key_id, registered_by=registered_by)
    public_key_b64 = base64.b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
    ).decode("ascii")
    conn.execute("UPDATE issuers SET public_key = ? WHERE id = ?", (public_key_b64, issuer_id))
    conn.commit()
    return key_id, private_key


def issue_via_api(client, private_key, key_id: str, **body):
    """prepare -> sign locally -> submit, matching exactly what
    Stage 5's browser flow will do. `body` is the same shape the old
    one-step /credentials/issue call used (credential_type, subject,
    heat_id, sources, segregation_*).

    If prepare itself fails (bad heat_id, open blocking flag, cross-org
    ownership, etc.) that response is returned as-is -- every check the
    old single endpoint used to do up front now lives in prepare, so a
    caller asserting on a specific failure status code still gets it
    from this one call, same as before the cutover.
    """
    prep = client.post("/credentials/issue/prepare", json=body)
    if prep.status_code != 200:
        return prep
    prep_body = prep.json()
    signable_bytes = base64.b64decode(prep_body["signable_bytes_b64"])
    signature_b64 = base64.b64encode(private_key.sign(signable_bytes)).decode("ascii")
    submit_body = {
        **body,
        "credential_id": prep_body["credential_id"],
        "issued_at": prep_body["issued_at"],
        "key_id": key_id,
        "signature_b64": signature_b64,
    }
    return client.post("/credentials/issue", json=submit_body)
