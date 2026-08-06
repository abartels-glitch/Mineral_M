"""Ed25519 signing for credentials.

Placeholder for a real W3C Verifiable Credentials library (Veramo,
did-jwt-vc) per spec section 4.3 — the credential schema (subject_json /
sources_json / signature / payload_hash) is written so that swap is
additive, not a rewrite.

Key custody: as of the client-side key custody + versioned keys
redesign, new issuer keys are generated in the org's own browser via
Web Crypto (non-extractable Ed25519 private key, never leaves the
browser) and registered via POST /issuers/{id}/keys — see main.py and
db.py's issuer_keys table. generate_issuer_keypair/sign_payload below
are frozen, not removed: they're what every pre-existing (legacy,
platform-held) credential was actually signed with, and
db._migrate_issuer_keys backfills exactly one such key per issuer as
key_id='legacy-platform-held'. Nothing new calls them going forward.
"""
import base64
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from db import DATA_DIR

KEYS_DIR = DATA_DIR / "keys"


def canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_issuer_keypair(issuer_id: str) -> tuple[str, str]:
    """Create and persist a new keypair for an issuer. Returns (public_key_b64, private_key_path)."""
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    private_key_path = KEYS_DIR / f"{issuer_id}.pem"
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_key_b64 = base64.b64encode(public_bytes).decode("ascii")
    return public_key_b64, str(private_key_path)


def _load_private_key(private_key_path: str) -> Ed25519PrivateKey:
    pem_bytes = Path(private_key_path).read_bytes()
    return serialization.load_pem_private_key(pem_bytes, password=None)


def sign_payload(private_key_path: str, payload: dict) -> tuple[str, str]:
    """Sign a payload. Returns (signature_b64, payload_hash_hex)."""
    import hashlib

    private_key = _load_private_key(private_key_path)
    data = canonical_bytes(payload)
    signature = private_key.sign(data)
    payload_hash = hashlib.sha256(data).hexdigest()
    return base64.b64encode(signature).decode("ascii"), payload_hash


def credential_signable_payload(
    *,
    id: str,
    issuer_id: str,
    credential_type: str,
    subject: dict,
    sources: list[str],
    segregation_attested: bool,
    segregation_attested_by: str | None,
    segregation_note: str | None,
    document_id: str | None,
    document_content_hash: str | None,
    issued_at: str,
) -> dict:
    """The exact fields a credential signs over. Shared between issuance
    (main.py) and verification (passport.py) so they never drift apart.

    `document_content_hash` is a snapshot of the source document's hash
    at issuance time — signing it (not just storing it) is what makes
    the passport compiler's tamper-evidence check meaningful: a swapped
    document AND an edited DB row still can't match a hash that's inside
    the signed payload.
    """
    return {
        "id": id,
        "issuer_id": issuer_id,
        "credential_type": credential_type,
        "subject": subject,
        "sources": sources,
        "segregation_attested": segregation_attested,
        "segregation_attested_by": segregation_attested_by,
        "segregation_note": segregation_note,
        "document_id": document_id,
        "document_content_hash": document_content_hash,
        "issued_at": issued_at,
    }


def verify_signature(public_key_b64: str, payload: dict, signature_b64: str) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
        public_key.verify(base64.b64decode(signature_b64), canonical_bytes(payload))
        return True
    except (InvalidSignature, ValueError):
        return False


def validate_raw_ed25519_public_key(public_key_b64: str) -> None:
    """Raises ValueError if public_key_b64 doesn't decode to a valid
    32-byte Ed25519 public key point. Used at key-registration time to
    reject a malformed browser-submitted key before it's ever stored —
    SubtleCrypto's "raw" export format is exactly the bare 32-byte
    RFC 8032 point per the WebCrypto Secure Curves spec, the same
    encoding this module already uses for platform-generated keys, so
    no format conversion is needed, only validation.
    `base64.b64decode(..., validate=True)` raises binascii.Error (a
    ValueError subclass) on malformed base64; from_public_bytes raises
    ValueError on the wrong byte length.
    """
    raw_bytes = base64.b64decode(public_key_b64, validate=True)
    Ed25519PublicKey.from_public_bytes(raw_bytes)
