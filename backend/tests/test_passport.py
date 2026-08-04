"""Tests for the passport compiler's pass / fail / insufficient_data logic.

Uses an in-memory SQLite connection built from the real schema and real
Ed25519 signing (keys written to a tmp dir) so these exercise the actual
signature-verification path, not a mock.
"""
import hashlib
import sqlite3
import uuid

import pytest

import crypto_utils
import passport as passport_engine
import storage
from db import SCHEMA
from seed import issue_credential

US_NDFEB_SUBJECT = {
    "material_type": "Sintered NdFeB Magnet Alloy (N42)",
    "origin_country": "United States",
    "mass_kg": 100.0,
    "heat_number": "TEST-0001",
    "supplier_name": "Test Issuer",
}


@pytest.fixture
def conn(tmp_path, monkeypatch):
    monkeypatch.setattr(crypto_utils, "KEYS_DIR", tmp_path / "keys")
    monkeypatch.setattr(storage, "OBJECTS_DIR", tmp_path / "objects")
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA)
    yield c
    c.close()


def make_issuer(conn, name="Test Issuer"):
    issuer_id = "issuer-" + name.replace(" ", "-").lower()
    public_key_b64, private_key_path = crypto_utils.generate_issuer_keypair(issuer_id)
    conn.execute(
        "INSERT INTO issuers (id, name, public_key, private_key_path, created_at) VALUES (?, ?, ?, ?, ?)",
        (issuer_id, name, public_key_b64, private_key_path, "2026-01-01T00:00:00Z"),
    )
    conn.commit()
    return issuer_id, private_key_path


def make_document(conn, org_id: str, raw_bytes: bytes = b"CERTIFICATE OF CONFORMANCE\nMaterial: NdFeB\n") -> str:
    document_id = uuid.uuid4().hex
    object_key = f"{document_id}/cert.txt"
    storage.save_object(object_key, raw_bytes)
    conn.execute(
        """
        INSERT INTO documents (id, org_id, filename, document_type, object_key, content_hash, raw_text, status, uploaded_at)
        VALUES (?, ?, 'cert.txt', 'mtr_coc', ?, ?, ?, 'extracted', '2026-01-01T00:00:00Z')
        """,
        (document_id, org_id, object_key, hashlib.sha256(raw_bytes).hexdigest(), raw_bytes.decode()),
    )
    conn.commit()
    return document_id


def make_reviewed_heat(conn, document_id: str) -> str:
    """A minimal already-reviewed heat for a document — credential
    issuance (seed.issue_credential / main.py's real route) links a
    credential to a document via a heat, not the document directly."""
    heat_id = uuid.uuid4().hex
    conn.execute(
        """
        INSERT INTO document_heats (id, document_id, reviewed, source, extraction_source)
        VALUES (?, ?, 1, 'human', 'regex')
        """,
        (heat_id, document_id),
    )
    conn.commit()
    return heat_id


def test_single_source_credential_passes(conn):
    issuer_id, key_path = make_issuer(conn)
    cred_id = issue_credential(
        conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, []
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "pass"
    assert len(result["nodes"]) == 1
    assert result["nodes"][0]["node_status"] == "pass"


def test_banned_origin_country_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    subject = {**US_NDFEB_SUBJECT, "origin_country": "China"}
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", subject, None, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "fail"
    assert any("FEOC-covered" in r for r in result["nodes"][0]["reasons"])


def test_out_of_scope_material_is_insufficient_data_not_fail(conn):
    issuer_id, key_path = make_issuer(conn)
    subject = {**US_NDFEB_SUBJECT, "material_type": "Lithium-ion battery cell"}
    cred_id = issue_credential(conn, issuer_id, key_path, "battery_cell", subject, None, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "insufficient_data"
    assert any("outside the DFARS rare-earth scope" in r for r in result["nodes"][0]["reasons"])


def test_multi_source_without_segregation_attestation_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    lot1 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    lot2 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    batch = issue_credential(
        conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [lot1, lot2]
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, batch)

    assert result["verdict"] == "fail"
    batch_node = next(n for n in result["nodes"] if n["credential_id"] == batch)
    assert any("segregation attestation" in r for r in batch_node["reasons"])


def test_multi_source_with_valid_segregation_attestation_passes(conn):
    issuer_id, key_path = make_issuer(conn)
    lot1 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    lot2 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    batch = issue_credential(
        conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [lot1, lot2],
        segregation_attested=True,
        segregation_attested_by="Maria Alvarez, QA Lead",
        segregation_note="Dedicated line, purged between runs.",
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, batch)

    assert result["verdict"] == "pass"


def test_segregation_boolean_alone_without_named_attestor_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    lot1 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    lot2 = issue_credential(conn, issuer_id, key_path, "collected_scrap_lot", US_NDFEB_SUBJECT, None, [])
    batch = issue_credential(
        conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [lot1, lot2],
        segregation_attested=True,
        segregation_attested_by=None,
        segregation_note=None,
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, batch)

    assert result["verdict"] == "fail"


def test_revoked_credential_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [])
    conn.commit()
    conn.execute("UPDATE credentials SET revoked_at = ? WHERE id = ?", ("2026-06-01T00:00:00Z", cred_id))
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    # Distinct from "fail" — revocation is an explicit retraction, not a
    # compliance check finding a problem with otherwise-live data. See
    # models.NodeStatus.
    assert result["verdict"] == "revoked"
    assert result["nodes"][0]["node_status"] == "revoked"
    assert any("revoked" in r for r in result["nodes"][0]["reasons"])


def test_tampered_payload_fails_signature_check(conn):
    issuer_id, key_path = make_issuer(conn)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [])
    conn.commit()
    # Simulate tampering: mutate the subject after signing without re-signing.
    conn.execute(
        "UPDATE credentials SET subject_json = ? WHERE id = ?",
        ('{"material_type": "Sintered NdFeB Magnet Alloy (N42)", "origin_country": "China"}', cred_id),
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "fail"
    assert any("signature does not verify" in r for r in result["nodes"][0]["reasons"])


def test_missing_referenced_credential_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    batch = issue_credential(
        conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, ["does-not-exist"]
    )
    conn.commit()

    result = passport_engine.compile_passport(conn, batch)

    assert result["verdict"] == "fail"
    missing_node = next(n for n in result["nodes"] if n["credential_id"] == "does-not-exist")
    assert "does not exist" in missing_node["reasons"][0]


def test_credential_with_untampered_document_passes(conn):
    issuer_id, key_path = make_issuer(conn)
    doc_id = make_document(conn, issuer_id)
    heat_id = make_reviewed_heat(conn, doc_id)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, heat_id, [])
    conn.commit()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "pass"


def test_swapped_document_bytes_fail_tamper_check(conn):
    issuer_id, key_path = make_issuer(conn)
    doc_id = make_document(conn, issuer_id)
    heat_id = make_reviewed_heat(conn, doc_id)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, heat_id, [])
    conn.commit()

    # Tamper: overwrite the stored object's bytes without touching the
    # signed credential row at all.
    object_key = conn.execute("SELECT object_key FROM documents WHERE id = ?", (doc_id,)).fetchone()["object_key"]
    storage.save_object(object_key, b"a completely different document")

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "fail"
    assert any("modified since this credential was signed" in r for r in result["nodes"][0]["reasons"])


def test_evaluate_node_never_fetches_private_key_path(conn):
    """_evaluate_node is reachable from the public, unauthenticated
    /passport/{id} and /passport/{id}/pdf endpoints and only needs
    issuers.public_key for signature verification. Regression guard: if
    its query is ever widened back to SELECT *, this catches it before
    private_key_path starts getting pulled into memory on every public
    passport lookup."""
    issuer_id, key_path = make_issuer(conn)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, None, [])
    conn.commit()

    captured_issuer_columns = []
    base_row_factory = conn.row_factory

    def recording_row_factory(cursor, row):
        cols = [d[0] for d in cursor.description]
        if "public_key" in cols:
            captured_issuer_columns.append(cols)
        return base_row_factory(cursor, row)

    conn.row_factory = recording_row_factory

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "pass"
    assert captured_issuer_columns, "expected the issuers table to be queried at least once"
    for cols in captured_issuer_columns:
        assert "private_key_path" not in cols, f"issuer query fetched private_key_path: {cols}"


def test_missing_document_object_fails(conn):
    issuer_id, key_path = make_issuer(conn)
    doc_id = make_document(conn, issuer_id)
    heat_id = make_reviewed_heat(conn, doc_id)
    cred_id = issue_credential(conn, issuer_id, key_path, "sintered_ndfeb_batch", US_NDFEB_SUBJECT, heat_id, [])
    conn.commit()

    object_key = conn.execute("SELECT object_key FROM documents WHERE id = ?", (doc_id,)).fetchone()["object_key"]
    (storage.OBJECTS_DIR / object_key).unlink()

    result = passport_engine.compile_passport(conn, cred_id)

    assert result["verdict"] == "fail"
    assert any("missing from storage" in r for r in result["nodes"][0]["reasons"])
