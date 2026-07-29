"""UII / Data Matrix generation.

Placeholder for a fully MIL-STD-130-compliant IUID numbering scheme —
that's its own standard. Here `uii_code` is simply the credential id, and
the Data Matrix encodes the passport lookup URL directly, so a scan
resolves straight to the passport view (the actual behavior the spec
cares about) without a separate app to decode a formal IUID string first.
"""
from pystrich.datamatrix import DataMatrixEncoder


def generate_datamatrix_png(payload: str) -> bytes:
    return DataMatrixEncoder(payload).get_imagedata()
