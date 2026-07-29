"""PDF text-layer extraction.

IMPORTANT LIMITATION: this reads a PDF's *embedded* text layer via
PyMuPDF — it is not image-based OCR. It works well for digitally
generated documents (most MTR/certificate-of-conformance PDFs are
this), but a scanned or photographed paper document with no embedded
text layer will come back empty or near-empty. Real OCR (Tesseract or a
cloud OCR service) is a documented follow-up, not built here — this
environment has no system package manager available to install the
Tesseract binary pytesseract would need.
"""
import fitz  # PyMuPDF


def _looks_like_pdf(raw_bytes: bytes, filename: str) -> bool:
    return filename.lower().endswith(".pdf") or raw_bytes[:5] == b"%PDF-"


def extract_text(raw_bytes: bytes, filename: str) -> str:
    if _looks_like_pdf(raw_bytes, filename):
        with fitz.open(stream=raw_bytes, filetype="pdf") as doc:
            return "\n".join(page.get_text() for page in doc)
    return raw_bytes.decode("utf-8", errors="replace")
