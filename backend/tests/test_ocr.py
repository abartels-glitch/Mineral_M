"""PyMuPDF text-layer extraction and the plain-text fallback path."""
import fitz

import ocr


def _make_pdf_bytes(text: str) -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    return doc.tobytes()


def test_extract_text_from_pdf():
    pdf_bytes = _make_pdf_bytes("Supplier: Test Co\nHeat Number: ABC-123")
    text = ocr.extract_text(pdf_bytes, "cert.pdf")
    assert "Supplier: Test Co" in text
    assert "Heat Number: ABC-123" in text


def test_extract_text_from_txt_fallback():
    raw = b"Supplier: Plain Text Co\n"
    text = ocr.extract_text(raw, "cert.txt")
    assert text == "Supplier: Plain Text Co\n"


def test_pdf_sniffed_by_magic_bytes_even_without_pdf_extension():
    pdf_bytes = _make_pdf_bytes("Material: NdFeB")
    text = ocr.extract_text(pdf_bytes, "upload")
    assert "Material: NdFeB" in text
