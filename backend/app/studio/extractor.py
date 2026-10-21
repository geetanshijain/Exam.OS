import io
from pathlib import Path
from typing import Any

from pypdf import PdfReader


def extract_document_text(
    file_bytes: bytes,
    filename: str,
    mime_type: str,
) -> tuple[int, list[dict[str, Any]], bool, str | None]:
    """
    Extracts text from PDF or DOCX files while preserving page/section provenance.
    Detects low text density and flags documents requiring OCR or manual review.

    Returns:
        (page_count, extracted_pages, requires_manual_review, review_reason)
    """
    ext = Path(filename).suffix.lower()
    extracted_pages: list[dict[str, Any]] = []
    page_count = 0
    requires_manual_review = False
    review_reason: str | None = None

    if ext == ".pdf" or "pdf" in mime_type.lower():
        try:
            reader = PdfReader(io.BytesIO(file_bytes))
            page_count = len(reader.pages)
            total_chars = 0

            for idx, page in enumerate(reader.pages):
                text = (page.extract_text() or "").strip()
                char_count = len(text)
                word_count = len(text.split())
                total_chars += char_count

                extracted_pages.append({
                    "page_number": idx + 1,
                    "text": text,
                    "character_count": char_count,
                    "word_count": word_count,
                })

            # Check text density threshold
            avg_chars_per_page = total_chars / max(page_count, 1)
            if page_count > 0 and avg_chars_per_page < 50:
                requires_manual_review = True
                review_reason = (
                    f"Low text density detected ({int(avg_chars_per_page)} chars/page avg). "
                    "Document appears to be a scanned image or lacks a searchable text layer; manual review or OCR required."
                )

        except Exception as exc:
            requires_manual_review = True
            review_reason = f"PDF parsing warning: {str(exc)}"
            extracted_pages.append({"page_number": 1, "text": "", "character_count": 0, "word_count": 0})
            page_count = 1

    elif ext in [".docx", ".doc"] or "word" in mime_type.lower() or "officedocument" in mime_type.lower():
        try:
            import docx
            doc = docx.Document(io.BytesIO(file_bytes))
            full_text = []
            
            # Group paragraphs into logical sections
            paragraphs = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
            
            # Chunk every 8 paragraphs as a pseudo-page reference for DOCX
            chunk_size = 8
            chunks = [paragraphs[i:i + chunk_size] for i in range(0, max(len(paragraphs), 1), chunk_size)]
            page_count = len(chunks)

            for idx, chunk in enumerate(chunks):
                section_text = "\n".join(chunk)
                extracted_pages.append({
                    "page_number": idx + 1,
                    "text": section_text,
                    "character_count": len(section_text),
                    "word_count": len(section_text.split()),
                })

            if not paragraphs:
                requires_manual_review = True
                review_reason = "DOCX file contains zero readable text paragraphs."

        except Exception as exc:
            requires_manual_review = True
            review_reason = f"DOCX parsing error: {str(exc)}"
            page_count = 1
            extracted_pages.append({"page_number": 1, "text": "", "character_count": 0, "word_count": 0})

    else:
        # Fallback to plain text decoding
        try:
            text = file_bytes.decode("utf-8", errors="replace").strip()
            page_count = 1
            extracted_pages.append({
                "page_number": 1,
                "text": text,
                "character_count": len(text),
                "word_count": len(text.split()),
            })
            if len(text) < 50:
                requires_manual_review = True
                review_reason = (
                    f"Low text density detected ({len(text)} chars). "
                    "Document appears to be a scanned image or lacks sufficient content; manual review or OCR required."
                )
        except Exception:
            page_count = 1
            requires_manual_review = True
            review_reason = "Unsupported document format; raw text extraction failed."

    return page_count, extracted_pages, requires_manual_review, review_reason
