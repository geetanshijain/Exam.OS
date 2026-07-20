import io
import json
import math
from datetime import datetime, timezone

from pypdf import PdfReader, PdfWriter


def _stamp_pdf(pdf_bytes: bytes, watermark_text: str) -> bytes:
    reader = PdfReader(io.BytesIO(pdf_bytes))
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    for i, page in enumerate(writer.pages):
        width = float(page.mediabox.width)
        height = float(page.mediabox.height)

        overlay_stream = _build_diagonal_overlay(width, height, watermark_text)
        overlay_page = PdfReader(io.BytesIO(overlay_stream)).pages[0]
        page.merge_page(overlay_page)

    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_diagonal_overlay(width: float, height: float, text: str) -> bytes:
    angle_rad = math.atan2(height, width)
    angle_deg = math.degrees(angle_rad)
    diagonal = math.sqrt(width**2 + height**2)
    cx = width / 2
    cy = height / 2

    safe_text = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    lines = [
        f"q",
        f"0.85 0.1 0.1 rg",
        f"BT",
        f"/F1 9 Tf",
        f"1 0 0 1 {cx:.2f} {cy:.2f} cm",
        f"{math.cos(angle_rad):.4f} {math.sin(angle_rad):.4f} {-math.sin(angle_rad):.4f} {math.cos(angle_rad):.4f} 0 0 Tm",
        f"0.15 Tr",
        f"({safe_text}) Tj",
        f"ET",
        f"Q",
    ]
    content = "\n".join(lines).encode()

    font_obj = (
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica "
        b"/Encoding /WinAnsiEncoding >>"
    )
    font_ref = b"1 0 obj\n" + font_obj + b"\nendobj\n"

    page_obj = (
        f"2 0 obj\n<< /Type /Page /Parent 3 0 R "
        f"/MediaBox [0 0 {width:.2f} {height:.2f}] "
        f"/Contents 4 0 R /Resources << /Font << /F1 1 0 R >> >> >>\nendobj\n"
    ).encode()

    content_obj = b"4 0 obj\n<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream\nendobj\n"

    pages_obj = (
        b"3 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj\n"
    )
    catalog_obj = b"5 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n"

    header = b"%PDF-1.4\n"
    body = font_ref + page_obj + pages_obj + content_obj + catalog_obj

    xref_pos = len(header) + len(body)
    offsets = []
    pos = len(header)
    for obj in [font_ref, page_obj, pages_obj, content_obj, catalog_obj]:
        offsets.append(pos)
        pos += len(obj)

    xref = b"xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = f"trailer\n<< /Size 6 /Root 5 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()

    return header + body + xref + trailer


def stamp_pdf_bytes(raw: bytes, email: str, ip: str, ts: datetime) -> bytes:
    ts_str = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
    watermark = f"CONFIDENTIAL - ACCESSED BY {email} - IP: {ip} - TIME: {ts_str}"
    try:
        return _stamp_pdf(raw, watermark)
    except Exception:
        return raw


def build_decoy_pdf() -> bytes:
    content_text = (
        "This document has been logged as an unauthorized access attempt."
    )
    safe_text = content_text.replace("(", "\\(").replace(")", "\\)")
    content = (
        f"q\n0 0 0 rg\nBT\n/F1 12 Tf\n72 720 Td\n({safe_text}) Tj\nET\nQ"
    ).encode()

    font_ref = b"1 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n"
    page_obj = b"2 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 1 0 R >> >> >>\nendobj\n"
    pages_obj = b"3 0 obj\n<< /Type /Pages /Kids [2 0 R] /Count 1 >>\nendobj\n"
    content_obj = b"4 0 obj\n<< /Length " + str(len(content)).encode() + b" >>\nstream\n" + content + b"\nendstream\nendobj\n"
    catalog_obj = b"5 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n"

    header = b"%PDF-1.4\n"
    body = font_ref + page_obj + pages_obj + content_obj + catalog_obj
    xref_pos = len(header) + len(body)

    offsets = []
    pos = len(header)
    for obj in [font_ref, page_obj, pages_obj, content_obj, catalog_obj]:
        offsets.append(pos)
        pos += len(obj)

    xref = b"xref\n0 6\n0000000000 65535 f \n"
    for off in offsets:
        xref += f"{off:010d} 00000 n \n".encode()

    trailer = f"trailer\n<< /Size 6 /Root 5 0 R >>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return header + body + xref + trailer
