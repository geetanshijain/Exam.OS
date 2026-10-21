import io
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.core.pdf_utils import stamp_pdf_bytes
from app.models.assembly import AssembledPaper, AssembledPaperStatus


def generate_paper_pdf(
    paper: AssembledPaper,
    sections: list[dict[str, Any]],
    requester_email: str = "faculty@examos.edu",
    client_ip: str = "127.0.0.1",
) -> bytes:
    """
    Renders an institutional academic examination paper in PDF format using ReportLab.
    Stamps security watermarks and provenance metadata.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=45,
        leftMargin=45,
        topMargin=45,
        bottomMargin=45,
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "InstTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=14,
        leading=16,
        alignment=1,  # Centered
        textColor=colors.HexColor("#0f172a"),
    )
    subtitle_style = ParagraphStyle(
        "InstSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        alignment=1,
        textColor=colors.HexColor("#1e293b"),
    )
    meta_style = ParagraphStyle(
        "InstMeta",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#334155"),
    )
    meta_bold = ParagraphStyle(
        "InstMetaBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0f172a"),
    )
    section_head_style = ParagraphStyle(
        "SectionHead",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f172a"),
    )
    instruction_style = ParagraphStyle(
        "SectionInst",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#475569"),
    )
    question_style = ParagraphStyle(
        "QuestionText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13,
        textColor=colors.HexColor("#0f172a"),
    )
    marks_style = ParagraphStyle(
        "MarksText",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13,
        alignment=2,  # Right aligned
        textColor=colors.HexColor("#0f172a"),
    )
    or_style = ParagraphStyle(
        "OrDivider",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=12,
        alignment=1,  # Centered
        textColor=colors.HexColor("#64748b"),
    )
    end_style = ParagraphStyle(
        "EndMarker",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=12,
        alignment=1,
        textColor=colors.HexColor("#64748b"),
    )

    story = []

    # 1. Institutional Header
    story.append(Paragraph("EXAM OS ACADEMIC EXAMINATION BOARD", title_style))
    story.append(Spacer(1, 2))
    story.append(Paragraph(f"DEPARTMENT OF {paper.department.upper()}", subtitle_style))
    story.append(Spacer(1, 2))
    story.append(Paragraph(paper.title.upper(), subtitle_style))
    story.append(Spacer(1, 6))

    # Meta table
    meta_data = [
        [
            Paragraph(f"<b>Subject:</b> {paper.subject}", meta_style),
            Paragraph(f"<b>Course / Sem:</b> {paper.course} (Sem {paper.semester})", meta_style),
        ],
        [
            Paragraph(f"<b>Paper Code:</b> {paper.paper_code}", meta_style),
            Paragraph(f"<b>Version:</b> v{paper.version} ({paper.status.value.upper()})", meta_style),
        ],
        [
            Paragraph(f"<b>Duration:</b> {paper.duration_minutes} Minutes", meta_bold),
            Paragraph(f"<b>Maximum Marks:</b> {paper.total_marks}", meta_bold),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[260, 260])
    meta_table.setStyle(
        TableStyle([
            ("LINEABOVE", (0, 0), (-1, 0), 0.75, colors.HexColor("#cbd5e1")),
            ("LINEBELOW", (0, -1), (-1, -1), 0.75, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))

    # General Instructions
    instructions_text = (
        "<b>General Instructions:</b> 1. Verify that the question paper is complete and legible. "
        "2. Write your Examination Registration Number clearly on the answer booklet. "
        "3. Answer the sections in sequential order according to the rubric specified."
    )
    story.append(Paragraph(instructions_text, instruction_style))
    story.append(Spacer(1, 10))

    # 2. Render Sections
    for sec in sections:
        sec_name = sec.get("name", "Section")
        sec_inst = sec.get("instructions", "Answer all questions.")
        sec_marks = sec.get("total_section_marks", 0)

        # Section Header Banner
        sec_banner = [
            [
                Paragraph(f"{sec_name.upper()}", section_head_style),
                Paragraph(f"[Max Marks: {sec_marks}]", marks_style),
            ]
        ]
        banner_table = Table(sec_banner, colWidths=[420, 100])
        banner_table.setStyle(
            TableStyle([
                ("LINEABOVE", (0, 0), (-1, -1), 1, colors.HexColor("#0f172a")),
                ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(banner_table)
        story.append(Spacer(1, 3))
        story.append(Paragraph(sec_inst, instruction_style))
        story.append(Spacer(1, 8))

        # Questions in section
        questions = sec.get("questions", [])
        for q in questions:
            item_num = q.get("item_number", 1)
            has_internal = q.get("has_internal_choice", False)
            choice_a = q.get("choice_a", {})
            choice_b = q.get("choice_b")

            q_text_a = choice_a.get("question_text", "")
            q_marks_a = choice_a.get("marks", q.get("marks", 0))

            q_row_a = [
                [
                    Paragraph(f"<b>Q{item_num}.</b>", meta_bold),
                    Paragraph(q_text_a, question_style),
                    Paragraph(f"[{q_marks_a}]", marks_style),
                ]
            ]
            q_table_a = Table(q_row_a, colWidths=[30, 440, 50])
            q_table_a.setStyle(TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(q_table_a)

            if has_internal and choice_b:
                story.append(Spacer(1, 3))
                story.append(Paragraph("--- OR ---", or_style))
                story.append(Spacer(1, 3))

                q_text_b = choice_b.get("question_text", "")
                q_marks_b = choice_b.get("marks", q_marks_a)
                q_row_b = [
                    [
                        Paragraph(f"<b>Q{item_num}(b).</b>", meta_bold),
                        Paragraph(q_text_b, question_style),
                        Paragraph(f"[{q_marks_b}]", marks_style),
                    ]
                ]
                q_table_b = Table(q_row_b, colWidths=[40, 430, 50])
                q_table_b.setStyle(TableStyle([
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]))
                story.append(q_table_b)

            story.append(Spacer(1, 6))

        story.append(Spacer(1, 6))

    # End of paper
    story.append(Spacer(1, 15))
    story.append(HRFlowable(width="60%", thickness=0.5, color=colors.HexColor("#94a3b8"), spaceAfter=8))
    story.append(Paragraph("*** END OF EXAMINATION PAPER ***", end_style))

    doc.build(story)
    raw_pdf = buffer.getvalue()

    # Apply watermark based on approval status
    if paper.status == AssembledPaperStatus.approved:
        watermark = f"EXAM OS VERIFIED - {paper.paper_code} - V{paper.version}"
    else:
        watermark = f"UNAPPROVED DRAFT (V{paper.version}) - CONFIDENTIAL INTERNAL REVIEW ONLY"

    return stamp_pdf_bytes(
        raw=raw_pdf,
        email=requester_email,
        ip=client_ip,
        ts=datetime.now(timezone.utc),
    )


def generate_accessible_html_preview(
    paper: AssembledPaper,
    sections: list[dict[str, Any]],
) -> str:
    """
    Renders a semantic, WCAG-compliant HTML preview with clear distinction
    between draft and approved versions.
    """
    is_approved = (paper.status == AssembledPaperStatus.approved)
    status_badge_class = "status-approved" if is_approved else "status-draft"
    status_text = "APPROVED VERSION" if is_approved else f"DRAFT (UNAPPROVED - VERSION {paper.version})"

    sections_html = []
    for sec in sections:
        sec_name = sec.get("name", "Section")
        sec_inst = sec.get("instructions", "Answer all questions.")
        sec_marks = sec.get("total_section_marks", 0)

        questions_html = []
        for q in sec.get("questions", []):
            item_num = q.get("item_number", 1)
            has_internal = q.get("has_internal_choice", False)
            choice_a = q.get("choice_a", {})
            choice_b = q.get("choice_b")

            q_text_a = choice_a.get("question_text", "")
            q_marks_a = choice_a.get("marks", q.get("marks", 0))

            q_html = f"""
            <li class="question-item" id="q-{item_num}">
                <div class="question-row">
                    <span class="question-number">Q{item_num}.</span>
                    <span class="question-text">{q_text_a}</span>
                    <span class="question-marks">[{q_marks_a} Marks]</span>
                </div>
            """

            if has_internal and choice_b:
                q_text_b = choice_b.get("question_text", "")
                q_marks_b = choice_b.get("marks", q_marks_a)
                q_html += f"""
                <div class="or-divider" aria-hidden="true">— OR —</div>
                <div class="question-row choice-b">
                    <span class="question-number">Q{item_num}(b).</span>
                    <span class="question-text">{q_text_b}</span>
                    <span class="question-marks">[{q_marks_b} Marks]</span>
                </div>
                """

            q_html += "</li>"
            questions_html.append(q_html)

        sections_html.append(f"""
        <section class="paper-section" aria-labelledby="sec-{sec.get('section_id', 'id')}">
            <div class="section-header">
                <h3 id="sec-{sec.get('section_id', 'id')}">{sec_name}</h3>
                <span class="section-marks">Maximum Marks: {sec_marks}</span>
            </div>
            <p class="section-instructions">{sec_inst}</p>
            <ol class="question-list">
                {"".join(questions_html)}
            </ol>
        </section>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{paper.paper_code} - {paper.title} Preview</title>
    <style>
        :root {{
            --bg-color: #f8fafc;
            --surface-color: #ffffff;
            --text-color: #0f172a;
            --border-color: #cbd5e1;
            --primary-accent: #1e3a8a;
            --success-color: #166534;
            --warning-color: #991b1b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.5;
            padding: 24px;
            margin: 0;
        }}
        .preview-container {{
            max-width: 820px;
            margin: 0 auto;
            background: var(--surface-color);
            border: 1px solid var(--border-color);
            padding: 40px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
        }}
        .status-banner {{
            padding: 10px 16px;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 24px;
            border-left: 4px solid;
        }}
        .status-draft {{
            background: #fef2f2;
            color: var(--warning-color);
            border-color: var(--warning-color);
        }}
        .status-approved {{
            background: #f0fdf4;
            color: var(--success-color);
            border-color: var(--success-color);
        }}
        header.paper-header {{
            text-align: center;
            border-bottom: 2px solid var(--text-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        header h1 {{
            font-size: 1.25rem;
            margin: 0 0 4px 0;
            letter-spacing: 0.02em;
        }}
        header h2 {{
            font-size: 1rem;
            margin: 0 0 6px 0;
            color: #334155;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 8px 16px;
            text-align: left;
            margin-top: 12px;
            font-size: 0.875rem;
        }}
        .paper-section {{
            margin-bottom: 32px;
        }}
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 4px;
            margin-bottom: 6px;
        }}
        .section-header h3 {{
            margin: 0;
            font-size: 1.05rem;
        }}
        .section-marks {{
            font-weight: 600;
            font-size: 0.875rem;
        }}
        .section-instructions {{
            font-style: italic;
            font-size: 0.825rem;
            color: #475569;
            margin: 0 0 16px 0;
        }}
        .question-list {{
            list-style: none;
            padding: 0;
            margin: 0;
        }}
        .question-item {{
            margin-bottom: 16px;
            font-size: 0.925rem;
        }}
        .question-row {{
            display: flex;
            gap: 12px;
            align-items: flex-start;
        }}
        .question-number {{
            font-weight: 700;
            min-width: 32px;
        }}
        .question-text {{
            flex: 1;
        }}
        .question-marks {{
            font-weight: 600;
            white-space: nowrap;
        }}
        .or-divider {{
            text-align: center;
            font-weight: 700;
            color: #64748b;
            margin: 8px 0;
            font-size: 0.85rem;
        }}
        footer.paper-footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 16px;
            border-top: 1px dashed var(--border-color);
            font-size: 0.8rem;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="preview-container">
        <div class="status-banner {status_badge_class}" role="status">
            {status_text} &bull; Paper Code: {paper.paper_code} &bull; Security Level: Institutional Vault
        </div>

        <header class="paper-header">
            <h1>EXAM OS ACADEMIC EXAMINATION BOARD</h1>
            <h2>DEPARTMENT OF {paper.department.upper()}</h2>
            <div style="font-weight: 600; font-size: 1.1rem; margin-top: 4px;">{paper.title}</div>
            <div class="meta-grid">
                <div><strong>Subject:</strong> {paper.subject}</div>
                <div><strong>Course / Semester:</strong> {paper.course} (Semester {paper.semester})</div>
                <div><strong>Duration:</strong> {paper.duration_minutes} Minutes</div>
                <div><strong>Maximum Marks:</strong> {paper.total_marks}</div>
            </div>
        </header>

        <main>
            {"".join(sections_html)}
        </main>

        <footer class="paper-footer">
            <div>*** END OF EXAMINATION PAPER ***</div>
            <div>Exam OS Confidentiality Protocol &bull; Generated: {paper.updated_at.strftime('%Y-%m-%d %H:%M UTC')}</div>
        </footer>
    </div>
</body>
</html>
"""
