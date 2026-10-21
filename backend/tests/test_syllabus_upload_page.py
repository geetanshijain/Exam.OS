import os
import io
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.studio import DocumentType, Examination, ExamStatus, UploadedDocument
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_syllabus_and_pyq_upload_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Syllabus and PYQ Upload page:
    1. Create an examination and upload syllabus (.pdf/.docx/.txt).
    2. Upload previous year question paper with provenance tracking.
    3. Low text yield triggers manual OCR review flag.
    4. Query uploaded documents ledger with extracted page details.
    5. Departmental isolation prevents cross-department document tampering.
    """
    # 1. Create setter user
    setter = User(
        email="setter_os@examos.edu",
        username="setter_os",
        full_name="Prof. Alex Setter",
        department="Computer Science",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(setter)
    await db_session.commit()
    await db_session.refresh(setter)

    token, _, _ = create_access_token(
        subject=setter.id,
        role=setter.role.value,
        department=setter.department,
        mfa_verified=True,
    )
    auth_headers = {"Authorization": f"Bearer {token}"}

    # 2. Create examination
    create_exam_res = await client.post(
        "/api/v1/studio/examinations",
        json={
            "title": "CS-501: Operating Systems",
            "subject": "Computer Science",
            "course": "B.Tech CSE",
            "semester": 5,
            "department": "Computer Science",
            "syllabus_version": "2026.1",
            "total_marks": 100,
            "duration_minutes": 180,
        },
        headers=auth_headers,
    )
    assert create_exam_res.status_code == 201
    exam_data = create_exam_res.json()
    exam_id = exam_data["id"]

    # 3. Upload Syllabus Document (.txt with rich unit structure)
    syllabus_text = """
    Unit I: Operating System Structures & System Calls
    Topics: Monolithic vs microkernel architectures, system call lifecycle, process context switching.
    Learning Outcomes: Understand core kernel primitives.

    Unit II: Concurrency, Deadlocks & Synchronization
    Topics: Semaphores, Mutex locks, Classic dining philosophers problem, Banker's avoidance algorithm.
    Learning Outcomes: Analyze race conditions and solve deadlocks.
    """.strip().encode("utf-8")

    syl_files = {"file": ("CS501_Syllabus_2026.txt", io.BytesIO(syllabus_text), "text/plain")}
    syl_data = {"document_type": "syllabus", "allow_external_ai": "false"}

    syl_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/upload",
        data=syl_data,
        files=syl_files,
        headers=auth_headers,
    )
    assert syl_res.status_code == 201
    syl_resp = syl_res.json()
    assert syl_resp["document_type"] == "syllabus"
    assert syl_resp["original_filename"] == "CS501_Syllabus_2026.txt"
    assert syl_resp["requires_manual_review"] is False
    assert len(syl_resp["extracted_pages"]) >= 1

    # 4. Upload Previous Year Question Paper (PYQ)
    pyq_text = """
    Q1. Define race condition and mutual exclusion mechanisms (5 Marks).
    Q2. Given allocation matrix, determine safe sequence using Banker's Algorithm (10 Marks).
    """.strip().encode("utf-8")

    pyq_files = {"file": ("CS501_EndSem_2025.txt", io.BytesIO(pyq_text), "text/plain")}
    pyq_data = {"document_type": "previous_paper", "allow_external_ai": "false"}

    pyq_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/upload",
        data=pyq_data,
        files=pyq_files,
        headers=auth_headers,
    )
    assert pyq_res.status_code == 201
    pyq_resp = pyq_res.json()
    assert pyq_resp["document_type"] == "previous_paper"
    assert pyq_resp["original_filename"] == "CS501_EndSem_2025.txt"

    # 5. Low text yield triggers manual OCR review flag
    scanned_text = b"Scan 2024"  # Less than 15 words
    scanned_files = {"file": ("CS501_Scanned_2024.txt", io.BytesIO(scanned_text), "text/plain")}
    scanned_data = {"document_type": "previous_paper", "allow_external_ai": "false"}

    scanned_res = await client.post(
        f"/api/v1/studio/examinations/{exam_id}/upload",
        data=scanned_data,
        files=scanned_files,
        headers=auth_headers,
    )
    assert scanned_res.status_code == 201
    scanned_resp = scanned_res.json()
    assert scanned_resp["requires_manual_review"] is True
    assert "low text" in (scanned_resp["review_reason"] or "").lower()

    # 6. List Ingested Documents Ledger
    docs_list_res = await client.get(
        f"/api/v1/studio/examinations/{exam_id}/documents",
        headers=auth_headers,
    )
    assert docs_list_res.status_code == 200
    docs = docs_list_res.json()
    assert len(docs) >= 3

    # 7. Cross-department IDOR protection:
    # A setter from Electrical Engineering cannot upload or view documents for Computer Science
    other_setter = User(
        email="setter_ee@examos.edu",
        username="setter_ee",
        full_name="Prof. EE Examiner",
        department="Electrical Engineering",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(other_setter)
    await db_session.commit()
    await db_session.refresh(other_setter)

    ee_token, _, _ = create_access_token(
        subject=other_setter.id,
        role=other_setter.role.value,
        department=other_setter.department,
        mfa_verified=True,
    )
    ee_headers = {"Authorization": f"Bearer {ee_token}"}

    forbidden_res = await client.get(
        f"/api/v1/studio/examinations/{exam_id}/documents",
        headers=ee_headers,
    )
    assert forbidden_res.status_code == 403


def test_syllabus_upload_html_and_reference_fidelity():
    """
    Verifies that frontend/syllabus-upload.html implements all components,
    accessible controls, and visual fidelity from the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "syllabus-upload.html")
    assert os.path.exists(page_path), "frontend/syllabus-upload.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header & Navigation Landmarks
    assert '<header class="site-header"' in html
    assert 'Question Paper Studio' in html
    assert 'Syllabus &amp; PYQ Upload' in html
    assert 'id="active-exam-title"' in html
    assert 'id="exam-selector"' in html
    assert 'id="btn-back-dashboard"' in html

    # 2. Upload Hub Controls
    assert 'Upload Hub' in html
    assert 'Syllabus Document Upload' in html
    assert 'id="syllabus-dropzone"' in html
    assert 'id="btn-browse-syllabus"' in html
    assert 'Previous Year Question Papers (PYQ)' in html
    assert 'id="pyq-dropzone"' in html
    assert 'id="pyq-year-select"' in html
    assert 'id="btn-browse-pyq"' in html
    assert 'id="airgap-toggle"' in html
    assert 'Local Institutional Processing Only' in html

    # 3. Provenance & OCR Quality Control Ledger
    assert 'Document Provenance &amp; OCR Quality Control' in html
    assert 'Ingested Documents &amp; Provenance Ledger' in html
    assert 'File Name' in html
    assert 'Extraction Status' in html
    assert 'id="documents-table-body"' in html
    assert 'Requires OCR Review' in html

    # 4. Inspector Modal Dialog
    assert 'id="inspector-modal"' in html
    assert 'Document Text &amp; Page Provenance Inspector' in html

    # 5. Bottom Navigation Bar
    assert 'id="provenance-summary"' in html
    assert 'id="btn-proceed-structure"' in html
    assert 'Proceed to Syllabus Structure Editor' in html
    assert 'Source Document Provenance Preserved' in html
    assert 'DEV ENVIRONMENT' in html
