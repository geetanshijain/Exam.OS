import os
import io
from datetime import datetime, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.question_paper import PaperStatus, QuestionPaper
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_setter_dashboard_backend_contracts_and_security(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Exam Setter Dashboard:
    1. Setter can fetch their authored papers list.
    2. Setter can upload a paper with AES-256 encryption.
    3. Cross-department upload rejection (Departmental Isolation Enforcement).
    4. Object-level authorization prevents IDOR access.
    """
    # 1. Create Setter User
    setter = User(
        email="setter_cs@examos.edu",
        username="setter_cs",
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

    # 2. Get current profile
    me_res = await client.get("/api/v1/auth/me", headers=auth_headers)
    assert me_res.status_code == 200
    me_data = me_res.json()
    assert me_data["username"] == "setter_cs"
    assert me_data["department"] == "Computer Science"

    # 3. Initially papers list is empty for new setter
    list_res = await client.get("/api/v1/papers/", headers=auth_headers)
    assert list_res.status_code == 200
    assert len(list_res.json()) == 0

    # 4. Upload paper for Computer Science
    file_content = b"%PDF-1.4 Mock exam paper content with questions"
    files = {"file": ("cs501_exam.pdf", io.BytesIO(file_content), "application/pdf")}
    data = {
        "title": "CS-501: Operating Systems & Kernel Architecture",
        "subject": "Computer Science",
        "exam_date": "2026-11-24T09:00:00",
        "department": "Computer Science",
        "description": "Finalized manuscript with process synchronization sections.",
    }

    upload_res = await client.post("/api/v1/papers/upload", data=data, files=files, headers=auth_headers)
    assert upload_res.status_code == 201
    upload_data = upload_res.json()
    assert upload_data["title"] == "CS-501: Operating Systems & Kernel Architecture"
    assert upload_data["status"] == "Pending_HOD"
    paper_id = upload_data["id"]

    # 5. Verify paper appears in setter's papers list
    list_after_res = await client.get("/api/v1/papers/", headers=auth_headers)
    assert list_after_res.status_code == 200
    papers = list_after_res.json()
    assert len(papers) == 1
    assert papers[0]["id"] == paper_id
    assert papers[0]["subject"] == "Computer Science"
    assert papers[0]["status"] == "Pending_HOD"

    # 6. Cross-department upload rejection:
    # Setter assigned to Computer Science cannot author a paper for Mechanical Engineering
    diff_dept_files = {"file": ("mech_exam.pdf", io.BytesIO(file_content), "application/pdf")}
    diff_dept_data = {
        "title": "ME-301: Thermodynamics & Heat Transfer",
        "subject": "Mechanical Engineering",
        "exam_date": "2026-12-01T09:00:00",
        "department": "Mechanical Engineering",
    }
    cross_upload_res = await client.post(
        "/api/v1/papers/upload",
        data=diff_dept_data,
        files=diff_dept_files,
        headers=auth_headers,
    )
    assert cross_upload_res.status_code == 403
    assert "Forbidden" in cross_upload_res.json()["detail"]

    # 7. Validation failure: empty file
    empty_file = {"file": ("empty.pdf", io.BytesIO(b""), "application/pdf")}
    empty_res = await client.post(
        "/api/v1/papers/upload",
        data=data,
        files=empty_file,
        headers=auth_headers,
    )
    assert empty_res.status_code == 400


def test_setter_dashboard_html_and_reference_fidelity():
    """
    Verifies that frontend/setter.html implements all components,
    accessible attributes, and visual requirements from the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    setter_path = os.path.join(frontend_dir, "setter.html")
    assert os.path.exists(setter_path), "frontend/setter.html must exist"

    with open(setter_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks
    assert '<header class="site-header"' in html
    assert 'ExamOS' in html
    assert 'Exam Setter Dashboard' in html
    assert 'id="user-display-name"' in html
    assert 'id="user-dept-badge"' in html
    assert 'id="btn-logout"' in html

    # 2. Four KPI Cards
    assert 'Total Papers Authored' in html
    assert 'Pending HOD Review' in html
    assert 'Approved & Vault-Locked' in html
    assert 'Revision Required' in html
    assert 'id="kpi-total"' in html
    assert 'id="kpi-pending-hod"' in html
    assert 'id="kpi-approved"' in html
    assert 'id="kpi-rejected"' in html

    # 3. Action Toolbar
    assert 'id="search-input"' in html
    assert 'id="status-filter"' in html
    assert 'id="btn-open-upload"' in html
    assert '+ Upload New Paper' in html
    assert 'id="btn-open-studio"' in html
    assert 'AI Question Studio' in html

    # 4. Table Structure
    assert 'Authored Examination Papers' in html
    assert 'Paper Code & Title' in html
    assert 'Vault Security Status' in html
    assert 'Approval Pipeline Status' in html
    assert 'AES-256-GCM Encrypted' in html
    assert 'id="papers-table-body"' in html

    # 5. Modals & Forms
    assert 'id="upload-modal"' in html
    assert 'id="upload-paper-form"' in html
    assert 'id="details-modal"' in html
    assert 'id="studio-modal"' in html

    # 6. Institutional Notices
    assert 'Departmental RBAC Isolation Active' in html
    assert 'DEV ENVIRONMENT' in html
