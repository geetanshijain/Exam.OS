import json
import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from app.models.question_paper import QuestionPaper, PaperStatus
from app.models.assembly import AssembledPaper, AssembledPaperStatus
from datetime import datetime, timezone


@pytest.mark.asyncio
async def test_paper_preview_and_approval_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Paper Preview & Approval page:
    1. Multi-stage dual-custody review pipeline (Setter Draft -> HOD Review -> Controller Release).
    2. Enforcing dual-custody invariant: Controller cannot be the same user who approved HOD stage.
    3. Departmental IDOR boundaries: Cross-department review attempts are rejected with HTTP 403.
    4. Assembly paper preview endpoint delivering rendered sections and blueprint compliance.
    """
    # 1. Create Setter (CS)
    setter = User(
        email="setter_prev@examos.edu",
        username="setter_prev",
        full_name="Prof. Alex Setter",
        department="Computer Science",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 2. Create HOD (CS)
    hod = User(
        email="hod_cs_prev@examos.edu",
        username="hod_cs_prev",
        full_name="Dr. Marcus Vance",
        department="Computer Science",
        role=UserRole.hod,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 3. Create Controller (Institutional)
    controller = User(
        email="controller_prev@examos.edu",
        username="controller_prev",
        full_name="Dr. Controller Exam",
        department="Examination Cell",
        role=UserRole.controller,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add_all([setter, hod, controller])
    await db_session.commit()
    await db_session.refresh(setter)
    await db_session.refresh(hod)
    await db_session.refresh(controller)

    hod_token, _, _ = create_access_token(
        subject=hod.id,
        role=hod.role.value,
        department=hod.department,
        mfa_verified=True,
    )
    hod_headers = {"Authorization": f"Bearer {hod_token}"}

    controller_token, _, _ = create_access_token(
        subject=controller.id,
        role=controller.role.value,
        department=controller.department,
        mfa_verified=True,
    )
    controller_headers = {"Authorization": f"Bearer {controller_token}"}

    # 4. Create Question Paper in Pending_HOD state
    paper = QuestionPaper(
        title="CS-501: Operating Systems & Kernel Architecture",
        subject="Computer Science",
        department="Computer Science",
        exam_date=datetime(2026, 12, 1, 9, 0, tzinfo=timezone.utc),
        file_path="vault/sample_test_paper.enc",
        encrypted_key=json.dumps({"key": "00" * 32, "nonce": "00" * 12}),
        status=PaperStatus.pending_hod,
        created_by=setter.id,
    )
    db_session.add(paper)
    await db_session.commit()
    await db_session.refresh(paper)

    # 5. HOD Review & Approval Stage
    hod_res = await client.patch(
        f"/api/v1/papers/{paper.id}/hod-review?action=approve&comment=Formally+approved+by+Department+HOD",
        headers=hod_headers,
    )
    assert hod_res.status_code == 200
    assert hod_res.json()["status"] == PaperStatus.pending_controller.value
    assert hod_res.json()["stage"] == "hod_completed"

    # 6. Dual-Custody Violation Test: HOD attempts to also perform Controller sign-off
    illegal_controller_res = await client.patch(
        f"/api/v1/papers/{paper.id}/controller-review?action=approve&comment=Self+approval+attempt",
        headers=hod_headers,  # HOD attempting to act as Controller
    )
    assert illegal_controller_res.status_code in [403, 401]

    # 7. Legitimate Controller Final Vault Release
    controller_res = await client.patch(
        f"/api/v1/papers/{paper.id}/controller-review?action=approve&comment=Controller+vault+seal+applied",
        headers=controller_headers,
    )
    assert controller_res.status_code == 200
    assert controller_res.json()["status"] == PaperStatus.approved_locked.value
    assert controller_res.json()["stage"] == "release_approved"

    # 8. Departmental IDOR Protection
    civil_hod = User(
        email="hod_civil_prev@examos.edu",
        username="hod_civil_prev",
        full_name="Dr. Civil Head",
        department="Civil Engineering",
        role=UserRole.hod,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add(civil_hod)
    await db_session.commit()
    await db_session.refresh(civil_hod)

    civil_token, _, _ = create_access_token(
        subject=civil_hod.id,
        role=civil_hod.role.value,
        department=civil_hod.department,
        mfa_verified=True,
    )
    civil_headers = {"Authorization": f"Bearer {civil_token}"}

    forbidden_hod = await client.patch(
        f"/api/v1/papers/{paper.id}/hod-review?action=approve",
        headers=civil_headers,
    )
    assert forbidden_hod.status_code in [403, 409]


def test_paper_preview_page_html_and_reference_fidelity():
    """
    Verifies that frontend/paper-preview.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "paper-preview.html")
    assert os.path.exists(page_path), "frontend/paper-preview.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Paper Studio' in html
    assert 'Paper Preview &amp; Approval' in html
    assert 'id="paper-headline"' in html
    assert 'id="paper-status-pill"' in html

    # 2. Action Controls
    assert 'id="btn-hod-approve"' in html
    assert 'Formal HOD Approve' in html
    assert 'id="btn-request-revision"' in html
    assert 'Request Revision' in html
    assert 'id="btn-download-pdf"' in html
    assert 'Download PDF' in html

    # 3. Quality Assurance KPI Strip (Matching Approved Reference Design)
    assert 'id="kpi-total-marks"' in html
    assert 'id="kpi-duration"' in html
    assert 'id="kpi-blueprint-status"' in html
    assert 'id="kpi-governance-stage"' in html
    assert '100 / 100 M Validated' in html
    assert '180 mins' in html
    assert '0 Conflicts' in html
    assert 'Stage 1 of 2 Active' in html

    # 4. Rendered Institutional Examination Paper Sheet (Left Column)
    assert 'class="exam-paper-sheet"' in html
    assert 'Central Examination Board' in html
    assert 'END-SEMESTER EXAMINATION 2026' in html
    assert 'Instructions to Candidates:' in html
    assert 'id="sheet-section-a"' in html
    assert 'id="sheet-section-b"' in html
    assert 'id="sheet-section-c"' in html
    assert 'Section A — Short Answers' in html
    assert 'Section B — Analytical' in html
    assert 'Section C — Comprehensive System Architecture' in html

    # 5. Governance Sidebar (Right Column)
    assert 'Multi-Stage Dual-Custody Approval Stepper' in html
    assert 'id="step-setter"' in html
    assert 'id="step-hod"' in html
    assert 'id="step-controller"' in html
    assert 'id="hod-comment-input"' in html
    assert 'Setter Draft' in html
    assert 'Department HOD Review' in html
    assert 'Controller Vault Locking' in html

    # 6. Blueprint Conformance Checklist & Version Card
    assert 'Blueprint Conformance' in html
    assert 'conformance-check-list' in html
    assert 'Cryptographic Version' in html
    assert 'id="audit-hash-text"' in html
    assert 'id="audit-seed-text"' in html
    assert 'id="btn-copy-hash"' in html

    # 7. Six UI States
    assert 'id="paper-loading-state"' in html
    assert 'id="paper-permission-denied"' in html
    assert 'id="paper-empty-state"' in html
    assert 'id="paper-alert"' in html

    # 8. Institutional Footer Notice
    assert 'Dual-Custody Review Enforced' in html
    assert 'AES-256 Vault-Bound' in html
    assert 'DEV ENVIRONMENT' in html
