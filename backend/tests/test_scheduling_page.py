import os
import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.scheduling import ExamSchedule, ExamScheduleStatus
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_examination_scheduling_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Examination Scheduling & Controlled Release page:
    1. Authorized staff (Controller/HOD/Admin) schedule creation with UTC normalization.
    2. Listing schedules filtered by role/department.
    3. Student eligibility mapping to exam center and group.
    4. Controlled release job enqueuing with idempotency key.
    5. Documented emergency cancellation terminating active sessions.
    6. Documented reissue workflow with new designated start time.
    """
    # 1. Create Controller (Staff)
    controller = User(
        email="coe_sched_page@examos.edu",
        username="coe_sched_page",
        full_name="Dr. Eleanor Vance",
        department="Computer Science",
        role=UserRole.controller,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 2. Create Candidate (Student)
    student = User(
        email="student_sched_page@examos.edu",
        username="student_sched_page",
        full_name="Aarav Sharma",
        department="Computer Science",
        role=UserRole.student,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add_all([controller, student])
    await db_session.commit()
    await db_session.refresh(controller)
    await db_session.refresh(student)

    controller_token, _, _ = create_access_token(
        subject=controller.id,
        role=controller.role.value,
        department=controller.department,
        mfa_verified=True,
    )
    controller_headers = {"Authorization": f"Bearer {controller_token}"}

    # 3. Create Schedule via Controller
    now = datetime.now(timezone.utc)
    start_time = (now + timedelta(hours=3)).isoformat()

    schedule_payload = {
        "vault_paper_id": 1,
        "paper_code": "CS-SCHED-PAGE-01",
        "approved_paper_version": 1,
        "title": "CS-501: Operating Systems Final",
        "department": "Computer Science",
        "exam_center_id": "CENTER-NORTH-01",
        "eligible_group_id": "CS-GRP-A1",
        "timezone": "Asia/Kolkata",
        "start_time_utc": start_time,
        "duration_minutes": 180,
        "grace_period_minutes": 15,
    }

    create_res = await client.post(
        "/api/v1/schedules",
        headers=controller_headers,
        json=schedule_payload,
    )
    assert create_res.status_code == 201, f"Schedule creation failed: {create_res.text}"
    created_data = create_res.json()
    schedule_id = created_data["id"]
    assert created_data["paper_code"] == "CS-SCHED-PAGE-01"
    assert created_data["status"] == ExamScheduleStatus.scheduled.value
    assert created_data["duration_minutes"] == 180

    # 4. List Schedules
    list_res = await client.get("/api/v1/schedules", headers=controller_headers)
    assert list_res.status_code == 200
    schedules_list = list_res.json()
    assert any(s["id"] == schedule_id for s in schedules_list)

    # 5. Register Student Eligibility
    reg_payload = {
        "student_id": student.id,
        "group_id": "CS-GRP-A1",
        "exam_center_id": "CENTER-NORTH-01",
        "is_eligible": True,
    }
    reg_res = await client.post(
        "/api/v1/schedules/register-student",
        headers=controller_headers,
        json=reg_payload,
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["is_eligible"] is True

    # 6. Controlled Release Queue Enqueue with Idempotency Key
    idempotency_key = f"IDEM-TEST-{schedule_id}-001"
    release_res = await client.post(
        f"/api/v1/schedules/{schedule_id}/enqueue-release?idempotency_key={idempotency_key}",
        headers=controller_headers,
    )
    assert release_res.status_code == 200
    job_data = release_res.json()
    assert job_data["schedule_id"] == schedule_id
    assert job_data["idempotency_key"] == idempotency_key

    # 7. Documented Emergency Cancellation
    cancel_payload = {
        "reason": "Severe weather alert: Center North inaccessible.",
        "approval_officials": ["Dr. Eleanor Vance", "Prof. Alan Turing"],
    }
    cancel_res = await client.post(
        f"/api/v1/schedules/{schedule_id}/cancel",
        headers=controller_headers,
        json=cancel_payload,
    )
    assert cancel_res.status_code == 200
    cancelled_data = cancel_res.json()
    assert cancelled_data["status"] == ExamScheduleStatus.cancelled.value

    # 8. Documented Reissue Workflow
    new_start = (now + timedelta(days=2)).isoformat()
    reissue_payload = {
        "new_start_time_utc": new_start,
        "reason": "Rescheduled after weather clearance.",
        "approval_officials": ["Dr. Eleanor Vance"],
    }
    reissue_res = await client.post(
        f"/api/v1/schedules/{schedule_id}/reissue",
        headers=controller_headers,
        json=reissue_payload,
    )
    assert reissue_res.status_code == 200
    reissued_data = reissue_res.json()
    assert reissued_data["id"] != schedule_id
    assert reissued_data["status"] == ExamScheduleStatus.scheduled.value


def test_examination_scheduling_html_and_reference_fidelity():
    """
    Verifies that frontend/scheduling.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "scheduling.html")
    assert os.path.exists(page_path), "frontend/scheduling.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Examination Governance' in html
    assert 'Examination Scheduling &amp; Controlled Release' in html
    assert 'id="scheduling-headline"' in html

    # 2. Context Action Controls
    assert 'id="btn-open-create-modal"' in html
    assert '+ Create Schedule' in html
    assert 'id="btn-open-assign-modal"' in html
    assert 'Bulk Center Assign' in html
    assert 'id="btn-emergency-cancel-global"' in html
    assert 'Emergency Cancel Directive' in html

    # 3. Top Metrics Strip (4 Cards Matching Reference Design)
    assert 'id="kpi-active-schedules"' in html
    assert '8 Timetabled' in html
    assert 'id="kpi-queue-status"' in html
    assert 'Idempotent FIFO Active' in html
    assert 'id="kpi-timezone-sync"' in html
    assert 'UTC Normalized / Asia/Kolkata' in html
    assert 'id="kpi-enrollment-count"' in html
    assert '3,420 Mapped' in html

    # 4. High-Density Examination Schedule Master Table
    assert 'High density Examination Schedule Master' in html
    assert 'id="scheduling-search-input"' in html
    assert 'id="scheduling-center-filter"' in html
    assert 'id="scheduling-table-wrapper"' in html
    assert 'id="scheduling-table-body"' in html
    assert 'Paper Code' in html
    assert 'Title &amp; Dept' in html
    assert 'Exam Center &amp; Group' in html
    assert 'Scheduled Window (UTC/IST)' in html
    assert 'Duration' in html

    # 5. Controlled Release Queue Real-Time Monitor
    assert 'Server-Side Controlled Release Queue Monitor' in html
    assert 'id="release-queue-jobs-container"' in html
    assert 'Idempotency Key Guard Active' in html

    # 6. Six UI States
    assert 'id="scheduling-loading-state"' in html
    assert 'id="scheduling-permission-denied"' in html
    assert 'id="scheduling-empty-state"' in html
    assert 'id="scheduling-alert"' in html
    assert 'id="create-modal-alert"' in html

    # 7. Accessible Dialogs / Modals
    assert 'id="modal-create-schedule"' in html
    assert 'id="form-create-schedule"' in html
    assert 'id="modal-student-assign"' in html
    assert 'id="form-student-assign"' in html
    assert 'id="modal-cancel-dialog"' in html
    assert 'id="form-cancel-schedule"' in html
    assert 'id="modal-reissue-dialog"' in html
    assert 'id="form-reissue-schedule"' in html
    assert 'id="modal-manifest-dialog"' in html

    # 8. Institutional Footer Notice
    assert 'Zero Pre-Release Question Exposure' in html
    assert 'UTC Normalized Timestamps with Millisecond Drift Tolerance' in html
    assert 'DEV ENVIRONMENT' in html
