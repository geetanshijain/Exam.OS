import os
import json
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.assembly import AssembledPaper, AssembledPaperStatus
from app.models.scheduling import (
    ExamSchedule,
    ExamScheduleStatus,
    StudentExamSession,
    StudentGroupRegistration,
    StudentSessionStatus,
)
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_student_examination_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates complete end-to-end backend API contracts for the Student Exam Portal:
    1. Candidate login / authentication and role assertions.
    2. Candidate schedule listing filtered to enrolled group & center.
    3. Strict early-access rejection (HTTP 425) prior to designated start time.
    4. Successful session initiation returning 12 questions, tokens, and forensic watermark.
    5. Center mismatch rejection (HTTP 403).
    6. Candidate debounced autosave updating remaining time and last heartbeat.
    7. Session interruption recovery via single-use recovery token.
    8. Final submission locking candidate responses and blocking further modifications.
    """
    now = datetime.now(timezone.utc)

    # 1. Setup Student & Controller Accounts
    student = User(
        email="test_candidate@examos.edu",
        username="test_candidate",
        full_name="Rohan Verma",
        department="Computer Science",
        role=UserRole.student,
        hashed_password=hash_password("password123"),
        is_active=True,
    )
    controller = User(
        email="coe_test@examos.edu",
        username="coe_test",
        full_name="Dr. Eleanor Vance",
        department="Computer Science",
        role=UserRole.controller,
        hashed_password=hash_password("password123"),
        is_active=True,
    )
    db_session.add_all([student, controller])
    await db_session.commit()
    await db_session.refresh(student)
    await db_session.refresh(controller)

    student_token, _, _ = create_access_token(
        subject=student.id,
        role=student.role.value,
        department=student.department,
        mfa_verified=False,
    )
    student_headers = {"Authorization": f"Bearer {student_token}"}

    # 2. Setup Assembled Paper with 12 Structured Questions
    sections_data = [
        {
            "title": "Section 1: Asymptotic Analysis",
            "questions": [
                {"item_number": 1, "marks": 8, "text": "Master Theorem analysis."},
                {"item_number": 2, "marks": 8, "text": "Divide and conquer closest pair."},
            ],
        },
        {
            "title": "Section 2: Dynamic Programming",
            "questions": [
                {
                    "item_number": 3,
                    "marks": 10,
                    "text": "Longest Common Subsequence (LCS).\n\nX = \"BACDB\"\nY = \"BDCB\"",
                },
                {"item_number": 4, "marks": 8, "text": "Dijkstra vs Bellman-Ford."},
                {"item_number": 5, "marks": 8, "text": "Kruskal algorithm and DSU."},
                {"item_number": 6, "marks": 10, "text": "0/1 Knapsack dynamic programming."},
            ],
        },
        {
            "title": "Section 3: Advanced Optimization",
            "questions": [
                {"item_number": 7, "marks": 8, "text": "Ford-Fulkerson network flow."},
                {"item_number": 8, "marks": 10, "text": "3-SAT reduction to Vertex Cover."},
                {"item_number": 9, "marks": 8, "text": "Amortized analysis accounting method."},
                {"item_number": 10, "marks": 8, "text": "Red-Black Tree invariants."},
                {"item_number": 11, "marks": 8, "text": "Las Vegas vs Monte Carlo."},
                {"item_number": 12, "marks": 6, "text": "Metric TSP 2-approximation."},
            ],
        },
    ]

    asm = AssembledPaper(
        paper_code="CS-401-TEST",
        title="CS-401 Advanced Algorithms",
        subject="Algorithms",
        course="B.Tech CS",
        semester=6,
        department="Computer Science",
        total_marks=100,
        duration_minutes=180,
        blueprint_json="{}",
        sections_json=json.dumps(sections_data),
        version=1,
        status=AssembledPaperStatus.approved,
        created_by=controller.id,
        last_edited_by=controller.id,
        approved_by=controller.id,
        approved_at=now,
    )
    db_session.add(asm)

    # 3. Register Student for Exam Center HALL-A1 and Group CS-UG-2026
    reg = StudentGroupRegistration(
        student_id=student.id,
        group_id="CS-UG-2026",
        exam_center_id="HALL-A1",
        is_eligible=True,
    )
    db_session.add(reg)

    # 4. Schedule A: Future Time-Locked Exam (HTTP 425)
    future_start = now + timedelta(hours=2)
    sched_future = ExamSchedule(
        paper_code="CS-401-TEST",
        approved_paper_version=1,
        title="CS-401 Advanced Algorithms (Future)",
        department="Computer Science",
        exam_center_id="HALL-A1",
        eligible_group_id="CS-UG-2026",
        timezone="UTC",
        start_time_utc=future_start,
        duration_minutes=180,
        end_time_utc=future_start + timedelta(minutes=180),
        grace_period_minutes=15,
        status=ExamScheduleStatus.scheduled,
        created_by=controller.id,
    )

    # 5. Schedule B: Active Exam (Started 10 mins ago)
    active_start = now - timedelta(minutes=10)
    sched_active = ExamSchedule(
        paper_code="CS-401-TEST",
        approved_paper_version=1,
        title="CS-401 Advanced Algorithms",
        department="Computer Science",
        exam_center_id="HALL-A1",
        eligible_group_id="CS-UG-2026",
        timezone="UTC",
        start_time_utc=active_start,
        duration_minutes=180,
        end_time_utc=active_start + timedelta(minutes=180),
        grace_period_minutes=15,
        status=ExamScheduleStatus.active_in_progress,
        created_by=controller.id,
    )
    db_session.add_all([sched_future, sched_active])
    await db_session.commit()
    await db_session.refresh(sched_future)
    await db_session.refresh(sched_active)

    # 6. Verify Schedule Listing
    list_res = await client.get("/api/v1/schedules", headers=student_headers)
    assert list_res.status_code == 200
    schedules = list_res.json()
    assert len(schedules) >= 2
    assert any(s["id"] == sched_active.id for s in schedules)

    # 7. Assert Time-Lock Boundary (HTTP 425) on future schedule
    early_res = await client.post(
        f"/api/v1/schedules/{sched_future.id}/start",
        headers=student_headers,
        json={"exam_center_id": "HALL-A1"},
    )
    assert early_res.status_code == 425
    assert "Early access forbidden" in early_res.text

    # 8. Assert Center Mismatch (HTTP 403)
    wrong_center_res = await client.post(
        f"/api/v1/schedules/{sched_active.id}/start",
        headers=student_headers,
        json={"exam_center_id": "WRONG-HALL"},
    )
    assert wrong_center_res.status_code == 403
    assert "Center mismatch" in wrong_center_res.text

    # 9. Successful Candidate Start on Active Schedule
    start_res = await client.post(
        f"/api/v1/schedules/{sched_active.id}/start",
        headers=student_headers,
        json={"exam_center_id": "HALL-A1"},
    )
    assert start_res.status_code == 200, f"Start failed: {start_res.text}"
    start_data = start_res.json()

    session_id = start_data["session_id"]
    session_token = start_data["session_token"]
    recovery_token = start_data["recovery_token"]
    assert len(session_token) > 20
    assert len(recovery_token) > 20
    assert len(start_data["questions"]) == 12
    assert start_data["watermark"]["student_id"] == student.id
    assert "forensic_hash" in start_data["watermark"]

    # 10. Autosave Candidate Response
    autosave_payload = {
        "session_token": session_token,
        "answers": {
            "3": "We use dynamic programming with table DP[m+1][n+1]. Time complexity is O(m*n).",
            "1": "T(n) = 2T(n/2) + O(n) yields case 2 of Master Theorem: T(n) = Theta(n log n).",
        },
    }
    autosave_res = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json=autosave_payload,
    )
    assert autosave_res.status_code == 200
    autosave_data = autosave_res.json()
    assert autosave_data["saved"] is True
    assert autosave_data["remaining_seconds"] > 0

    # 11. Interrupted Session Recovery
    recover_res = await client.post(
        "/api/v1/schedules/sessions/recover",
        json={"recovery_token": recovery_token},
    )
    assert recover_res.status_code == 200
    recover_data = recover_res.json()
    assert recover_data["session_id"] == session_id
    assert recover_data["saved_answers"]["3"].startswith("We use dynamic programming")
    assert len(recover_data["questions"]) == 12
    new_session_token = recover_data["new_session_token"]

    # 12. Final Submission
    submit_payload = {
        "session_token": new_session_token,
        "final_answers": recover_data["saved_answers"],
    }
    submit_res = await client.post(
        "/api/v1/schedules/sessions/submit",
        json=submit_payload,
    )
    assert submit_res.status_code == 200
    submit_data = submit_res.json()
    assert submit_data["session_id"] == session_id
    assert submit_data["status"] == StudentSessionStatus.submitted.value

    # 13. Block Further Autosaves on Submitted Session
    post_submit_autosave = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json=autosave_payload,
    )
    assert post_submit_autosave.status_code in [400, 403, 410]


def test_student_examination_html_and_reference_fidelity():
    """
    Verifies that frontend/student-exam.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "student-exam.html")
    js_path = os.path.join(frontend_dir, "js", "student-exam.js")
    css_path = os.path.join(frontend_dir, "css", "design-system.css")

    assert os.path.exists(page_path), "frontend/student-exam.html must exist"
    assert os.path.exists(js_path), "frontend/js/student-exam.js must exist"
    assert os.path.exists(css_path), "frontend/css/design-system.css must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()
    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # 1. Semantic Landmarks & Skip Link
    assert '<header class="student-exam-header"' in html
    assert '<main class="dashboard-content-wrap"' in html
    assert 'class="skip-to-main"' in html
    assert 'id="main-content"' in html

    # 2. Institutional Header Elements (Matches Reference Design)
    assert 'ExamOS' in html
    assert 'Candidate:' in html
    assert 'id="candidate-name-display"' in html
    assert 'id="candidate-roll-display"' in html
    assert 'id="exam-course-title"' in html
    assert 'id="timer-pill"' in html
    assert 'id="timer-countdown"' in html
    assert 'id="autosave-pill"' in html
    assert 'id="autosave-status-text"' in html

    # 3. Dynamic Forensic Watermark Overlay
    assert 'id="exam-watermark-overlay"' in html
    assert '.exam-watermark-overlay' in css
    assert 'pointer-events: none;' in css

    # 4. Question Workspace (Left/Center Pane)
    assert 'id="question-title-heading"' in html
    assert 'Question <span id="current-question-num">' in html
    assert '<span id="total-questions-num">' in html
    assert 'id="question-marks"' in html
    assert 'id="question-prompt-text"' in html
    assert 'id="question-code-block"' in html
    assert 'id="candidate-answer-input"' in html
    assert 'id="word-count-display"' in html
    assert 'id="char-count-display"' in html
    assert 'id="btn-prev-question"' in html
    assert 'id="btn-flag-review"' in html
    assert 'id="btn-next-question"' in html

    # 5. Question Palette Sidebar (Right Pane)
    assert 'Question Palette' in html
    assert 'id="palette-grid"' in html
    assert 'Answered' in html
    assert 'Unanswered' in html
    assert 'Flagged for Review' in html
    assert 'Candidate Session Info' in html
    assert 'id="session-info-start-time"' in html
    assert 'id="session-info-ip"' in html
    assert 'id="session-info-center"' in html
    assert 'id="session-info-recovery-token"' in html
    assert 'id="btn-open-submit-modal"' in html
    assert 'Final Submit' in html

    # 6. Six Explicit System States
    assert 'id="state-loading"' in html
    assert 'id="state-empty"' in html
    assert 'id="state-too-early"' in html
    assert 'id="state-permission-denied"' in html
    assert 'id="state-expired"' in html
    assert 'id="state-submitted"' in html

    # 7. Accessible Confirmation & Recovery Modals
    assert 'id="modal-submit-exam"' in html
    assert 'id="modal-count-answered"' in html
    assert 'id="modal-count-unanswered"' in html
    assert 'id="modal-count-flagged"' in html
    assert 'id="chk-confirm-submit"' in html
    assert 'id="btn-confirm-final-submit"' in html
    assert 'id="modal-recover-session"' in html
    assert 'id="recovery-token-input"' in html

    # 8. Vanilla JS Logic Assertions
    assert 'schedules/${scheduleId}/start' in js
    assert 'schedules/sessions/autosave' in js
    assert 'schedules/sessions/recover' in js
    assert 'schedules/sessions/submit' in js
    assert 'sessionStorage' in js
    assert 'startCountdownTimer' in js
    assert 'renderQuestionPalette' in js
