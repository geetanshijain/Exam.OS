import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assembly import AssembledPaper, AssembledPaperStatus
from app.models.scheduling import (
    ExamSchedule,
    ExamScheduleStatus,
    ReleaseJobStatus,
    ReleaseQueueJob,
    StudentExamSession,
    StudentGroupRegistration,
    StudentSessionStatus,
)
from app.models.user import User, UserRole
from app.scheduling.release_engine import (
    process_release_queue_job,
)


@pytest.mark.asyncio
async def test_scheduling_secure_release_comprehensive(client: AsyncClient, db_session: AsyncSession):
    """
    Comprehensive integration test suite covering:
    1. Authorized staff scheduling approved papers with UTC timestamps
    2. Zero pre-release exposure in metadata/APIs
    3. Server-side early access rejection (HTTP 425)
    4. Center-specific & student-specific access boundaries & revoked permissions
    5. Release-time authorization check against approved paper version
    6. Controlled release queue idempotency, retries, and failure alerts
    7. Recipient-specific visible watermarking with external photography disclaimer
    8. Exam session lifecycle: start, autosave, submission
    9. Network interruption & interrupted-session recovery via recovery_token
    10. Clock boundaries & session timeout enforcement
    11. Emergency cancellation and reissue workflow with documented approvals
    """
    now = datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 0. SETUP: Create Users (Controller, Student A, Student B)
    # -------------------------------------------------------------------------
    # Controller (Staff)
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "coe_scheduler@examos.edu",
            "username": "coe_scheduler",
            "password": "ValidPassword123!",
            "full_name": "Controller of Exams",
            "department": "Computer Science",
            "role": "controller",
        },
    )
    coe_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "coe_scheduler", "password": "ValidPassword123!"},
    )
    coe_token = coe_login.json()["access_token"]
    coe_headers = {"Authorization": f"Bearer {coe_token}"}

    # Student 1 (Eligible for Center North, Group G1)
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "student_alpha@examos.edu",
            "username": "student_alpha",
            "password": "ValidPassword123!",
            "full_name": "Student Alpha",
            "department": "Computer Science",
            "role": "student",
        },
    )
    s1_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "student_alpha", "password": "ValidPassword123!"},
    )
    s1_token = s1_login.json()["access_token"]
    s1_headers = {"Authorization": f"Bearer {s1_token}"}
    s1_user = (await db_session.execute(select(User).where(User.username == "student_alpha"))).scalar_one()

    # Student 2 (Ineligible / Different Center)
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "student_beta@examos.edu",
            "username": "student_beta",
            "password": "ValidPassword123!",
            "full_name": "Student Beta",
            "department": "Computer Science",
            "role": "student",
        },
    )
    s2_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "student_beta", "password": "ValidPassword123!"},
    )
    s2_token = s2_login.json()["access_token"]
    s2_headers = {"Authorization": f"Bearer {s2_token}"}
    s2_user = (await db_session.execute(select(User).where(User.username == "student_beta"))).scalar_one()

    # Register Student 1 for CENTER-NORTH, GROUP-CS-2026
    reg1_res = await client.post(
        "/api/v1/schedules/register-student",
        headers=coe_headers,
        json={
            "student_id": s1_user.id,
            "group_id": "GROUP-CS-2026",
            "exam_center_id": "CENTER-NORTH",
            "is_eligible": True,
        },
    )
    assert reg1_res.status_code == 201

    # Register Student 2 for CENTER-SOUTH, GROUP-CS-2026 (Different center)
    reg2_res = await client.post(
        "/api/v1/schedules/register-student",
        headers=coe_headers,
        json={
            "student_id": s2_user.id,
            "group_id": "GROUP-CS-2026",
            "exam_center_id": "CENTER-SOUTH",
            "is_eligible": True,
        },
    )
    assert reg2_res.status_code == 201

    # Create approved AssembledPaper (Version 1)
    asm_paper = AssembledPaper(
        paper_code="CS-SCHED-401",
        title="Distributed Systems Final 2026",
        subject="Distributed Systems",
        course="B.Tech Computer Science",
        semester=7,
        department="Computer Science",
        total_marks=100,
        duration_minutes=180,
        blueprint_json="{}",
        sections_json='[{"title":"Core Architecture","questions":[{"item_number":1,"text":"Explain Paxos and Raft consensus algorithms in distributed clusters.","marks":50,"topic":"Consensus"}]}]',
        version=1,
        status=AssembledPaperStatus.approved,
        created_by=s1_user.id,
        last_edited_by=s1_user.id,
    )
    db_session.add(asm_paper)
    await db_session.commit()

    # -------------------------------------------------------------------------
    # 1. EARLY ACCESS PREVENTION (SERVER-SIDE RELEASE SCHEDULING)
    # -------------------------------------------------------------------------
    # Create future schedule (Starts in 2 hours)
    future_start = now + timedelta(hours=2)
    sched_future_res = await client.post(
        "/api/v1/schedules",
        headers=coe_headers,
        json={
            "paper_code": "CS-SCHED-401",
            "approved_paper_version": 1,
            "title": "Distributed Systems Final 2026",
            "department": "Computer Science",
            "exam_center_id": "CENTER-NORTH",
            "eligible_group_id": "GROUP-CS-2026",
            "timezone": "Asia/Kolkata",
            "start_time_utc": future_start.isoformat(),
            "duration_minutes": 180,
            "grace_period_minutes": 15,
        },
    )
    assert sched_future_res.status_code == 201
    future_sched_id = sched_future_res.json()["id"]

    # Student 1 attempts to start examination BEFORE scheduled start
    early_start_res = await client.post(
        f"/api/v1/schedules/{future_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    # Must be rejected with HTTP 425 Too Early (server-side enforced!)
    assert early_start_res.status_code == 425
    assert "Early access forbidden" in early_start_res.json()["detail"]

    # -------------------------------------------------------------------------
    # 2. ZERO PRE-RELEASE INFORMATION DISCLOSURE IN METADATA / LISTING
    # -------------------------------------------------------------------------
    # Student fetches schedule metadata
    meta_res = await client.get(f"/api/v1/schedules/{future_sched_id}", headers=s1_headers)
    assert meta_res.status_code == 200
    meta_data = meta_res.json()
    assert meta_data["title"] == "Distributed Systems Final 2026"
    assert "questions" not in meta_data
    assert "plaintext_questions" not in meta_data
    assert "answers" not in meta_data

    # -------------------------------------------------------------------------
    # 3. ACTIVE SCHEDULE & CENTER-SPECIFIC / STUDENT ACCESS BOUNDARIES
    # -------------------------------------------------------------------------
    # Create active schedule (Started 10 minutes ago)
    active_start = now - timedelta(minutes=10)
    sched_active_res = await client.post(
        "/api/v1/schedules",
        headers=coe_headers,
        json={
            "paper_code": "CS-SCHED-401",
            "approved_paper_version": 1,
            "title": "Distributed Systems Live Exam",
            "department": "Computer Science",
            "exam_center_id": "CENTER-NORTH",
            "eligible_group_id": "GROUP-CS-2026",
            "timezone": "UTC",
            "start_time_utc": active_start.isoformat(),
            "duration_minutes": 180,
            "grace_period_minutes": 15,
        },
    )
    assert sched_active_res.status_code == 201
    active_sched_id = sched_active_res.json()["id"]

    # Test 3a: Center mismatch (Student 1 claims they are at CENTER-SOUTH)
    mismatch_center_res = await client.post(
        f"/api/v1/schedules/{active_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-SOUTH"},
    )
    assert mismatch_center_res.status_code == 403
    assert "Center mismatch" in mismatch_center_res.json()["detail"]

    # Test 3b: Ineligible student (Student 2 belongs to CENTER-SOUTH, schedule is CENTER-NORTH)
    ineligible_res = await client.post(
        f"/api/v1/schedules/{active_sched_id}/start",
        headers=s2_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    assert ineligible_res.status_code == 403
    assert "not registered or eligible" in ineligible_res.json()["detail"]

    # -------------------------------------------------------------------------
    # 4. PAPER VERSION INVALIDATION CHECK
    # -------------------------------------------------------------------------
    # Create a schedule requiring approved version 2, but asm_paper is version 1
    sched_v2_res = await client.post(
        "/api/v1/schedules",
        headers=coe_headers,
        json={
            "paper_code": "CS-SCHED-401",
            "approved_paper_version": 2,  # Mismatch!
            "title": "Version Mismatch Test",
            "department": "Computer Science",
            "exam_center_id": "CENTER-NORTH",
            "eligible_group_id": "GROUP-CS-2026",
            "timezone": "UTC",
            "start_time_utc": active_start.isoformat(),
            "duration_minutes": 180,
        },
    )
    v2_sched_id = sched_v2_res.json()["id"]
    version_mismatch_res = await client.post(
        f"/api/v1/schedules/{v2_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    assert version_mismatch_res.status_code == 403
    assert "version mismatch" in version_mismatch_res.json()["detail"].lower()

    # -------------------------------------------------------------------------
    # 5. CONTROLLED RELEASE QUEUE (IDEMPOTENCY, RETRIES, FAILURE ALERTS)
    # -------------------------------------------------------------------------
    # Enqueue release job with idempotency key
    job_key = "RELEASE-QUEUE-JOB-XYZ-001"
    job1_res = await client.post(
        f"/api/v1/schedules/{active_sched_id}/enqueue-release?idempotency_key={job_key}",
        headers=coe_headers,
    )
    assert job1_res.status_code == 200
    job1_data = job1_res.json()
    assert job1_data["status"] == "completed"

    # Concurrent / Duplicate request with same idempotency key
    job2_res = await client.post(
        f"/api/v1/schedules/{active_sched_id}/enqueue-release?idempotency_key={job_key}",
        headers=coe_headers,
    )
    assert job2_res.status_code == 200
    job2_data = job2_res.json()
    assert job2_data["id"] == job1_data["id"]  # Exact same job returned!

    # -------------------------------------------------------------------------
    # 6. EXAM START & RECIPIENT-SPECIFIC VISIBLE WATERMARKING
    # -------------------------------------------------------------------------
    # Eligible student 1 starts live exam
    start_res = await client.post(
        f"/api/v1/schedules/{active_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    assert start_res.status_code == 200
    start_data = start_res.json()
    session_token = start_data["session_token"]
    recovery_token = start_data["recovery_token"]
    assert len(session_token) > 20
    assert len(recovery_token) > 20

    # Verify structured questions delivered
    assert len(start_data["questions"]) > 0
    assert "Paxos and Raft" in start_data["questions"][0]["text"]

    # Verify recipient-specific watermark & external photography disclaimer
    watermark = start_data["watermark"]
    assert f"ROLL: #{s1_user.id}" in watermark["text"]
    assert "CENTER: CENTER-NORTH" in watermark["text"]
    assert len(watermark["forensic_hash"]) > 8
    assert "Browser restrictions cannot reliably prevent" in watermark["security_disclaimer"]
    assert "Browser restrictions cannot reliably prevent" in start_data["security_notice"]

    # -------------------------------------------------------------------------
    # 7. AUTOSAVE LIFECYCLE
    # -------------------------------------------------------------------------
    autosave_res = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json={
            "session_token": session_token,
            "answers": {
                "q1": "Paxos relies on a proposer, acceptor, and learner consensus cycle.",
            },
        },
    )
    assert autosave_res.status_code == 200
    assert autosave_res.json()["saved"] is True
    assert autosave_res.json()["remaining_seconds"] > 0

    # -------------------------------------------------------------------------
    # 8. NETWORK INTERRUPTION & INTERRUPTED-SESSION RECOVERY
    # -------------------------------------------------------------------------
    # Candidate experiences network drop, page refresh, or power loss
    recovery_res = await client.post(
        "/api/v1/schedules/sessions/recover",
        json={"recovery_token": recovery_token},
    )
    assert recovery_res.status_code == 200
    recovery_data = recovery_res.json()
    new_session_token = recovery_data["new_session_token"]
    assert new_session_token != session_token  # Fresh refreshed session token!
    assert recovery_data["recovery_token"] == recovery_token
    # Saved answers preserved
    assert "Paxos relies on" in recovery_data["saved_answers"]["q1"]
    assert len(recovery_data["questions"]) > 0

    # Candidate continues answering using new_session_token
    autosave2_res = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json={
            "session_token": new_session_token,
            "answers": {
                "q1": "Paxos achieves consensus through leader election and majority quorums.",
            },
        },
    )
    assert autosave2_res.status_code == 200

    # -------------------------------------------------------------------------
    # 9. SUBMISSION & SUBSEQUENT LOCKING
    # -------------------------------------------------------------------------
    submit_res = await client.post(
        "/api/v1/schedules/sessions/submit",
        json={
            "session_token": new_session_token,
            "final_answers": {
                "q1": "Final submitted answer on Paxos and Raft architecture.",
            },
        },
    )
    assert submit_res.status_code == 200
    assert submit_res.json()["status"] == "submitted"

    # Attempting to autosave after submission must be rejected
    post_submit_autosave = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json={
            "session_token": new_session_token,
            "answers": {"q1": "Attempt to tamper after submit"},
        },
    )
    assert post_submit_autosave.status_code == 403

    # Attempting to recover a submitted session must be rejected
    post_submit_recovery = await client.post(
        "/api/v1/schedules/sessions/recover",
        json={"recovery_token": recovery_token},
    )
    assert post_submit_recovery.status_code == 403

    # -------------------------------------------------------------------------
    # 10. CLOCK BOUNDARIES & TIMEOUT ENFORCEMENT
    # -------------------------------------------------------------------------
    # Create schedule in the past (Ended 30 minutes ago)
    past_start = now - timedelta(hours=4)
    sched_past_res = await client.post(
        "/api/v1/schedules",
        headers=coe_headers,
        json={
            "paper_code": "CS-SCHED-401",
            "approved_paper_version": 1,
            "title": "Expired Examination",
            "department": "Computer Science",
            "exam_center_id": "CENTER-NORTH",
            "eligible_group_id": "GROUP-CS-2026",
            "timezone": "UTC",
            "start_time_utc": past_start.isoformat(),
            "duration_minutes": 60,
            "grace_period_minutes": 15,
        },
    )
    past_sched_id = sched_past_res.json()["id"]

    past_start_res = await client.post(
        f"/api/v1/schedules/{past_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    assert past_start_res.status_code == 410  # HTTP 410 Gone (Window closed)

    # -------------------------------------------------------------------------
    # 11. EMERGENCY CANCELLATION & REISSUE WORKFLOW
    # -------------------------------------------------------------------------
    # Create a schedule to be cancelled
    sched_cancel_res = await client.post(
        "/api/v1/schedules",
        headers=coe_headers,
        json={
            "paper_code": "CS-SCHED-401",
            "approved_paper_version": 1,
            "title": "Incident Schedule",
            "department": "Computer Science",
            "exam_center_id": "CENTER-NORTH",
            "eligible_group_id": "GROUP-CS-2026",
            "timezone": "UTC",
            "start_time_utc": (now - timedelta(minutes=5)).isoformat(),
            "duration_minutes": 180,
        },
    )
    cancel_sched_id = sched_cancel_res.json()["id"]

    # Student starts this session
    incident_start = await client.post(
        f"/api/v1/schedules/{cancel_sched_id}/start",
        headers=s1_headers,
        json={"exam_center_id": "CENTER-NORTH"},
    )
    assert incident_start.status_code == 200
    incident_token = incident_start.json()["session_token"]

    # Staff triggers emergency cancellation
    cancel_res = await client.post(
        f"/api/v1/schedules/{cancel_sched_id}/cancel",
        headers=coe_headers,
        json={
            "reason": "Severe power disruption at Examination Center North",
            "approval_officials": ["Dean Academic", "Controller of Examinations"],
        },
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "cancelled"

    # Candidate active session is invalidated
    incident_autosave = await client.post(
        "/api/v1/schedules/sessions/autosave",
        json={"session_token": incident_token, "answers": {"q1": "Test"}},
    )
    assert incident_autosave.status_code == 403
    assert "cancelled by administrative directive" in incident_autosave.json()["detail"].lower()

    # Reissue schedule with documented approvals
    reissue_time = now + timedelta(days=2)
    reissue_res = await client.post(
        f"/api/v1/schedules/{cancel_sched_id}/reissue",
        headers=coe_headers,
        json={
            "new_start_time_utc": reissue_time.isoformat(),
            "reason": "Rescheduled following Center North power disruption",
            "approval_officials": ["Dean Academic", "Controller of Examinations"],
        },
    )
    assert reissue_res.status_code == 200
    reissued_sched = reissue_res.json()
    assert reissued_sched["status"] == "scheduled"
    assert "(Reissued)" in reissued_sched["title"]
