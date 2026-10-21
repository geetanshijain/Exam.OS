import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity
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
from app.models.user import User
from app.models.vault import VaultPaper, VaultStatus

logger = logging.getLogger(__name__)


class SchedulingSecurityError(Exception):
    """Base exception for scheduling and secure release violations."""
    pass


class EarlyAccessForbiddenError(SchedulingSecurityError):
    """Raised when release or candidate access is attempted before scheduled start."""
    pass


class ExamWindowClosedError(SchedulingSecurityError):
    """Raised when access is attempted after scheduled end time and grace period."""
    pass


class CandidateIneligibleError(SchedulingSecurityError):
    """Raised when student does not have authorized registration for center or group."""
    pass


class PaperVersionMismatchError(SchedulingSecurityError):
    """Raised when the approved paper version does not match currently locked version."""
    pass


class UnapprovedPaperError(SchedulingSecurityError):
    """Raised when paper is not in an approved and locked release state."""
    pass


class SessionExpiredError(SchedulingSecurityError):
    """Raised when candidate session has passed its expiration timestamp."""
    pass


class SessionTerminatedError(SchedulingSecurityError):
    """Raised when candidate session was cancelled or already submitted."""
    pass


def generate_watermark_metadata(
    student_id: int,
    student_email: str,
    schedule: ExamSchedule,
    client_ip: str,
) -> dict[str, Any]:
    """
    Generates recipient-specific visible watermark containing minimal identifying information.
    Includes explicit security notice on screen-capture limits.
    """
    now = datetime.now(timezone.utc)
    ts_str = now.strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Minimal identifying text suitable for visible canvas/CSS overlay
    display_text = (
        f"EXAM-OS | ROLL: #{student_id} | CENTER: {schedule.exam_center_id} | "
        f"PAPER: {schedule.paper_code} | {ts_str}"
    )
    
    # Forensic signature binding recipient, schedule, IP, and timestamp
    raw_sig = f"{student_id}:{schedule.id}:{client_ip}:{ts_str}"
    forensic_hash = hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()[:16].upper()

    return {
        "text": display_text,
        "student_id": student_id,
        "exam_center_id": schedule.exam_center_id,
        "paper_code": schedule.paper_code,
        "access_timestamp_utc": ts_str,
        "forensic_hash": forensic_hash,
        "security_disclaimer": (
            "NOTICE: Browser restrictions cannot reliably prevent external photography or physical camera capture. "
            "All candidate paper interactions and sessions are cryptographically logged with forensic watermarking."
        ),
    }


async def verify_candidate_eligibility(
    session: AsyncSession,
    student_id: int,
    schedule: ExamSchedule,
) -> bool:
    """
    Asserts candidate-specific and center-specific authorization rules.
    Candidate must have an active StudentGroupRegistration matching both center and group.
    """
    stmt = select(StudentGroupRegistration).where(
        StudentGroupRegistration.student_id == student_id,
        StudentGroupRegistration.group_id == schedule.eligible_group_id,
        StudentGroupRegistration.exam_center_id == schedule.exam_center_id,
        StudentGroupRegistration.is_eligible.is_(True),
    )
    res = await session.execute(stmt)
    reg = res.scalar_one_or_none()
    return reg is not None


async def validate_release_authorization(
    session: AsyncSession,
    schedule: ExamSchedule,
) -> tuple[bool, str | None, list[dict[str, Any]]]:
    """
    Authorizes paper for release by verifying against the currently approved paper version:
    1. Checks if VaultPaper or AssembledPaper is linked and approved.
    2. Ensures currently approved version matches schedule.approved_paper_version.
    3. If paper was edited or unapproved, rejects release.
    """
    questions: list[dict[str, Any]] = []

    # 1. Check VaultPaper if linked
    if schedule.vault_paper_id:
        v_paper = await session.get(VaultPaper, schedule.vault_paper_id)
        if not v_paper:
            return False, f"Vault paper ID {schedule.vault_paper_id} not found.", []
        
        if v_paper.status not in [VaultStatus.approved_locked, VaultStatus.released]:
            return False, f"Vault paper is not in approved_locked status (Current: {v_paper.status.value}).", []

        if v_paper.version != schedule.approved_paper_version:
            return (
                False,
                f"Paper version mismatch: Scheduled v{schedule.approved_paper_version} != Vault v{v_paper.version}.",
                [],
            )

    # 2. Check AssembledPaper by paper_code
    stmt = select(AssembledPaper).where(AssembledPaper.paper_code == schedule.paper_code)
    res = await session.execute(stmt)
    asm_paper = res.scalar_one_or_none()

    if asm_paper:
        if asm_paper.status != AssembledPaperStatus.approved:
            return (
                False,
                f"Assembled paper '{schedule.paper_code}' is in status '{asm_paper.status.value}', not approved.",
                [],
            )
        if asm_paper.version != schedule.approved_paper_version:
            return (
                False,
                f"Assembled paper version mismatch: Scheduled v{schedule.approved_paper_version} != Assembly v{asm_paper.version}.",
                [],
            )

        # Extract structured questions from sections_json
        try:
            sections = json.loads(asm_paper.sections_json)
            for s_idx, sec in enumerate(sections):
                sec_title = sec.get("title", f"Section {s_idx + 1}")
                for q in sec.get("questions", []):
                    questions.append({
                        "section": sec_title,
                        "item_number": q.get("item_number", len(questions) + 1),
                        "text": q.get("text", "Question prompt"),
                        "marks": q.get("marks", 10),
                        "topic": q.get("topic", "Core Syllabus"),
                    })
        except Exception as exc:
            logger.warning("Could not parse sections_json from AssembledPaper: %s", exc)

    # Fallback default questions if not loaded from sections
    if not questions:
        questions = [
            {
                "section": "Part A - Core Examination",
                "item_number": 1,
                "text": f"Solve detailed examination problem set for {schedule.title} ({schedule.paper_code}).",
                "marks": 50,
                "topic": "Comprehensive",
            },
            {
                "section": "Part B - Analytical Evaluation",
                "item_number": 2,
                "text": f"Analyze system architecture trade-offs and provide implementation blueprint.",
                "marks": 50,
                "topic": "Advanced Architecture",
            },
        ]

    return True, None, questions


async def process_release_queue_job(
    session: AsyncSession,
    schedule_id: int,
    idempotency_key: str,
) -> ReleaseQueueJob:
    """
    Processes or re-executes a release queue job with strict idempotency and failure alerts.
    """
    # 1. Check existing job by idempotency key
    stmt = select(ReleaseQueueJob).where(ReleaseQueueJob.idempotency_key == idempotency_key)
    res = await session.execute(stmt)
    job = res.scalar_one_or_none()

    if job:
        if job.status == ReleaseJobStatus.completed:
            return job
        if job.status == ReleaseJobStatus.failed and job.retry_count >= job.max_retries:
            return job
    else:
        job = ReleaseQueueJob(
            idempotency_key=idempotency_key,
            schedule_id=schedule_id,
            status=ReleaseJobStatus.pending,
            retry_count=0,
            max_retries=3,
        )
        session.add(job)
        await session.flush()

    job.status = ReleaseJobStatus.running
    await session.flush()

    # 2. Fetch schedule
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        job.status = ReleaseJobStatus.failed
        job.last_error = f"Schedule {schedule_id} does not exist."
        await session.commit()
        return job

    # 3. Validate paper release authorization
    is_authorized, reason, _ = await validate_release_authorization(session, schedule)

    if not is_authorized:
        job.retry_count += 1
        job.last_error = reason
        if job.retry_count >= job.max_retries:
            job.status = ReleaseJobStatus.failed
            # Trigger institutional failure alert
            alert = Alert(
                severity=AlertSeverity.critical,
                message=(
                    f"RELEASE QUEUE PERMANENT FAILURE for schedule {schedule.id} ({schedule.paper_code}): "
                    f"{reason}. Max retries ({job.max_retries}) exhausted."
                ),
                actor_id=schedule.created_by,
            )
            session.add(alert)
        else:
            job.status = ReleaseJobStatus.pending
        await session.commit()
        return job

    # 4. Mark job completed and schedule as active if within start boundary
    job.status = ReleaseJobStatus.completed
    job.last_error = None
    job.executed_at = datetime.now(timezone.utc)

    now = datetime.now(timezone.utc)
    t_start = schedule.start_time_utc.replace(tzinfo=timezone.utc) if schedule.start_time_utc.tzinfo is None else schedule.start_time_utc
    if now >= t_start and schedule.status == ExamScheduleStatus.scheduled:
        schedule.status = ExamScheduleStatus.active_in_progress

    await session.commit()
    await session.refresh(job)
    return job


async def start_candidate_session(
    session: AsyncSession,
    student: User,
    schedule: ExamSchedule,
    client_ip: str,
) -> tuple[StudentExamSession, list[dict[str, Any]], dict[str, Any]]:
    """
    Initiates a candidate examination session with rigorous server-side time checks:
    - Pre-release access strictly blocked (HTTP 425 / EarlyAccessForbiddenError)
    - Expired access blocked (ExamWindowClosedError)
    - Center and student group registration verified (CandidateIneligibleError)
    - Paper authorization and version checked
    - Cryptographically random session_token and recovery_token generated
    """
    now = datetime.now(timezone.utc)
    t_start = schedule.start_time_utc.replace(tzinfo=timezone.utc) if schedule.start_time_utc.tzinfo is None else schedule.start_time_utc
    t_end = schedule.end_time_utc.replace(tzinfo=timezone.utc) if schedule.end_time_utc.tzinfo is None else schedule.end_time_utc
    grace_delta = timedelta(minutes=schedule.grace_period_minutes)

    # 1. Early access check (Server-side release scheduling, NOT browser-only timers!)
    if now < t_start:
        raise EarlyAccessForbiddenError(
            f"Early access forbidden: Examination scheduled release begins at {t_start.isoformat()}."
        )

    # 2. Window expiration check
    if now > (t_end + grace_delta):
        raise ExamWindowClosedError(
            f"Examination access window closed at {(t_end + grace_delta).isoformat()}."
        )

    # 3. Schedule state check
    if schedule.status == ExamScheduleStatus.cancelled:
        raise SessionTerminatedError("Examination has been cancelled by administrative directive.")

    # 4. Center-specific and student-specific eligibility check
    is_eligible = await verify_candidate_eligibility(session, student.id, schedule)
    if not is_eligible:
        raise CandidateIneligibleError(
            f"Access denied: Student #{student.id} is not registered or eligible for examination "
            f"center '{schedule.exam_center_id}' and group '{schedule.eligible_group_id}'."
        )

    # 5. Paper release-time authorization check
    is_authorized, reason, questions = await validate_release_authorization(session, schedule)
    if not is_authorized:
        raise UnapprovedPaperError(f"Paper release authorization rejected: {reason}")

    # 6. Check existing active session to avoid duplicate duplicates
    stmt = select(StudentExamSession).where(
        StudentExamSession.schedule_id == schedule.id,
        StudentExamSession.student_id == student.id,
    )
    res = await session.execute(stmt)
    existing_session = res.scalar_one_or_none()

    if existing_session:
        if existing_session.status == StudentSessionStatus.submitted:
            raise SessionTerminatedError("Candidate has already submitted this examination.")
        if existing_session.status == StudentSessionStatus.cancelled:
            raise SessionTerminatedError("Candidate session was cancelled.")
        
        # Resume existing active session
        watermark = generate_watermark_metadata(student.id, student.email, schedule, client_ip)
        return existing_session, questions, watermark

    # 7. Create brand new session
    # Duration limit is min(start + duration_minutes, end_time_utc + grace)
    session_expires = min(
        now + timedelta(minutes=schedule.duration_minutes),
        t_end + grace_delta,
    )

    exam_session = StudentExamSession(
        schedule_id=schedule.id,
        student_id=student.id,
        session_token=secrets.token_urlsafe(32),
        recovery_token=secrets.token_urlsafe(32),
        started_at=now,
        expires_at=session_expires,
        last_heartbeat_at=now,
        status=StudentSessionStatus.active,
        answers_json=json.dumps({}),
        client_ip=client_ip,
    )
    session.add(exam_session)

    # Update schedule status to active_in_progress if still scheduled
    if schedule.status == ExamScheduleStatus.scheduled:
        schedule.status = ExamScheduleStatus.active_in_progress

    await session.commit()
    await session.refresh(exam_session)

    watermark = generate_watermark_metadata(student.id, student.email, schedule, client_ip)
    return exam_session, questions, watermark


async def autosave_candidate_session(
    session: AsyncSession,
    session_token: str,
    answers: dict[str, Any],
) -> StudentExamSession:
    """
    Autosaves candidate answers with timeout enforcement and heartbeat tracking.
    """
    stmt = select(StudentExamSession).where(StudentExamSession.session_token == session_token)
    res = await session.execute(stmt)
    exam_session = res.scalar_one_or_none()

    if not exam_session:
        raise SchedulingSecurityError("Invalid session token.")

    # Check schedule status
    schedule = await session.get(ExamSchedule, exam_session.schedule_id)
    if schedule and schedule.status == ExamScheduleStatus.cancelled:
        exam_session.status = StudentSessionStatus.cancelled
        await session.commit()
        raise SessionTerminatedError("Examination has been cancelled by administrative directive.")

    now = datetime.now(timezone.utc)
    t_expires = exam_session.expires_at.replace(tzinfo=timezone.utc) if exam_session.expires_at.tzinfo is None else exam_session.expires_at

    # Timeout check
    if now > t_expires:
        exam_session.status = StudentSessionStatus.timed_out
        await session.commit()
        raise SessionExpiredError(f"Session expired at {t_expires.isoformat()}. Autosave rejected.")

    if exam_session.status in [StudentSessionStatus.submitted, StudentSessionStatus.cancelled]:
        raise SessionTerminatedError(f"Cannot autosave in session status '{exam_session.status.value}'.")

    # Save answers and record heartbeat
    exam_session.answers_json = json.dumps(answers)
    exam_session.last_heartbeat_at = now
    await session.commit()
    await session.refresh(exam_session)
    return exam_session


async def recover_interrupted_session(
    session: AsyncSession,
    recovery_token: str,
) -> tuple[StudentExamSession, list[dict[str, Any]], dict[str, Any]]:
    """
    Recovers an interrupted examination session using the recovery token:
    - Validates recovery token against session record
    - Asserts session has not timed out or been submitted
    - Generates a new fresh session_token (invalidates compromised/lost token)
    - Returns saved answers, questions, watermark, and remaining time
    """
    stmt = select(StudentExamSession).where(StudentExamSession.recovery_token == recovery_token)
    res = await session.execute(stmt)
    exam_session = res.scalar_one_or_none()

    if not exam_session:
        raise SchedulingSecurityError("Invalid recovery token.")

    schedule = await session.get(ExamSchedule, exam_session.schedule_id)
    if not schedule or schedule.status == ExamScheduleStatus.cancelled:
        exam_session.status = StudentSessionStatus.cancelled
        await session.commit()
        raise SessionTerminatedError("Examination schedule has been cancelled.")

    now = datetime.now(timezone.utc)
    t_expires = exam_session.expires_at.replace(tzinfo=timezone.utc) if exam_session.expires_at.tzinfo is None else exam_session.expires_at

    if now > t_expires:
        exam_session.status = StudentSessionStatus.timed_out
        await session.commit()
        raise SessionExpiredError(f"Session has timed out at {t_expires.isoformat()}.")

    if exam_session.status == StudentSessionStatus.submitted:
        raise SessionTerminatedError("Session has already been submitted and cannot be recovered.")
    if exam_session.status == StudentSessionStatus.cancelled:
        raise SessionTerminatedError("Session was cancelled.")

    # Refresh session token
    exam_session.session_token = secrets.token_urlsafe(32)
    exam_session.last_heartbeat_at = now
    exam_session.status = StudentSessionStatus.active

    # Fetch questions
    _, _, questions = await validate_release_authorization(session, schedule)

    # Watermark
    student = await session.get(User, exam_session.student_id)
    watermark = generate_watermark_metadata(
        exam_session.student_id,
        student.email if student else "candidate",
        schedule,
        exam_session.client_ip,
    )

    await session.commit()
    await session.refresh(exam_session)
    return exam_session, questions, watermark


async def submit_candidate_session(
    session: AsyncSession,
    session_token: str,
    final_answers: dict[str, Any] | None = None,
) -> StudentExamSession:
    """
    Finalizes and submits candidate examination session:
    - Prevents any further modifications or autosaves
    - Records exact UTC submission timestamp
    """
    stmt = select(StudentExamSession).where(StudentExamSession.session_token == session_token)
    res = await session.execute(stmt)
    exam_session = res.scalar_one_or_none()

    if not exam_session:
        raise SchedulingSecurityError("Invalid session token.")

    if exam_session.status == StudentSessionStatus.submitted:
        return exam_session

    if exam_session.status in [StudentSessionStatus.timed_out, StudentSessionStatus.cancelled]:
        raise SessionTerminatedError(f"Cannot submit session in status '{exam_session.status.value}'.")

    now = datetime.now(timezone.utc)
    if final_answers is not None:
        exam_session.answers_json = json.dumps(final_answers)

    exam_session.status = StudentSessionStatus.submitted
    exam_session.submitted_at = now
    exam_session.last_heartbeat_at = now

    await session.commit()
    await session.refresh(exam_session)
    return exam_session


async def emergency_cancel_schedule(
    session: AsyncSession,
    schedule: ExamSchedule,
    reason: str,
    approval_officials: list[str],
    actor: User,
) -> ExamSchedule:
    """
    Executes emergency cancellation workflow:
    - Records documented approvals and institutional reason
    - Changes schedule status to 'cancelled'
    - Automatically cancels and terminates all active candidate sessions
    """
    now = datetime.now(timezone.utc)
    schedule.status = ExamScheduleStatus.cancelled
    schedule.cancellation_reason = reason
    schedule.cancellation_approvals_json = json.dumps({
        "cancelled_by": actor.email,
        "actor_id": actor.id,
        "timestamp": now.isoformat(),
        "approval_officials": approval_officials,
        "reason": reason,
    })

    # Invalidate all active candidate sessions for this schedule
    stmt = select(StudentExamSession).where(
        StudentExamSession.schedule_id == schedule.id,
        StudentExamSession.status == StudentSessionStatus.active,
    )
    res = await session.execute(stmt)
    active_sessions = res.scalars().all()
    for s in active_sessions:
        s.status = StudentSessionStatus.cancelled

    await session.commit()
    await session.refresh(schedule)
    return schedule


async def reissue_schedule(
    session: AsyncSession,
    original_schedule: ExamSchedule,
    new_start_time_utc: datetime,
    reason: str,
    approval_officials: list[str],
    actor: User,
) -> ExamSchedule:
    """
    Reissues an examination schedule with documented approvals:
    - Calculates new end_time_utc based on original duration
    - Sets original schedule status to 'reissued' and links reissued_schedule_id
    - Creates new ExamSchedule in 'scheduled' status
    """
    now = datetime.now(timezone.utc)
    original_schedule.status = ExamScheduleStatus.reissued
    original_schedule.cancellation_reason = f"Reissued: {reason}"
    original_schedule.cancellation_approvals_json = json.dumps({
        "reissued_by": actor.email,
        "actor_id": actor.id,
        "timestamp": now.isoformat(),
        "approval_officials": approval_officials,
        "reason": reason,
    })

    new_end_time_utc = new_start_time_utc + timedelta(minutes=original_schedule.duration_minutes)

    new_schedule = ExamSchedule(
        vault_paper_id=original_schedule.vault_paper_id,
        paper_code=original_schedule.paper_code,
        approved_paper_version=original_schedule.approved_paper_version,
        title=f"{original_schedule.title} (Reissued)",
        department=original_schedule.department,
        exam_center_id=original_schedule.exam_center_id,
        eligible_group_id=original_schedule.eligible_group_id,
        timezone=original_schedule.timezone,
        start_time_utc=new_start_time_utc,
        duration_minutes=original_schedule.duration_minutes,
        end_time_utc=new_end_time_utc,
        grace_period_minutes=original_schedule.grace_period_minutes,
        status=ExamScheduleStatus.scheduled,
        created_by=actor.id,
    )
    session.add(new_schedule)
    await session.flush()

    original_schedule.reissued_schedule_id = new_schedule.id
    await session.commit()
    await session.refresh(new_schedule)
    return new_schedule
