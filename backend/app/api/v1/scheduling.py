import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, get_current_user, require_role
from app.db.session import get_session
from app.models.scheduling import (
    ExamSchedule,
    ExamScheduleStatus,
    ReleaseQueueJob,
    StudentExamSession,
    StudentGroupRegistration,
)
from app.models.user import User, UserRole
from app.schemas.scheduling import (
    AutosaveRequest,
    AutosaveResponse,
    EmergencyCancelRequest,
    ExamStartRequest,
    ExamStartResponse,
    ReissueScheduleRequest,
    ReleaseQueueJobResponse,
    ScheduleCreate,
    ScheduleResponse,
    SessionRecoveryRequest,
    SessionRecoveryResponse,
    StudentRegistrationCreate,
    StudentRegistrationResponse,
    SubmitExamRequest,
    SubmitExamResponse,
)
from app.scheduling.release_engine import (
    CandidateIneligibleError,
    EarlyAccessForbiddenError,
    ExamWindowClosedError,
    PaperVersionMismatchError,
    SchedulingSecurityError,
    SessionExpiredError,
    SessionTerminatedError,
    UnapprovedPaperError,
    autosave_candidate_session,
    emergency_cancel_schedule,
    process_release_queue_job,
    recover_interrupted_session,
    reissue_schedule,
    start_candidate_session,
    submit_candidate_session,
)

router = APIRouter(prefix="/schedules", tags=["Examination Scheduling & Secure Release"])


# =========================================================================
# 1. SCHEDULE MANAGEMENT (AUTHORIZED STAFF ONLY)
# =========================================================================


@router.post(
    "",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller, UserRole.hod))],
)
async def create_exam_schedule(
    payload: ScheduleCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Creates an examination schedule with explicit institutional timezone handling
    and normalized UTC timestamps.
    """
    # Normalize start time to UTC
    t_start = (
        payload.start_time_utc.replace(tzinfo=timezone.utc)
        if payload.start_time_utc.tzinfo is None
        else payload.start_time_utc.astimezone(timezone.utc)
    )
    t_end = t_start + timedelta(minutes=payload.duration_minutes)

    schedule = ExamSchedule(
        vault_paper_id=payload.vault_paper_id,
        paper_code=payload.paper_code.strip(),
        approved_paper_version=payload.approved_paper_version,
        title=payload.title.strip(),
        department=payload.department.strip(),
        exam_center_id=payload.exam_center_id.strip(),
        eligible_group_id=payload.eligible_group_id.strip(),
        timezone=payload.timezone.strip(),
        start_time_utc=t_start,
        duration_minutes=payload.duration_minutes,
        end_time_utc=t_end,
        grace_period_minutes=payload.grace_period_minutes,
        status=ExamScheduleStatus.scheduled,
        created_by=current_user.id,
    )
    session.add(schedule)
    await session.commit()
    await session.refresh(schedule)
    return schedule


@router.get("", response_model=list[ScheduleResponse])
async def list_exam_schedules(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Lists schedules accessible to the requesting user.
    - Students: Only see metadata of examinations for which their group & center are registered.
    - Staff: Department or institution wide.
    NEVER leaks paper contents or plaintext questions prior to scheduled release.
    """
    stmt = select(ExamSchedule)

    if current_user.role == UserRole.student:
        reg_stmt = select(StudentGroupRegistration).where(
            StudentGroupRegistration.student_id == current_user.id,
            StudentGroupRegistration.is_eligible.is_(True),
        )
        reg_res = await session.execute(reg_stmt)
        regs = reg_res.scalars().all()
        if not regs:
            return []

        group_ids = [r.group_id for r in regs]
        center_ids = [r.exam_center_id for r in regs]
        stmt = stmt.where(
            ExamSchedule.eligible_group_id.in_(group_ids),
            ExamSchedule.exam_center_id.in_(center_ids),
        )
    elif current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(ExamSchedule.department == current_user.department)

    stmt = stmt.order_by(ExamSchedule.start_time_utc.asc())
    res = await session.execute(stmt)
    return res.scalars().all()


@router.get("/public-lookup", response_model=list[ScheduleResponse])
async def public_schedule_lookup(
    session: Annotated[AsyncSession, Depends(get_session)],
    query: str = Query(..., min_length=2, max_length=100),
):
    """
    Public lookup for approved examination schedules and centers.
    Allows candidates and center staff to verify scheduled times and centers.
    Zero paper questions, answers, or decryption metadata are ever exposed.
    """
    search_term = f"%{query.strip()}%"
    stmt = (
        select(ExamSchedule)
        .where(
            (ExamSchedule.paper_code.ilike(search_term))
            | (ExamSchedule.title.ilike(search_term))
            | (ExamSchedule.department.ilike(search_term))
            | (ExamSchedule.exam_center_id.ilike(search_term))
        )
        .order_by(ExamSchedule.start_time_utc.asc())
        .limit(20)
    )
    res = await session.execute(stmt)
    return res.scalars().all()


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_exam_schedule(
    schedule_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Retrieves schedule metadata with object-level authorization.
    Never exposes paper questions before scheduled release.
    """
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    if current_user.role == UserRole.student:
        reg_stmt = select(StudentGroupRegistration).where(
            StudentGroupRegistration.student_id == current_user.id,
            StudentGroupRegistration.group_id == schedule.eligible_group_id,
            StudentGroupRegistration.exam_center_id == schedule.exam_center_id,
            StudentGroupRegistration.is_eligible.is_(True),
        )
        reg_res = await session.execute(reg_stmt)
        if not reg_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Student is not registered for this examination schedule.",
            )
    elif current_user.role not in [UserRole.admin, UserRole.controller]:
        if schedule.department != current_user.department:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: Schedule belongs to another academic department.",
            )

    return schedule


@router.post(
    "/register-student",
    response_model=StudentRegistrationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller, UserRole.hod))],
)
async def register_student_group(
    payload: StudentRegistrationCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Registers a student to an eligible examination group and examination center.
    """
    student = await session.get(User, payload.student_id)
    if not student:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Student user not found.")

    reg = StudentGroupRegistration(
        student_id=payload.student_id,
        group_id=payload.group_id.strip(),
        exam_center_id=payload.exam_center_id.strip(),
        is_eligible=payload.is_eligible,
    )
    session.add(reg)
    await session.commit()
    await session.refresh(reg)
    return reg


# =========================================================================
# 2. CONTROLLED RELEASE QUEUE (WITH RETRIES & IDEMPOTENCY)
# =========================================================================


@router.post(
    "/{schedule_id}/enqueue-release",
    response_model=ReleaseQueueJobResponse,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller, UserRole.hod, UserRole.printer))],
)
async def enqueue_release_job(
    schedule_id: int,
    idempotency_key: Annotated[str, Query(..., min_length=4, max_length=128)],
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Dispatches a controlled release job through the server-side release queue.
    Guarantees idempotency and triggers alerts on repeated authorization failures.
    """
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    job = await process_release_queue_job(
        session=session,
        schedule_id=schedule_id,
        idempotency_key=idempotency_key,
    )
    return job


# =========================================================================
# 3. CANDIDATE EXAM SESSION LIFECYCLE (START, AUTOSAVE, RECOVER, SUBMIT)
# =========================================================================


@router.post("/{schedule_id}/start", response_model=ExamStartResponse)
async def start_exam(
    schedule_id: int,
    payload: ExamStartRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Candidate starts examination session.
    Server asserts:
    1. Early access boundary: now >= start_time_utc (rejection HTTP 425)
    2. Candidate is enrolled and eligible for center & group (rejection HTTP 403)
    3. Center match: candidate is at designated center (rejection HTTP 403)
    4. Currently approved paper version matches scheduled version (rejection HTTP 403)
    Returns questions, session token, recovery token, and dynamic recipient watermark.
    """
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    if schedule.exam_center_id != payload.exam_center_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Center mismatch: Scheduled for '{schedule.exam_center_id}', requested from '{payload.exam_center_id}'.",
        )

    client_ip = request.client.host if request.client else "127.0.0.1"

    try:
        exam_session, questions, watermark = await start_candidate_session(
            session=session,
            student=current_user,
            schedule=schedule,
            client_ip=client_ip,
        )
    except EarlyAccessForbiddenError as exc:
        raise HTTPException(status_code=status.HTTP_425_TOO_EARLY, detail=str(exc))
    except ExamWindowClosedError as exc:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(exc))
    except (CandidateIneligibleError, UnapprovedPaperError, SessionTerminatedError) as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except SchedulingSecurityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    now = datetime.now(timezone.utc)
    t_exp = exam_session.expires_at.replace(tzinfo=timezone.utc) if exam_session.expires_at.tzinfo is None else exam_session.expires_at
    remaining = max(0, int((t_exp - now).total_seconds()))

    return ExamStartResponse(
        session_id=exam_session.id,
        session_token=exam_session.session_token,
        recovery_token=exam_session.recovery_token,
        schedule_id=schedule.id,
        student_id=current_user.id,
        started_at=exam_session.started_at,
        expires_at=exam_session.expires_at,
        remaining_seconds=remaining,
        questions=questions,
        watermark=watermark,
    )


@router.post("/sessions/autosave", response_model=AutosaveResponse)
async def autosave_exam(
    payload: AutosaveRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Candidate autosaves answer state.
    Enforces strict timeout. Rejects autosave after session expiration with HTTP 410.
    """
    try:
        exam_session = await autosave_candidate_session(
            session=session,
            session_token=payload.session_token,
            answers=payload.answers,
        )
    except SessionExpiredError as exc:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(exc))
    except SessionTerminatedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except SchedulingSecurityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    now = datetime.now(timezone.utc)
    t_exp = exam_session.expires_at.replace(tzinfo=timezone.utc) if exam_session.expires_at.tzinfo is None else exam_session.expires_at
    remaining = max(0, int((t_exp - now).total_seconds()))

    return AutosaveResponse(
        saved=True,
        last_heartbeat_at=exam_session.last_heartbeat_at,
        remaining_seconds=remaining,
    )


@router.post("/sessions/recover", response_model=SessionRecoveryResponse)
async def recover_session(
    payload: SessionRecoveryRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Recovers an interrupted examination session using single-use recovery token.
    Refreshes session token, returns saved answers, questions, and remaining time.
    """
    try:
        exam_session, questions, watermark = await recover_interrupted_session(
            session=session,
            recovery_token=payload.recovery_token,
        )
    except SessionExpiredError as exc:
        raise HTTPException(status_code=status.HTTP_410_GONE, detail=str(exc))
    except SessionTerminatedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except SchedulingSecurityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    now = datetime.now(timezone.utc)
    t_exp = exam_session.expires_at.replace(tzinfo=timezone.utc) if exam_session.expires_at.tzinfo is None else exam_session.expires_at
    remaining = max(0, int((t_exp - now).total_seconds()))
    saved_answers = json.loads(exam_session.answers_json) if exam_session.answers_json else {}

    return SessionRecoveryResponse(
        session_id=exam_session.id,
        new_session_token=exam_session.session_token,
        recovery_token=exam_session.recovery_token,
        status=exam_session.status,
        saved_answers=saved_answers,
        questions=questions,
        remaining_seconds=remaining,
        expires_at=exam_session.expires_at,
        watermark=watermark,
    )


@router.post("/sessions/submit", response_model=SubmitExamResponse)
async def submit_exam(
    payload: SubmitExamRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
):
    """
    Final submission of examination. Transitions session to 'submitted'.
    Prevents any further answers from being accepted.
    """
    try:
        exam_session = await submit_candidate_session(
            session=session,
            session_token=payload.session_token,
            final_answers=payload.final_answers,
        )
    except SessionTerminatedError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    except SchedulingSecurityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return SubmitExamResponse(
        session_id=exam_session.id,
        status=exam_session.status,
        submitted_at=exam_session.submitted_at or datetime.now(timezone.utc),
        message="Examination submitted successfully. Candidate response record is locked.",
    )


# =========================================================================
# 4. EMERGENCY CANCELLATION & REISSUE WORKFLOW
# =========================================================================


@router.post(
    "/{schedule_id}/cancel",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller, UserRole.hod))],
)
async def cancel_exam_schedule(
    schedule_id: int,
    payload: EmergencyCancelRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Executes documented emergency cancellation:
    - Stores institutional reason and list of approving officials
    - Sets schedule status to 'cancelled'
    - Immediately terminates all active candidate sessions
    """
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    updated_schedule = await emergency_cancel_schedule(
        session=session,
        schedule=schedule,
        reason=payload.reason,
        approval_officials=payload.approval_officials,
        actor=current_user,
    )
    return updated_schedule


@router.post(
    "/{schedule_id}/reissue",
    response_model=ScheduleResponse,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller, UserRole.hod))],
)
async def reissue_exam_schedule(
    schedule_id: int,
    payload: ReissueScheduleRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Reissues an examination schedule with documented approvals and new start time.
    """
    schedule = await session.get(ExamSchedule, schedule_id)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    t_new_start = (
        payload.new_start_time_utc.replace(tzinfo=timezone.utc)
        if payload.new_start_time_utc.tzinfo is None
        else payload.new_start_time_utc.astimezone(timezone.utc)
    )

    new_schedule = await reissue_schedule(
        session=session,
        original_schedule=schedule,
        new_start_time_utc=t_new_start,
        reason=payload.reason,
        approval_officials=payload.approval_officials,
        actor=current_user,
    )
    return new_schedule
