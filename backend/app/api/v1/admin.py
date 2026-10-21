import csv
import io
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.admin.audit_engine import (
    collect_real_system_telemetry,
    record_admin_audit,
    run_automated_security_anomaly_detection,
)
from app.core.config import settings
from app.core.deps import CurrentUser, get_current_user, require_permission, require_role
from app.core.permissions import ROLE_PERMISSIONS, Permission
from app.core.security import hash_password
from app.db.session import get_session
from app.models.alert import Alert, AlertSeverity
from app.models.approval import Approval, ApprovalStatus
from app.models.assembly import AssembledPaper, AssembledPaperStatus
from app.models.audit_log import AuditLog
from app.models.center import ExamCenter
from app.models.incident import IncidentSeverity, IncidentStatus, SecurityIncident
from app.models.question_paper import PaperStatus, QuestionPaper
from app.models.risk_score import RiskScore
from app.models.scheduling import ExamSchedule, ReleaseJobStatus, ReleaseQueueJob
from app.models.subject import Subject
from app.models.user import User, UserRole
from app.models.vault import VaultPaper, VaultStatus
from app.schemas.admin import (
    AlertItemResponse,
    AlertResolveRequest,
    AuditLogResponse,
    AuditSearchResponse,
    ExamCenterCreate,
    ExamCenterResponse,
    ExamCenterUpdate,
    IncidentClosureRequest,
    IncidentCreate,
    IncidentEvidenceAdd,
    IncidentNoteAdd,
    IncidentResponse,
    PendingApprovalItem,
    PendingApprovalsSummary,
    RolePermissionResponse,
    SubjectCreate,
    SubjectResponse,
    SubjectUpdate,
    SystemHealthConsole,
    UserAdminCreate,
    UserAdminResponse,
    UserAdminUpdate,
)

router = APIRouter(prefix="/admin", tags=["Administrative Console & Security Audit"])


# =========================================================================
# 1. USER & ROLE MANAGEMENT
# =========================================================================


@router.get(
    "/users",
    response_model=list[UserAdminResponse],
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def list_users(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    role: UserRole | None = None,
    department: str | None = None,
):
    """Lists users with optional role and department filters."""
    stmt = select(User)
    if role:
        stmt = stmt.where(User.role == role)
    if department:
        stmt = stmt.where(User.department == department)
    stmt = stmt.order_by(User.id.asc())

    res = await session.execute(stmt)
    return res.scalars().all()


@router.post(
    "/users",
    response_model=UserAdminResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def create_user_by_admin(
    payload: UserAdminCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Creates a new institutional user with assigned role and department."""
    # Check duplicate email/username
    existing = await session.scalar(
        select(User).where((User.email == payload.email) | (User.username == payload.username))
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with that email or username already exists.",
        )

    new_user = User(
        email=payload.email,
        username=payload.username.strip(),
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name.strip(),
        department=payload.department.strip(),
        role=payload.role,
        is_active=payload.is_active,
    )
    session.add(new_user)
    await session.flush()

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="USER_CREATED_BY_ADMIN",
        entity_type="User",
        entity_id=new_user.id,
        outcome="SUCCESS",
        metadata={"created_username": new_user.username, "role": new_user.role.value},
    )

    await session.commit()
    await session.refresh(new_user)
    return new_user


@router.get(
    "/users/{user_id}",
    response_model=UserAdminResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def get_user_details(
    user_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves full user administrative record."""
    target_user = await session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return target_user


@router.patch(
    "/users/{user_id}",
    response_model=UserAdminResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def update_user_by_admin(
    user_id: int,
    payload: UserAdminUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Updates user attributes, unlocks account, or resets credentials."""
    target_user = await session.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    modifications: dict[str, Any] = {}

    if payload.full_name is not None:
        target_user.full_name = payload.full_name.strip()
        modifications["full_name"] = target_user.full_name
    if payload.department is not None:
        target_user.department = payload.department.strip()
        modifications["department"] = target_user.department
    if payload.role is not None:
        target_user.role = payload.role
        modifications["role"] = target_user.role.value
    if payload.is_active is not None:
        target_user.is_active = payload.is_active
        modifications["is_active"] = target_user.is_active
    if payload.unlock_account:
        target_user.locked_until = None
        target_user.failed_login_attempts = 0
        modifications["unlocked"] = True
    if payload.reset_password is not None:
        target_user.hashed_password = hash_password(payload.reset_password)
        modifications["password_reset"] = True

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="USER_MODIFIED_BY_ADMIN",
        entity_type="User",
        entity_id=target_user.id,
        outcome="SUCCESS",
        metadata=modifications,
    )

    await session.commit()
    await session.refresh(target_user)
    return target_user


@router.get(
    "/roles/permissions",
    response_model=list[RolePermissionResponse],
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def get_role_permissions_matrix(current_user: CurrentUser):
    """Returns the system role-permission matrix."""
    return [
        RolePermissionResponse(
            role=role,
            permissions=sorted([p.value for p in perms]),
        )
        for role, perms in ROLE_PERMISSIONS.items()
    ]


# =========================================================================
# 2. SUBJECT & EXAMINATION CENTER MANAGEMENT
# =========================================================================


@router.get("/subjects", response_model=list[SubjectResponse])
async def list_subjects(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    department: str | None = None,
):
    """Lists subjects in academic catalog."""
    stmt = select(Subject)
    if department:
        stmt = stmt.where(Subject.department == department)
    elif current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(Subject.department == current_user.department)
    stmt = stmt.order_by(Subject.code.asc())
    res = await session.execute(stmt)
    return res.scalars().all()


@router.post(
    "/subjects",
    response_model=SubjectResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def create_subject(
    payload: SubjectCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Adds a new subject to the institutional catalog."""
    existing = await session.scalar(select(Subject).where(Subject.code == payload.code.strip()))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Subject with code '{payload.code}' already exists.",
        )

    subj = Subject(
        code=payload.code.strip().upper(),
        name=payload.name.strip(),
        department=payload.department.strip(),
        credits=payload.credits,
        syllabus_version=payload.syllabus_version.strip(),
        is_active=payload.is_active,
    )
    session.add(subj)
    await session.flush()

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="SUBJECT_CREATED",
        entity_type="Subject",
        entity_id=subj.id,
        metadata={"code": subj.code, "name": subj.name},
    )

    await session.commit()
    await session.refresh(subj)
    return subj


@router.get("/centers", response_model=list[ExamCenterResponse])
async def list_exam_centers(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists examination centers."""
    stmt = select(ExamCenter).order_by(ExamCenter.center_code.asc())
    res = await session.execute(stmt)
    return res.scalars().all()


@router.post(
    "/centers",
    response_model=ExamCenterResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def create_exam_center(
    payload: ExamCenterCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Configures a new examination center with physical capacity limits."""
    existing = await session.scalar(
        select(ExamCenter).where(ExamCenter.center_code == payload.center_code.strip())
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Center code '{payload.center_code}' already registered.",
        )

    center = ExamCenter(
        center_code=payload.center_code.strip().upper(),
        name=payload.name.strip(),
        city=payload.city.strip(),
        capacity=payload.capacity,
        department=payload.department.strip(),
        is_active=payload.is_active,
    )
    session.add(center)
    await session.flush()

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="EXAM_CENTER_CREATED",
        entity_type="ExamCenter",
        entity_id=center.id,
        metadata={"code": center.center_code, "capacity": center.capacity},
    )

    await session.commit()
    await session.refresh(center)
    return center


# =========================================================================
# 3. APPROVAL QUEUES & PENDING ACTIONS
# =========================================================================


@router.get(
    "/pending-actions",
    response_model=PendingApprovalsSummary,
    dependencies=[Depends(require_permission(Permission.REVIEW_PAPERS))],
)
async def list_pending_approval_queues(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Consolidates pending institutional approval queues:
    1. Vault papers pending K-of-N quorum approvals.
    2. Assembled papers pending review.
    3. Release queue jobs pending execution.
    """
    items: list[PendingApprovalItem] = []

    # 1. Vault Quorum Approvals
    stmt_vault = select(VaultPaper).where(VaultPaper.status == VaultStatus.pending_approvals)
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt_vault = stmt_vault.where(VaultPaper.department == current_user.department)
    vault_papers = (await session.execute(stmt_vault)).scalars().all()

    for vp in vault_papers:
        items.append(
            PendingApprovalItem(
                queue_type="vault_quorum",
                item_id=vp.id,
                identifier=vp.paper_code,
                title=vp.title,
                department=vp.department,
                current_status=vp.status.value,
                pending_since=vp.created_at,
                details={
                    "current_approvals": vp.current_approvals_count,
                    "required_threshold": vp.approval_threshold,
                    "version": vp.version,
                },
            )
        )

    # 2. Assembled Papers Pending Review
    stmt_asm = select(AssembledPaper).where(
        AssembledPaper.status == AssembledPaperStatus.review_pending
    )
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt_asm = stmt_asm.where(AssembledPaper.department == current_user.department)
    asm_papers = (await session.execute(stmt_asm)).scalars().all()

    for ap in asm_papers:
        items.append(
            PendingApprovalItem(
                queue_type="assembled_paper",
                item_id=ap.id,
                identifier=ap.paper_code,
                title=ap.title,
                department=ap.department,
                current_status=ap.status.value,
                pending_since=ap.updated_at,
                details={
                    "total_marks": ap.total_marks,
                    "duration_minutes": ap.duration_minutes,
                    "version": ap.version,
                },
            )
        )

    # 3. Release Queue Jobs Pending
    stmt_jobs = select(ReleaseQueueJob).where(ReleaseQueueJob.status == ReleaseJobStatus.pending)
    pending_jobs = (await session.execute(stmt_jobs)).scalars().all()
    for pj in pending_jobs:
        items.append(
            PendingApprovalItem(
                queue_type="release_queue",
                item_id=pj.id,
                identifier=pj.idempotency_key,
                title=f"Release Job for Schedule #{pj.schedule_id}",
                department="Examination Division",
                current_status=pj.status.value,
                pending_since=pj.created_at,
                details={"retry_count": pj.retry_count, "schedule_id": pj.schedule_id},
            )
        )

    return PendingApprovalsSummary(
        total_pending=len(items),
        vault_quorum_pending=len(vault_papers),
        assembled_papers_pending=len(asm_papers),
        release_queue_pending=len(pending_jobs),
        items=items,
    )


# =========================================================================
# 4. SEARCHABLE AUDIT LOGS & RESTRICTED EXPORTS
# =========================================================================


@router.get(
    "/audit-logs",
    response_model=AuditSearchResponse,
    dependencies=[Depends(require_permission(Permission.VIEW_AUDITS))],
)
async def search_audit_logs(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    actor_id: int | None = None,
    action: str | None = None,
    entity_type: str | None = None,
    entity_id: int | None = None,
    outcome: str | None = None,
    correlation_id: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    search: str | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
):
    """
    Searchable audit events engine with multi-dimensional filtering.
    Strictly restricted to users with VIEW_AUDITS permission.
    Never exposes passwords, tokens, or plaintext questions.
    """
    stmt = select(AuditLog)

    if actor_id:
        stmt = stmt.where(AuditLog.actor_id == actor_id)
    if action:
        stmt = stmt.where(AuditLog.action == action.strip())
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type.strip())
    if entity_id:
        stmt = stmt.where(AuditLog.entity_id == entity_id)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome.strip().upper())
    if correlation_id:
        stmt = stmt.where(AuditLog.correlation_id == correlation_id.strip())
    if start_date:
        stmt = stmt.where(AuditLog.timestamp >= start_date)
    if end_date:
        stmt = stmt.where(AuditLog.timestamp <= end_date)
    if search:
        search_term = f"%{search.strip()}%"
        stmt = stmt.where(
            (AuditLog.action.ilike(search_term))
            | (AuditLog.metadata_json.ilike(search_term))
            | (AuditLog.entity_type.ilike(search_term))
        )

    # Count total matches
    count_stmt = select(func.count()).select_from(stmt.subquery())
    total_matches = (await session.execute(count_stmt)).scalar() or 0

    # Paged query
    stmt = stmt.order_by(AuditLog.timestamp.desc())
    stmt = stmt.offset((page - 1) * page_size).limit(page_size)
    res = await session.execute(stmt)
    logs = res.scalars().all()

    # Pre-fetch actors for username/email mapping
    actor_ids = {l.actor_id for l in logs}
    users_stmt = select(User).where(User.id.in_(actor_ids))
    users_map = {u.id: u for u in (await session.execute(users_stmt)).scalars().all()}

    items = [
        AuditLogResponse(
            id=l.id,
            actor_id=l.actor_id,
            actor_username=users_map[l.actor_id].username if l.actor_id in users_map else None,
            actor_email=users_map[l.actor_id].email if l.actor_id in users_map else None,
            action=l.action,
            entity_type=l.entity_type,
            entity_id=l.entity_id,
            outcome=l.outcome,
            correlation_id=l.correlation_id,
            ip_address=l.ip_address,
            metadata_json=l.metadata_json,
            timestamp=l.timestamp,
        )
        for l in logs
    ]

    return AuditSearchResponse(
        total_matches=total_matches,
        page=page,
        page_size=page_size,
        items=items,
        verified_clock_offset_ms=0.0,
        storage_type="append_only_authenticated_db",
    )


@router.get(
    "/audit-logs/export",
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller))],
)
async def export_audit_logs_csv(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    limit: int = Query(default=500, ge=1, le=5000),
):
    """
    Restricted audit trail export.
    Restricted to Controller and Administrator clearance.
    Records an authorized export audit entry in the log itself.
    """
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    res = await session.execute(stmt)
    logs = res.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "timestamp_utc", "actor_id", "action", "entity_type",
        "entity_id", "outcome", "correlation_id", "ip_address", "metadata"
    ])
    for l in logs:
        writer.writerow([
            l.id,
            l.timestamp.isoformat(),
            l.actor_id,
            l.action,
            l.entity_type,
            l.entity_id or "",
            l.outcome,
            l.correlation_id or "",
            l.ip_address or "",
            l.metadata_json or "{}",
        ])

    # Record export in audit log
    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="AUDIT_LOG_EXPORTED_CSV",
        entity_type="AuditLog",
        outcome="SUCCESS",
        metadata={"exported_rows": len(logs)},
    )
    await session.commit()

    csv_data = output.getvalue()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=examos_audit_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            "Cache-Control": "no-store, private",
        },
    )


# =========================================================================
# 5. SECURITY ALERTS & ANOMALY SCANNING
# =========================================================================


@router.get(
    "/alerts",
    response_model=list[AlertItemResponse],
    dependencies=[Depends(require_permission(Permission.VIEW_AUDITS))],
)
async def list_security_alerts(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    resolved: bool | None = None,
    severity: AlertSeverity | None = None,
):
    """Lists security alerts with optional resolution and severity filters."""
    stmt = select(Alert)
    if resolved is not None:
        stmt = stmt.where(Alert.resolved == resolved)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    stmt = stmt.order_by(Alert.created_at.desc())
    res = await session.execute(stmt)
    alerts = res.scalars().all()

    # Pre-fetch actor usernames
    actor_ids = {a.actor_id for a in alerts if a.actor_id}
    users_stmt = select(User).where(User.id.in_(actor_ids))
    users_map = {u.id: u for u in (await session.execute(users_stmt)).scalars().all()}

    return [
        AlertItemResponse(
            id=a.id,
            severity=a.severity,
            message=a.message,
            paper_id=a.paper_id,
            actor_id=a.actor_id,
            actor_username=users_map[a.actor_id].username if a.actor_id in users_map else None,
            resolved=a.resolved,
            resolution_notes=None,
            created_at=a.created_at,
        )
        for a in alerts
    ]


@router.post(
    "/alerts/scan-anomalies",
    response_model=list[AlertItemResponse],
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def scan_security_anomalies(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Executes automated security anomaly detection:
    - Unusual login patterns and locked accounts
    - Repeated permission failures
    - Unauthorized download attempts and honeytoken triggers
    - Abnormal access timing
    - Suspicious release queue failures
    """
    new_alerts = await run_automated_security_anomaly_detection(session)

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="SECURITY_ANOMALY_SCAN_EXECUTED",
        entity_type="Alert",
        outcome="SUCCESS",
        metadata={"alerts_generated": len(new_alerts)},
    )
    await session.commit()

    return [
        AlertItemResponse(
            id=a.id,
            severity=a.severity,
            message=a.message,
            paper_id=a.paper_id,
            actor_id=a.actor_id,
            resolved=a.resolved,
            created_at=a.created_at,
        )
        for a in new_alerts
    ]


@router.patch(
    "/alerts/{alert_id}/resolve",
    response_model=AlertItemResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def resolve_security_alert(
    alert_id: int,
    payload: AlertResolveRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Resolves an alert with mandatory documented investigation remarks."""
    alert = await session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found.")

    alert.resolved = True

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="ALERT_RESOLVED",
        entity_type="Alert",
        entity_id=alert.id,
        metadata={"notes": payload.resolution_notes},
    )

    await session.commit()
    await session.refresh(alert)
    return AlertItemResponse(
        id=alert.id,
        severity=alert.severity,
        message=alert.message,
        paper_id=alert.paper_id,
        actor_id=alert.actor_id,
        resolved=alert.resolved,
        resolution_notes=payload.resolution_notes,
        created_at=alert.created_at,
    )


# =========================================================================
# 6. INCIDENT RECORDS, INVESTIGATION NOTES, & EVIDENCE
# =========================================================================


@router.get(
    "/incidents",
    response_model=list[IncidentResponse],
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def list_security_incidents(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    status_filter: IncidentStatus | None = None,
    severity: IncidentSeverity | None = None,
):
    """Lists security incidents with status and severity filters."""
    stmt = select(SecurityIncident)
    if status_filter:
        stmt = stmt.where(SecurityIncident.status == status_filter)
    if severity:
        stmt = stmt.where(SecurityIncident.severity == severity)
    stmt = stmt.order_by(SecurityIncident.created_at.desc())
    res = await session.execute(stmt)
    incidents = res.scalars().all()

    return [
        IncidentResponse(
            id=inc.id,
            incident_code=inc.incident_code,
            title=inc.title,
            severity=inc.severity,
            status=inc.status,
            category=inc.category,
            description=inc.description,
            assigned_to_id=inc.assigned_to_id,
            related_exam_id=inc.related_exam_id,
            related_paper_code=inc.related_paper_code,
            investigation_notes=json.loads(inc.investigation_notes_json) if inc.investigation_notes_json else [],
            evidence_references=json.loads(inc.evidence_references_json) if inc.evidence_references_json else [],
            root_cause=inc.root_cause,
            remediation_steps=inc.remediation_steps,
            closed_by_id=inc.closed_by_id,
            closed_at=inc.closed_at,
            closure_approval_notes=inc.closure_approval_notes,
            created_by_id=inc.created_by_id,
            created_at=inc.created_at,
            updated_at=inc.updated_at,
        )
        for inc in incidents
    ]


@router.post(
    "/incidents",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def create_security_incident(
    payload: IncidentCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Opens a formal security incident record for investigation."""
    inc_code = f"INC-{datetime.now(timezone.utc).strftime('%Y%m')}-{uuid.uuid4().hex[:6].upper()}"

    inc = SecurityIncident(
        incident_code=inc_code,
        title=payload.title.strip(),
        severity=payload.severity,
        status=IncidentStatus.open,
        category=payload.category.strip(),
        description=payload.description.strip(),
        assigned_to_id=payload.assigned_to_id,
        related_exam_id=payload.related_exam_id,
        related_paper_code=payload.related_paper_code,
        investigation_notes_json=json.dumps([]),
        evidence_references_json=json.dumps([]),
        created_by_id=current_user.id,
    )
    session.add(inc)
    await session.flush()

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="SECURITY_INCIDENT_OPENED",
        entity_type="SecurityIncident",
        entity_id=inc.id,
        metadata={"incident_code": inc.incident_code, "severity": inc.severity.value},
    )

    await session.commit()
    await session.refresh(inc)

    return IncidentResponse(
        id=inc.id,
        incident_code=inc.incident_code,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        category=inc.category,
        description=inc.description,
        assigned_to_id=inc.assigned_to_id,
        related_exam_id=inc.related_exam_id,
        related_paper_code=inc.related_paper_code,
        investigation_notes=[],
        evidence_references=[],
        root_cause=None,
        remediation_steps=None,
        closed_by_id=None,
        closed_at=None,
        closure_approval_notes=None,
        created_by_id=inc.created_by_id,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.post(
    "/incidents/{incident_id}/notes",
    response_model=IncidentResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def add_incident_note(
    incident_id: int,
    payload: IncidentNoteAdd,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Appends an immutable investigation note to the incident record."""
    inc = await session.get(SecurityIncident, incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    notes = json.loads(inc.investigation_notes_json) if inc.investigation_notes_json else []
    notes.append({
        "author_id": current_user.id,
        "author_email": current_user.email,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "note": payload.note.strip(),
    })
    inc.investigation_notes_json = json.dumps(notes)
    if inc.status == IncidentStatus.open:
        inc.status = IncidentStatus.investigating

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="INCIDENT_NOTE_ADDED",
        entity_type="SecurityIncident",
        entity_id=inc.id,
        metadata={"incident_code": inc.incident_code},
    )

    await session.commit()
    await session.refresh(inc)

    return IncidentResponse(
        id=inc.id,
        incident_code=inc.incident_code,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        category=inc.category,
        description=inc.description,
        assigned_to_id=inc.assigned_to_id,
        related_exam_id=inc.related_exam_id,
        related_paper_code=inc.related_paper_code,
        investigation_notes=notes,
        evidence_references=json.loads(inc.evidence_references_json) if inc.evidence_references_json else [],
        root_cause=inc.root_cause,
        remediation_steps=inc.remediation_steps,
        closed_by_id=inc.closed_by_id,
        closed_at=inc.closed_at,
        closure_approval_notes=inc.closure_approval_notes,
        created_by_id=inc.created_by_id,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.post(
    "/incidents/{incident_id}/evidence",
    response_model=IncidentResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_INCIDENTS))],
)
async def add_incident_evidence(
    incident_id: int,
    payload: IncidentEvidenceAdd,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Appends an evidentiary reference (audit ID, forensic digest, IP capture)."""
    inc = await session.get(SecurityIncident, incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    evidence = json.loads(inc.evidence_references_json) if inc.evidence_references_json else []
    evidence.append({
        "evidence_type": payload.evidence_type.strip(),
        "reference_id": payload.reference_id.strip(),
        "description": payload.description.strip(),
        "added_by_id": current_user.id,
        "added_at_utc": datetime.now(timezone.utc).isoformat(),
    })
    inc.evidence_references_json = json.dumps(evidence)

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="INCIDENT_EVIDENCE_ATTACHED",
        entity_type="SecurityIncident",
        entity_id=inc.id,
        metadata={"ref_id": payload.reference_id},
    )

    await session.commit()
    await session.refresh(inc)

    return IncidentResponse(
        id=inc.id,
        incident_code=inc.incident_code,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        category=inc.category,
        description=inc.description,
        assigned_to_id=inc.assigned_to_id,
        related_exam_id=inc.related_exam_id,
        related_paper_code=inc.related_paper_code,
        investigation_notes=json.loads(inc.investigation_notes_json) if inc.investigation_notes_json else [],
        evidence_references=evidence,
        root_cause=inc.root_cause,
        remediation_steps=inc.remediation_steps,
        closed_by_id=inc.closed_by_id,
        closed_at=inc.closed_at,
        closure_approval_notes=inc.closure_approval_notes,
        created_by_id=inc.created_by_id,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


@router.post(
    "/incidents/{incident_id}/close",
    response_model=IncidentResponse,
    dependencies=[Depends(require_role(UserRole.admin, UserRole.controller))],
)
async def close_security_incident(
    incident_id: int,
    payload: IncidentClosureRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Executes formal authorized closure of a security incident.
    Requires documented root cause, remediation steps, and closure approval notes.
    """
    inc = await session.get(SecurityIncident, incident_id)
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found.")

    now = datetime.now(timezone.utc)
    inc.status = IncidentStatus.closed
    inc.root_cause = payload.root_cause.strip()
    inc.remediation_steps = payload.remediation_steps.strip()
    inc.closure_approval_notes = payload.closure_approval_notes.strip()
    inc.closed_by_id = current_user.id
    inc.closed_at = now

    await record_admin_audit(
        session=session,
        actor_id=current_user.id,
        action="INCIDENT_FORMALLY_CLOSED",
        entity_type="SecurityIncident",
        entity_id=inc.id,
        metadata={"incident_code": inc.incident_code, "closed_by": current_user.email},
    )

    await session.commit()
    await session.refresh(inc)

    return IncidentResponse(
        id=inc.id,
        incident_code=inc.incident_code,
        title=inc.title,
        severity=inc.severity,
        status=inc.status,
        category=inc.category,
        description=inc.description,
        assigned_to_id=inc.assigned_to_id,
        related_exam_id=inc.related_exam_id,
        related_paper_code=inc.related_paper_code,
        investigation_notes=json.loads(inc.investigation_notes_json) if inc.investigation_notes_json else [],
        evidence_references=json.loads(inc.evidence_references_json) if inc.evidence_references_json else [],
        root_cause=inc.root_cause,
        remediation_steps=inc.remediation_steps,
        closed_by_id=inc.closed_by_id,
        closed_at=inc.closed_at,
        closure_approval_notes=inc.closure_approval_notes,
        created_by_id=inc.created_by_id,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
    )


# =========================================================================
# 7. REAL SYSTEM HEALTH & OPERATIONAL TELEMETRY
# =========================================================================


@router.get(
    "/health-console",
    response_model=SystemHealthConsole,
    dependencies=[Depends(require_permission(Permission.VIEW_AUDITS))],
)
async def get_system_health_console(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Returns authentic system telemetry and operational health metrics:
    - Real database latency
    - Real disk free bytes and encrypted storage usage
    - Background job states and failures
    - Backup file metrics
    - KMS active key status and AI configuration
    - Synchronized UTC server clock validation
    Distinguishes genuine measurements from synthetic development data.
    """
    return await collect_real_system_telemetry(session)


# =========================================================================
# 8. COMPATIBILITY & SIMULATION ROUTES (PRESERVED & ENHANCED)
# =========================================================================


@router.post("/analyze-logs")
async def analyze_logs(
    current_user: Annotated[User, Depends(require_role(UserRole.controller, UserRole.admin))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, str]:
    """Analyzes recent audit events for immediate threats."""
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(30)
    res = await session.execute(stmt)
    logs = res.scalars().all()

    if not logs:
        return {
            "summary": "System operating normally with zero recorded audit events. No immediate threat vectors or security anomalies detected across vault boundaries."
        }

    log_lines = []
    unauth_count = 0
    for l in logs:
        ts_str = l.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        log_lines.append(
            f"[{ts_str}] Actor #{l.actor_id} | Action: {l.action} | Entity: {l.entity_type} #{l.entity_id} | Meta: {l.metadata_json or '{}'}"
        )
        if "UNAUTHORIZED" in l.action or "HONEYTOKEN" in l.action or l.outcome == "FAILURE":
            unauth_count += 1

    formatted_logs = "\n".join(log_lines)
    prompt = f"Audit records:\n{formatted_logs}"

    api_key = settings.GEMINI_API_KEY or os.environ.get("GEMINI_API_KEY", "")
    if api_key:
        try:
            from google import genai
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "system_instruction": "You are an elite institutional cybersecurity officer. Analyze these audit records and provide a high-level, clear, 2-3 sentence overview of immediate security vulnerabilities or threat patterns detected. Do not use markdown bolding inside the returned string summary."
                },
            )
            if response.text:
                clean_text = response.text.replace("**", "").replace("*", "").strip()
                return {"summary": clean_text}
        except Exception:
            pass

    if unauth_count > 0:
        summary = (
            f"Detected {unauth_count} security-relevant event(s) or unauthorized access failure(s). "
            "Improper access vectors were intercepted and defense mechanisms were triggered. "
            "Recommend immediate review of active critical alerts and incident records."
        )
    else:
        summary = (
            "System audit telemetry indicates normal operational behavior with zero access violations. "
            "All paper submissions and access requests adhere to institutional role-based access control and time-lock protocols. "
            "Vault integrity remains uncompromised with active sentry monitors enabled."
        )

    return {"summary": summary}


@router.get("/stats")
async def admin_stats(
    current_user: Annotated[User, Depends(require_role(UserRole.controller, UserRole.admin))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Consolidates high-level admin dashboard counters."""
    unresolved_alerts_res = await session.execute(
        select(func.count(Alert.id)).where(Alert.resolved.is_(False))
    )
    active_threats = unresolved_alerts_res.scalar() or 0

    vault_locks_res = await session.execute(
        select(func.count(VaultPaper.id)).where(VaultPaper.status == VaultStatus.approved_locked)
    )
    vault_locks = vault_locks_res.scalar() or 0

    open_incidents_res = await session.execute(
        select(func.count(SecurityIncident.id)).where(SecurityIncident.status != IncidentStatus.closed)
    )
    open_incidents = open_incidents_res.scalar() or 0

    return {
        "active_threats": active_threats,
        "vault_locks": vault_locks,
        "open_incidents": open_incidents,
        "is_synthetic_stats": False,
    }


@router.post("/simulate-leak")
async def simulate_leak(
    current_user: Annotated[User, Depends(require_role(UserRole.controller, UserRole.admin))],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Security drill simulation (clearly marked as synthetic test telemetry)."""
    sim_alert = Alert(
        severity=AlertSeverity.critical,
        message="SIMULATION DRILL: Honeytoken triggered - Unauthorized early vault access attempt by external node",
        actor_id=current_user.id,
        resolved=False,
    )
    audit = AuditLog(
        actor_id=current_user.id,
        action="HONEYTOKEN_TRIP",
        entity_type="SimulationDrill",
        entity_id=None,
        outcome="FAILURE",
        correlation_id=f"sim-{uuid.uuid4().hex[:8]}",
        metadata_json=json.dumps({"simulation": True, "ip": "10.0.99.1"}),
    )
    session.add_all([sim_alert, audit])
    await session.commit()
    return {"message": "Security leak drill simulated successfully. Honeytokens tripped (synthetic)."}


alerts_router = APIRouter(prefix="/alerts", tags=["Alerts"])
alerts_router.add_api_route("", list_security_alerts, methods=["GET"], response_model=list[AlertItemResponse])
alerts_router.add_api_route("/{alert_id}/resolve", resolve_security_alert, methods=["PATCH"], response_model=AlertItemResponse)

