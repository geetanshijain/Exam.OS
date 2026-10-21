import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.assembly.builder import assemble_paper_sections
from app.assembly.pdf_generator import generate_accessible_html_preview, generate_paper_pdf
from app.assembly.validator import validate_assembled_paper
from app.core.deps import CurrentUser, get_current_user, require_permission
from app.core.permissions import Permission, verify_object_access
from app.db.session import get_session
from app.models.assembly import AssembledPaper, AssembledPaperStatus
from app.models.bank import BankQuestion, BankQuestionApprovalStatus
from app.models.user import User, UserRole
from app.schemas.assembly import (
    ApprovePaperRequest,
    AssemblePaperRequest,
    AssembledPaperResponse,
    PaperPreviewResponse,
    PaperValidationReport,
    UpdateAssembledPaperRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assembly", tags=["paper-assembly"])


def _serialize_assembled_paper(paper: AssembledPaper) -> AssembledPaperResponse:
    return AssembledPaperResponse(
        id=paper.id,
        paper_code=paper.paper_code,
        title=paper.title,
        subject=paper.subject,
        course=paper.course,
        semester=paper.semester,
        department=paper.department,
        total_marks=paper.total_marks,
        duration_minutes=paper.duration_minutes,
        syllabus_version=paper.syllabus_version,
        blueprint=json.loads(paper.blueprint_json),
        sections=json.loads(paper.sections_json),
        version=paper.version,
        generation_seed=paper.generation_seed,
        generation_version=paper.generation_version,
        status=paper.status,
        approval_history=json.loads(paper.approval_history_json) if paper.approval_history_json else [],
        created_by=paper.created_by,
        last_edited_by=paper.last_edited_by,
        approved_by=paper.approved_by,
        approved_at=paper.approved_at,
        created_at=paper.created_at,
        updated_at=paper.updated_at,
    )


async def _get_paper_with_auth(
    paper_id: int,
    session: AsyncSession,
    user: User,
    require_owner: bool = False,
) -> AssembledPaper:
    paper = await session.get(AssembledPaper, paper_id)
    if not paper:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assembled paper #{paper_id} not found.",
        )
    verify_object_access(
        user=user,
        resource_department=paper.department,
        resource_owner_id=paper.created_by,
        require_owner=require_owner,
    )
    return paper


# =========================================================================
# 1. ASSEMBLE PAPER
# =========================================================================


@router.post(
    "/papers",
    response_model=AssembledPaperResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def assemble_paper(
    payload: AssemblePaperRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Assembles a new examination paper based on explicit blueprint rules.
    Supports deterministic, reproducible selection when a seed is provided.
    """
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        if payload.department.strip().lower() != current_user.department.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Cannot assemble paper for department '{payload.department}'. Restricted to '{current_user.department}'.",
            )

    # Check for duplicate paper code
    existing_stmt = select(AssembledPaper).where(AssembledPaper.paper_code == payload.paper_code.strip())
    existing = (await session.execute(existing_stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"A question paper with code '{payload.paper_code}' already exists.",
        )

    # Fetch candidate bank questions for this subject/department
    bank_stmt = select(BankQuestion).where(
        BankQuestion.department == payload.department,
        BankQuestion.subject.ilike(f"%{payload.subject.strip()}%"),
    )
    bank_res = await session.execute(bank_stmt)
    bank_records = bank_res.scalars().all()

    bank_candidates = [
        {
            "question_id": bq.id,
            "question_text": bq.question_text,
            "marks": bq.marks,
            "difficulty": bq.difficulty,
            "question_type": bq.question_type,
            "unit": bq.unit,
            "topic": bq.topic,
            "learning_outcome_code": bq.learning_outcome_code,
            "expected_answer_points": json.loads(bq.expected_answer_points_json) if bq.expected_answer_points_json else [],
            "source_provenance": bq.source_provenance,
        }
        for bq in bank_records
    ]

    # Assemble sections
    assembled_sections = assemble_paper_sections(
        blueprint=payload.blueprint,
        bank_questions=bank_candidates,
        seed=payload.blueprint.seed,
    )

    # Validate assembly rules
    validation_report = validate_assembled_paper(
        target_total_marks=payload.blueprint.total_marks,
        sections=assembled_sections,
        mandatory_topics=payload.blueprint.mandatory_topics,
    )
    if not validation_report.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Paper assembly blueprint validation failed: {'; '.join(validation_report.issues)}",
        )

    initial_audit = [
        {
            "event": "CREATED",
            "actor_id": current_user.id,
            "actor_email": current_user.email,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": 1,
            "seed": payload.blueprint.seed,
            "notes": "Initial deterministic paper assembly",
        }
    ]

    paper = AssembledPaper(
        paper_code=payload.paper_code.strip(),
        title=payload.title,
        subject=payload.subject,
        course=payload.course,
        semester=payload.semester,
        department=payload.department,
        total_marks=payload.blueprint.total_marks,
        duration_minutes=payload.blueprint.duration_minutes,
        syllabus_version=payload.syllabus_version,
        blueprint_json=json.dumps(payload.blueprint.model_dump()),
        sections_json=json.dumps(assembled_sections),
        version=1,
        generation_seed=payload.blueprint.seed,
        generation_version="v1.0-deterministic",
        status=AssembledPaperStatus.draft,
        approval_history_json=json.dumps(initial_audit),
        created_by=current_user.id,
        last_edited_by=current_user.id,
    )
    session.add(paper)
    await session.commit()
    await session.refresh(paper)

    return _serialize_assembled_paper(paper)


@router.get(
    "/papers",
    response_model=list[AssembledPaperResponse],
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def list_assembled_papers(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists assembled papers within user's department."""
    stmt = select(AssembledPaper)
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(AssembledPaper.department == current_user.department)
    stmt = stmt.order_by(AssembledPaper.created_at.desc())

    res = await session.execute(stmt)
    papers = res.scalars().all()
    return [_serialize_assembled_paper(p) for p in papers]


@router.get(
    "/papers/{paper_id}",
    response_model=AssembledPaperResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def get_assembled_paper(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves full details of an assembled paper."""
    paper = await _get_paper_with_auth(paper_id, session, current_user)
    return _serialize_assembled_paper(paper)


# =========================================================================
# 2. VALIDATION REPORT ENDPOINT
# =========================================================================


@router.post(
    "/papers/{paper_id}/validate",
    response_model=PaperValidationReport,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def validate_paper(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Validates totals, mandatory topics, duplicate questions, section rules,
    and syllabus coverage for this paper.
    """
    paper = await _get_paper_with_auth(paper_id, session, current_user)
    blueprint = json.loads(paper.blueprint_json)
    sections = json.loads(paper.sections_json)

    return validate_assembled_paper(
        target_total_marks=paper.total_marks,
        sections=sections,
        mandatory_topics=blueprint.get("mandatory_topics", []),
    )


# =========================================================================
# 3. EDIT & APPROVAL INVALIDATION WORKFLOW
# =========================================================================


@router.put(
    "/papers/{paper_id}",
    response_model=AssembledPaperResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def update_assembled_paper(
    paper_id: int,
    payload: UpdateAssembledPaperRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Updates paper content or sections.
    CRITICAL QUALITY RULE:
    Every change made after approval immediately invalidates the previous approval,
    increments the version number, and requires re-approval.
    """
    paper = await _get_paper_with_auth(paper_id, session, current_user, require_owner=True)

    previous_status = paper.status
    previous_version = paper.version
    audit_history = json.loads(paper.approval_history_json) if paper.approval_history_json else []

    if payload.title is not None:
        paper.title = payload.title

    if payload.sections is not None:
        raw_sections = [s.model_dump() for s in payload.sections]

        # Validate edited sections
        blueprint = json.loads(paper.blueprint_json)
        val_report = validate_assembled_paper(
            target_total_marks=paper.total_marks,
            sections=raw_sections,
            mandatory_topics=blueprint.get("mandatory_topics", []),
        )
        if not val_report.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Edited paper failed validation: {'; '.join(val_report.issues)}",
            )
        paper.sections_json = json.dumps(raw_sections)

    paper.last_edited_by = current_user.id
    paper.version += 1

    # Invalidation logic if the paper was previously approved
    if previous_status == AssembledPaperStatus.approved:
        paper.status = AssembledPaperStatus.review_pending
        paper.approved_by = None
        paper.approved_at = None

        invalidation_entry = {
            "event": "APPROVAL_INVALIDATED",
            "actor_id": current_user.id,
            "actor_email": current_user.email,
            "invalidated_version": previous_version,
            "new_version": paper.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "reason": payload.change_reason or "Paper content edited post-approval. Re-review required.",
        }
        audit_history.append(invalidation_entry)
    else:
        edit_entry = {
            "event": "EDITED",
            "actor_id": current_user.id,
            "actor_email": current_user.email,
            "version": paper.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "notes": payload.change_reason or "Paper draft content updated.",
        }
        audit_history.append(edit_entry)

    paper.approval_history_json = json.dumps(audit_history)
    await session.commit()
    await session.refresh(paper)

    return _serialize_assembled_paper(paper)


@router.post(
    "/papers/{paper_id}/approve",
    response_model=AssembledPaperResponse,
    dependencies=[Depends(require_permission(Permission.REVIEW_PAPERS))],
)
async def approve_assembled_paper(
    paper_id: int,
    payload: ApprovePaperRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Formally approves the current version of the paper.
    Requires reviewer privileges (HOD, Controller, Admin).
    Validates paper invariants before approval.
    """
    paper = await _get_paper_with_auth(paper_id, session, current_user)

    # Validate paper before approval
    sections = json.loads(paper.sections_json)
    blueprint = json.loads(paper.blueprint_json)
    val_report = validate_assembled_paper(
        target_total_marks=paper.total_marks,
        sections=sections,
        mandatory_topics=blueprint.get("mandatory_topics", []),
    )
    if not val_report.is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve paper: validation failed with issues: {'; '.join(val_report.issues)}",
        )

    paper.status = AssembledPaperStatus.approved
    paper.approved_by = current_user.id
    paper.approved_at = datetime.now(timezone.utc)

    audit_history = json.loads(paper.approval_history_json) if paper.approval_history_json else []
    approval_entry = {
        "event": "APPROVED",
        "actor_id": current_user.id,
        "actor_email": current_user.email,
        "actor_role": current_user.role.value,
        "approved_version": paper.version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "comment": payload.comment or "Formally verified and approved by examination committee.",
    }
    audit_history.append(approval_entry)
    paper.approval_history_json = json.dumps(audit_history)

    await session.commit()
    await session.refresh(paper)
    return _serialize_assembled_paper(paper)


# =========================================================================
# 4. ACCESSIBLE PREVIEW & FORMATTED PDF OUTPUT
# =========================================================================


@router.get(
    "/papers/{paper_id}/preview",
    response_model=PaperPreviewResponse,
)
async def get_paper_preview(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Generates an accessible preview of the paper.
    Draft Protection: Rejects unauthorized access to draft papers.
    """
    paper = await _get_paper_with_auth(paper_id, session, current_user)

    # Strict draft protection: only authorized faculty/staff in department can view draft versions
    if paper.status != AssembledPaperStatus.approved:
        if current_user.role in [UserRole.student, UserRole.printer]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Unapproved draft question papers are restricted to authorized examination staff.",
            )

    sections = json.loads(paper.sections_json)
    html_content = generate_accessible_html_preview(paper, sections)

    return PaperPreviewResponse(
        paper_id=paper.id,
        paper_code=paper.paper_code,
        title=paper.title,
        subject=paper.subject,
        course=paper.course,
        semester=paper.semester,
        department=paper.department,
        duration_minutes=paper.duration_minutes,
        total_marks=paper.total_marks,
        version=paper.version,
        status=paper.status,
        is_approved=(paper.status == AssembledPaperStatus.approved),
        sections=sections,
        html_preview=html_content,
    )


@router.get(
    "/papers/{paper_id}/pdf",
)
async def download_paper_pdf(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Renders and streams formatted PDF output with watermark stamps.
    Draft Protection: Rejects unauthorized access to draft papers.
    """
    paper = await _get_paper_with_auth(paper_id, session, current_user)

    # Draft protection
    if paper.status != AssembledPaperStatus.approved:
        if current_user.role in [UserRole.student, UserRole.printer]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: Cannot generate PDF for unapproved draft paper.",
            )

    sections = json.loads(paper.sections_json)
    pdf_bytes = generate_paper_pdf(
        paper=paper,
        sections=sections,
        requester_email=current_user.email,
        client_ip="127.0.0.1",
    )

    filename = f"{paper.paper_code}_v{paper.version}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename={filename}"},
    )
