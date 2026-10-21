import json
import logging
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, require_permission
from app.core.permissions import Permission, verify_object_access
from app.db.session import get_session
from app.models.bank import BankQuestion, BankQuestionApprovalStatus
from app.models.studio import Examination, GeneratedQuestion, QuestionReviewStatus
from app.models.user import UserRole
from app.schemas.bank import (
    BankQuestionCreate,
    BankQuestionListResponse,
    BankQuestionResponse,
    BankQuestionUpdate,
    ImportStudioQuestionsRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/bank", tags=["question-bank"])


def _serialize_bank_q(q: BankQuestion) -> BankQuestionResponse:
    return BankQuestionResponse(
        id=q.id,
        subject=q.subject,
        topic=q.topic,
        unit=q.unit,
        subtopics=json.loads(q.subtopics_json) if q.subtopics_json else [],
        question_text=q.question_text,
        marks=q.marks,
        difficulty=q.difficulty,
        question_type=q.question_type,
        syllabus_version=q.syllabus_version,
        learning_outcome_code=q.learning_outcome_code,
        approval_status=q.approval_status,
        source_provenance=q.source_provenance,
        expected_answer_points=json.loads(q.expected_answer_points_json) if q.expected_answer_points_json else [],
        department=q.department,
        created_by=q.created_by,
        approved_by=q.approved_by,
        approved_at=q.approved_at,
        created_at=q.created_at,
        updated_at=q.updated_at,
    )


@router.post(
    "/questions",
    response_model=BankQuestionResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def create_bank_question(
    payload: BankQuestionCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Adds a new question to the Question Bank."""
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        if payload.department.strip().lower() != current_user.department.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot add question to department '{payload.department}'. Restricted to '{current_user.department}'.",
            )

    subtopics_json = json.dumps(payload.subtopics) if payload.subtopics else None
    rubric_json = json.dumps(payload.expected_answer_points) if payload.expected_answer_points else None

    # Reviewer auto-approval if submitted by HOD/Admin/Controller
    approved_by = None
    approved_at = None
    initial_status = payload.approval_status

    if payload.approval_status == BankQuestionApprovalStatus.approved:
        if current_user.role in [UserRole.admin, UserRole.controller, UserRole.hod]:
            approved_by = current_user.id
            approved_at = datetime.now(timezone.utc)
        else:
            initial_status = BankQuestionApprovalStatus.draft

    question = BankQuestion(
        subject=payload.subject,
        topic=payload.topic,
        unit=payload.unit,
        subtopics_json=subtopics_json,
        question_text=payload.question_text,
        marks=payload.marks,
        difficulty=payload.difficulty,
        question_type=payload.question_type,
        syllabus_version=payload.syllabus_version,
        learning_outcome_code=payload.learning_outcome_code,
        approval_status=initial_status,
        source_provenance=payload.source_provenance,
        expected_answer_points_json=rubric_json,
        department=payload.department,
        created_by=current_user.id,
        approved_by=approved_by,
        approved_at=approved_at,
    )
    session.add(question)
    await session.commit()
    await session.refresh(question)

    return _serialize_bank_q(question)


@router.get(
    "/questions",
    response_model=BankQuestionListResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def search_bank_questions(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    subject: str | None = None,
    topic: str | None = None,
    unit: int | None = None,
    marks: int | None = None,
    difficulty: str | None = None,
    question_type: str | None = None,
    syllabus_version: str | None = None,
    approval_status: BankQuestionApprovalStatus | None = None,
    source_provenance: str | None = None,
    learning_outcome_code: str | None = None,
    q: str | None = Query(default=None, description="Free-text search in question text and rubric"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    """
    Searchable question management with filters for subject, topic, unit,
    marks, difficulty, question type, syllabus version, approval status, and source provenance.
    """
    stmt = select(BankQuestion)

    # Department boundary (IDOR protection)
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(BankQuestion.department == current_user.department)

    if subject:
        stmt = stmt.where(BankQuestion.subject.ilike(f"%{subject.strip()}%"))
    if topic:
        stmt = stmt.where(BankQuestion.topic.ilike(f"%{topic.strip()}%"))
    if unit is not None:
        stmt = stmt.where(BankQuestion.unit == unit)
    if marks is not None:
        stmt = stmt.where(BankQuestion.marks == marks)
    if difficulty:
        stmt = stmt.where(BankQuestion.difficulty == difficulty.strip().lower())
    if question_type:
        stmt = stmt.where(BankQuestion.question_type == question_type.strip().lower())
    if syllabus_version:
        stmt = stmt.where(BankQuestion.syllabus_version == syllabus_version.strip())
    if approval_status:
        stmt = stmt.where(BankQuestion.approval_status == approval_status)
    if source_provenance:
        stmt = stmt.where(BankQuestion.source_provenance.ilike(f"%{source_provenance.strip()}%"))
    if learning_outcome_code:
        stmt = stmt.where(BankQuestion.learning_outcome_code == learning_outcome_code.strip())

    if q:
        search_term = f"%{q.strip()}%"
        stmt = stmt.where(
            or_(
                BankQuestion.question_text.ilike(search_term),
                BankQuestion.topic.ilike(search_term),
                BankQuestion.expected_answer_points_json.ilike(search_term),
            )
        )

    stmt = stmt.order_by(BankQuestion.id.desc()).offset(offset).limit(limit)
    res = await session.execute(stmt)
    items = res.scalars().all()

    return BankQuestionListResponse(
        total=len(items),
        items=[_serialize_bank_q(item) for item in items],
    )


@router.get(
    "/questions/{question_id}",
    response_model=BankQuestionResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def get_bank_question(
    question_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves a single bank question with object authorization."""
    q = await session.get(BankQuestion, question_id)
    if not q:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found.")
    verify_object_access(user=current_user, resource_department=q.department)
    return _serialize_bank_q(q)


@router.patch(
    "/questions/{question_id}",
    response_model=BankQuestionResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def update_bank_question(
    question_id: int,
    payload: BankQuestionUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Updates question details or modifies approval status."""
    q = await session.get(BankQuestion, question_id)
    if not q:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found.")
    verify_object_access(user=current_user, resource_department=q.department, resource_owner_id=q.created_by)

    if payload.subject is not None:
        q.subject = payload.subject
    if payload.topic is not None:
        q.topic = payload.topic
    if payload.unit is not None:
        q.unit = payload.unit
    if payload.subtopics is not None:
        q.subtopics_json = json.dumps(payload.subtopics)
    if payload.question_text is not None:
        q.question_text = payload.question_text
    if payload.marks is not None:
        q.marks = payload.marks
    if payload.difficulty is not None:
        q.difficulty = payload.difficulty
    if payload.question_type is not None:
        q.question_type = payload.question_type
    if payload.syllabus_version is not None:
        q.syllabus_version = payload.syllabus_version
    if payload.learning_outcome_code is not None:
        q.learning_outcome_code = payload.learning_outcome_code
    if payload.source_provenance is not None:
        q.source_provenance = payload.source_provenance
    if payload.expected_answer_points is not None:
        q.expected_answer_points_json = json.dumps(payload.expected_answer_points)

    if payload.approval_status is not None:
        # Only authorized reviewers (HOD, Controller, Admin) can approve questions in the bank
        if payload.approval_status == BankQuestionApprovalStatus.approved:
            if current_user.role not in [UserRole.admin, UserRole.controller, UserRole.hod]:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Forbidden: Question bank approval requires reviewer or HOD privilege.",
                )
            q.approved_by = current_user.id
            q.approved_at = datetime.now(timezone.utc)
        elif payload.approval_status in [BankQuestionApprovalStatus.draft, BankQuestionApprovalStatus.under_review]:
            q.approved_by = None
            q.approved_at = None

        q.approval_status = payload.approval_status

    await session.commit()
    await session.refresh(q)
    return _serialize_bank_q(q)


@router.delete(
    "/questions/{question_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def delete_bank_question(
    question_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Deletes a question from the question bank."""
    q = await session.get(BankQuestion, question_id)
    if not q:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Question not found.")
    verify_object_access(user=current_user, resource_department=q.department, resource_owner_id=q.created_by, require_owner=True)
    await session.delete(q)
    await session.commit()


@router.post(
    "/questions/import-from-studio/{exam_id}",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def import_questions_from_studio(
    exam_id: int,
    payload: ImportStudioQuestionsRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Imports questions approved in the Question Paper Studio directly into the Question Bank.
    """
    exam = await session.get(Examination, exam_id)
    if not exam:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Examination not found.")
    verify_object_access(user=current_user, resource_department=exam.department)

    stmt = select(GeneratedQuestion).where(GeneratedQuestion.examination_id == exam.id)
    if payload.promote_only_accepted:
        stmt = stmt.where(
            GeneratedQuestion.review_status.in_([
                QuestionReviewStatus.setter_accepted,
                QuestionReviewStatus.setter_edited,
            ])
        )

    res = await session.execute(stmt)
    studio_qs = res.scalars().all()

    if not studio_qs:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No accepted questions found in this examination to import into the bank.",
        )

    imported_count = 0
    for sq in studio_qs:
        bq = BankQuestion(
            subject=exam.subject,
            topic=sq.syllabus_topic or f"Unit {sq.unit_number or 1} Topic",
            unit=sq.unit_number or 1,
            subtopics_json=None,
            question_text=sq.question_text,
            marks=sq.marks,
            difficulty=sq.difficulty,
            question_type=sq.question_type,
            syllabus_version=exam.syllabus_version,
            learning_outcome_code=sq.learning_outcome_code,
            approval_status=BankQuestionApprovalStatus.approved,
            source_provenance=f"Studio Examination #{exam.id} ({sq.provenance_basis or 'Generated'})",
            expected_answer_points_json=sq.expected_answer_points_json,
            department=exam.department,
            created_by=current_user.id,
            approved_by=current_user.id,
            approved_at=datetime.now(timezone.utc),
        )
        session.add(bq)
        imported_count += 1

    await session.commit()
    return {"message": f"Successfully imported {imported_count} questions into the question bank.", "imported_count": imported_count}
