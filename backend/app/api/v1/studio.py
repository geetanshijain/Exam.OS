import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, get_current_user, require_permission
from app.core.permissions import Permission, verify_object_access
from app.db.session import get_session
from app.models.studio import (
    DocumentType,
    Examination,
    ExamStatus,
    GeneratedQuestion,
    HistoricalQuestion,
    QuestionReviewStatus,
    SyllabusStructure,
    UploadedDocument,
)
from app.models.user import User, UserRole
from app.schemas.studio import (
    ExaminationCreate,
    ExaminationResponse,
    ExaminationUpdate,
    FinalizeExaminationResponse,
    GenerateQuestionsRequest,
    GeneratedQuestionResponse,
    GeneratedQuestionUpdate,
    HistoricalAnalysisResponse,
    HistoricalQuestionResponse,
    SyllabusStructureResponse,
    SyllabusStructureUpdate,
    UploadedDocumentResponse,
)
from app.studio.extractor import extract_document_text
from app.studio.generator import build_default_blueprint, generate_blueprint_questions
from app.studio.historical_analyzer import (
    analyze_historical_coverage,
    extract_historical_questions_from_pages,
)
from app.studio.syllabus_analyzer import parse_syllabus_structure, validate_syllabus_structure
from app.studio.validator import check_duplicate_risk, validate_question

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/studio", tags=["studio"])

UPLOAD_STORAGE_DIR = Path(__file__).resolve().parents[4] / "vault" / "studio_uploads"
UPLOAD_STORAGE_DIR.mkdir(parents=True, exist_ok=True)


async def _get_exam_with_auth(
    exam_id: int,
    session: AsyncSession,
    user: User,
    require_owner: bool = False,
) -> Examination:
    exam = await session.get(Examination, exam_id)
    if not exam:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Examination #{exam_id} not found.",
        )
    verify_object_access(
        user=user,
        resource_department=exam.department,
        resource_owner_id=exam.created_by,
        require_owner=require_owner,
    )
    return exam


# =========================================================================
# 1. EXAMINATION MANAGEMENT
# =========================================================================


@router.post(
    "/examinations",
    response_model=ExaminationResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def create_examination(
    payload: ExaminationCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Creates a new examination record initialized with syllabus version, duration, and learning outcomes."""
    # Enforce department boundary unless admin or controller
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        if payload.department.strip().lower() != current_user.department.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot create examination for '{payload.department}'. Restricted to '{current_user.department}'.",
            )

    lo_json = json.dumps([lo.model_dump() for lo in payload.learning_outcomes]) if payload.learning_outcomes else None
    blueprint_json = json.dumps(payload.blueprint) if payload.blueprint else json.dumps(build_default_blueprint(payload.total_marks))

    exam = Examination(
        title=payload.title,
        subject=payload.subject,
        course=payload.course,
        semester=payload.semester,
        department=payload.department,
        syllabus_version=payload.syllabus_version,
        total_marks=payload.total_marks,
        duration_minutes=payload.duration_minutes,
        learning_outcomes_json=lo_json,
        blueprint_json=blueprint_json,
        status=ExamStatus.draft,
        created_by=current_user.id,
    )
    session.add(exam)
    await session.commit()
    await session.refresh(exam)

    return _serialize_exam(exam)


@router.get(
    "/examinations",
    response_model=list[ExaminationResponse],
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def list_examinations(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists examinations accessible to the authorized setter within their department."""
    stmt = select(Examination)
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(Examination.department == current_user.department)
    stmt = stmt.order_by(Examination.created_at.desc())

    result = await session.execute(stmt)
    exams = result.scalars().all()
    return [_serialize_exam(e) for e in exams]


@router.get(
    "/examinations/{exam_id}",
    response_model=ExaminationResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def get_examination(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves specific examination details with IDOR protection."""
    exam = await _get_exam_with_auth(exam_id, session, current_user)
    return _serialize_exam(exam)


@router.put(
    "/examinations/{exam_id}",
    response_model=ExaminationResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def update_examination(
    exam_id: int,
    payload: ExaminationUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Updates examination metadata, blueprint, or learning outcomes."""
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)

    if payload.title is not None:
        exam.title = payload.title
    if payload.subject is not None:
        exam.subject = payload.subject
    if payload.course is not None:
        exam.course = payload.course
    if payload.semester is not None:
        exam.semester = payload.semester
    if payload.syllabus_version is not None:
        exam.syllabus_version = payload.syllabus_version
    if payload.total_marks is not None:
        exam.total_marks = payload.total_marks
    if payload.duration_minutes is not None:
        exam.duration_minutes = payload.duration_minutes
    if payload.learning_outcomes is not None:
        exam.learning_outcomes_json = json.dumps([lo.model_dump() for lo in payload.learning_outcomes])
    if payload.blueprint is not None:
        exam.blueprint_json = json.dumps(payload.blueprint)
    if payload.status is not None:
        exam.status = payload.status

    await session.commit()
    await session.refresh(exam)
    return _serialize_exam(exam)


# =========================================================================
# 2. DOCUMENT INGESTION & EXTRACTION
# =========================================================================


@router.post(
    "/examinations/{exam_id}/upload",
    response_model=UploadedDocumentResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def upload_examination_document(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    file: UploadFile = File(...),
    document_type: DocumentType = Form(...),
    allow_external_ai: bool = Form(False),
):
    """
    Uploads syllabus or previous-year exam papers.
    Extracts text with page provenance, flags OCR requirements, and triggers parsing.
    """
    exam = await _get_exam_with_auth(exam_id, session, current_user)

    filename = file.filename or "uploaded_doc"
    ext = Path(filename).suffix.lower()
    if ext not in [".pdf", ".docx", ".doc", ".txt"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format '{ext}'. Only PDF, DOCX, and TXT documents are accepted.",
        )

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty.",
        )

    # Save to secure storage vault
    storage_path = UPLOAD_STORAGE_DIR / f"exam_{exam.id}_{int(datetime.now(timezone.utc).timestamp())}_{filename}"
    storage_path.write_bytes(content)

    # Extract text with page references and quality control
    page_count, extracted_pages, requires_manual_review, review_reason = extract_document_text(
        file_bytes=content,
        filename=filename,
        mime_type=file.content_type or "application/octet-stream",
    )

    doc = UploadedDocument(
        examination_id=exam.id,
        document_type=document_type,
        original_filename=filename,
        file_path=str(storage_path),
        mime_type=file.content_type or "application/octet-stream",
        page_count=page_count,
        extracted_text_json=json.dumps(extracted_pages),
        requires_manual_review=requires_manual_review,
        review_reason=review_reason,
        allow_external_ai=allow_external_ai,
    )
    session.add(doc)
    await session.flush()

    # Automatic processing based on document category
    if document_type == DocumentType.syllabus:
        parsed = parse_syllabus_structure(extracted_pages)
        # Check existing syllabus structure
        existing_syl = await session.execute(
            select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
        )
        syl_record = existing_syl.scalar_one_or_none()
        if not syl_record:
            syl_record = SyllabusStructure(
                examination_id=exam.id,
                units_json=json.dumps(parsed.get("units", [])),
            )
            session.add(syl_record)
        else:
            syl_record.units_json = json.dumps(parsed.get("units", []))

    elif document_type == DocumentType.previous_paper:
        historical_qs = extract_historical_questions_from_pages(extracted_pages, doc_id=doc.id)
        for hq in historical_qs:
            hq_obj = HistoricalQuestion(
                examination_id=exam.id,
                source_doc_id=doc.id,
                question_text=hq["question_text"],
                year=None,
                marks=hq.get("marks", 10),
                question_type=hq.get("question_type", "descriptive"),
                difficulty=hq.get("difficulty", "medium"),
                source_provenance=hq.get("source_provenance"),
                topics_detected_json=json.dumps(hq.get("topics_detected", [])),
            )
            session.add(hq_obj)

    await session.commit()
    await session.refresh(doc)

    return UploadedDocumentResponse(
        id=doc.id,
        examination_id=doc.examination_id,
        document_type=doc.document_type,
        original_filename=doc.original_filename,
        mime_type=doc.mime_type,
        page_count=doc.page_count,
        requires_manual_review=doc.requires_manual_review,
        review_reason=doc.review_reason,
        allow_external_ai=doc.allow_external_ai,
        uploaded_at=doc.uploaded_at,
        extracted_pages=extracted_pages,
    )


@router.get(
    "/examinations/{exam_id}/documents",
    response_model=list[UploadedDocumentResponse],
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def list_examination_documents(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists all uploaded documents for this examination."""
    exam = await _get_exam_with_auth(exam_id, session, current_user)
    stmt = select(UploadedDocument).where(UploadedDocument.examination_id == exam.id).order_by(UploadedDocument.uploaded_at.desc())
    result = await session.execute(stmt)
    docs = result.scalars().all()
    
    return [
        UploadedDocumentResponse(
            id=d.id,
            examination_id=d.examination_id,
            document_type=d.document_type,
            original_filename=d.original_filename,
            mime_type=d.mime_type,
            page_count=d.page_count,
            requires_manual_review=d.requires_manual_review,
            review_reason=d.review_reason,
            allow_external_ai=d.allow_external_ai,
            uploaded_at=d.uploaded_at,
            extracted_pages=json.loads(d.extracted_text_json) if d.extracted_text_json else [],
        )
        for d in docs
    ]


# =========================================================================
# 3. STRUCTURED SYLLABUS EDITING
# =========================================================================


@router.get(
    "/examinations/{exam_id}/syllabus",
    response_model=SyllabusStructureResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def get_examination_syllabus(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves current syllabus structure (units, topics, subtopics, weightings)."""
    exam = await _get_exam_with_auth(exam_id, session, current_user)
    stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
    result = await session.execute(stmt)
    syl = result.scalar_one_or_none()
    if not syl:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No syllabus structure defined yet. Upload a syllabus document first or submit units.",
        )

    return SyllabusStructureResponse(
        examination_id=syl.examination_id,
        units=json.loads(syl.units_json),
        updated_at=syl.updated_at,
    )


@router.put(
    "/examinations/{exam_id}/syllabus",
    response_model=SyllabusStructureResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def update_examination_syllabus(
    exam_id: int,
    payload: SyllabusStructureUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Allows exam setters to edit units, topics, subtopics, and weighting percentages (must sum to 100%)."""
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)
    raw_units = [u.model_dump() for u in payload.units]

    is_valid, error_msg = validate_syllabus_structure(raw_units)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg,
        )

    stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
    result = await session.execute(stmt)
    syl = result.scalar_one_or_none()
    if not syl:
        syl = SyllabusStructure(
            examination_id=exam.id,
            units_json=json.dumps(raw_units),
        )
        session.add(syl)
    else:
        syl.units_json = json.dumps(raw_units)

    await session.commit()
    await session.refresh(syl)

    return SyllabusStructureResponse(
        examination_id=syl.examination_id,
        units=raw_units,
        updated_at=syl.updated_at,
    )


# =========================================================================
# 4. HISTORICAL QUESTIONS ANALYSIS
# =========================================================================


@router.get(
    "/examinations/{exam_id}/analysis",
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def get_historical_analysis(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Analyzes historical question papers:
    topic coverage, repetition patterns, difficulty, and mark distribution.
    """
    exam = await _get_exam_with_auth(exam_id, session, current_user)

    # Fetch syllabus units
    syl_stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
    syl_res = await session.execute(syl_stmt)
    syl = syl_res.scalar_one_or_none()
    units = json.loads(syl.units_json) if syl else []

    # Fetch historical questions
    hq_stmt = select(HistoricalQuestion).where(HistoricalQuestion.examination_id == exam.id)
    hq_res = await session.execute(hq_stmt)
    h_questions = hq_res.scalars().all()

    hq_dicts = [
        {
            "id": hq.id,
            "question_text": hq.question_text,
            "marks": hq.marks,
            "question_type": hq.question_type,
            "difficulty": hq.difficulty,
            "source_provenance": hq.source_provenance,
        }
        for hq in h_questions
    ]

    analysis = analyze_historical_coverage(hq_dicts, units)
    return analysis


# =========================================================================
# 5. BLUEPRINT-DRIVEN QUESTION GENERATION
# =========================================================================


@router.post(
    "/examinations/{exam_id}/generate",
    response_model=list[GeneratedQuestionResponse],
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def generate_questions_for_examination(
    exam_id: int,
    payload: GenerateQuestionsRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Generates new questions according to an explicit examination blueprint.
    Guarantees:
    - Zero data sent to external AI without explicit allow_external_ai authorization.
    - Full syllabus unit and learning outcome tracking.
    - Near-duplicate detection against historical questions.
    - Initial review status is 'draft_suggestion'.
    """
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)

    # 1. Fetch syllabus units
    syl_stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
    syl_res = await session.execute(syl_stmt)
    syl = syl_res.scalar_one_or_none()
    if not syl:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot generate questions: Syllabus structure has not been defined. Upload syllabus or define units first.",
        )
    units = json.loads(syl.units_json)

    # 2. Determine blueprint
    blueprint = payload.blueprint
    if not blueprint and exam.blueprint_json:
        blueprint = json.loads(exam.blueprint_json)
    if not blueprint:
        blueprint = build_default_blueprint(exam.total_marks)

    # 3. Learning outcomes
    learning_outcomes = json.loads(exam.learning_outcomes_json) if exam.learning_outcomes_json else []

    # 4. Fetch historical question texts for duplicate detection
    hq_stmt = select(HistoricalQuestion.question_text).where(HistoricalQuestion.examination_id == exam.id)
    hq_res = await session.execute(hq_stmt)
    historical_texts = [row[0] for row in hq_res.all()]

    # 5. Execute generation
    generated_items = generate_blueprint_questions(
        blueprint=blueprint,
        units=units,
        learning_outcomes=learning_outcomes,
        historical_questions=historical_texts,
        allow_external_ai=payload.allow_external_ai,
    )

    db_questions: list[GeneratedQuestion] = []
    for g in generated_items:
        gq = GeneratedQuestion(
            examination_id=exam.id,
            question_text=g["question_text"],
            marks=g["marks"],
            question_type=g["question_type"],
            difficulty=g["difficulty"],
            unit_number=g["unit_number"],
            syllabus_topic=g["syllabus_topic"],
            learning_outcome_code=g["learning_outcome_code"],
            expected_answer_points_json=json.dumps(g.get("expected_answer_points", [])),
            provenance_basis=g.get("provenance_basis"),
            duplicate_risk_score=g.get("duplicate_risk_score", 0.0),
            validation_flags_json=json.dumps(g.get("validation_flags", [])),
            review_status=QuestionReviewStatus.draft_suggestion,
            reviewer_comments=None,
        )
        session.add(gq)
        db_questions.append(gq)

    exam.status = ExamStatus.questions_generated
    await session.commit()

    for gq in db_questions:
        await session.refresh(gq)

    return [_serialize_generated_question(g) for g in db_questions]


@router.get(
    "/examinations/{exam_id}/questions",
    response_model=list[GeneratedQuestionResponse],
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def list_generated_questions(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists all generated questions for this examination."""
    exam = await _get_exam_with_auth(exam_id, session, current_user)
    stmt = select(GeneratedQuestion).where(GeneratedQuestion.examination_id == exam.id).order_by(GeneratedQuestion.id.asc())
    res = await session.execute(stmt)
    questions = res.scalars().all()
    return [_serialize_generated_question(q) for q in questions]


# =========================================================================
# 6. HUMAN-IN-THE-LOOP REVIEW, EDIT & REGENERATE
# =========================================================================


@router.patch(
    "/examinations/{exam_id}/questions/{question_id}",
    response_model=GeneratedQuestionResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def update_generated_question(
    exam_id: int,
    question_id: int,
    payload: GeneratedQuestionUpdate,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Enables authorized exam setters to review, edit, reject, or approve individual questions.
    Re-runs duplicate and validation analysis if text or marks are modified.
    """
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)

    gq = await session.get(GeneratedQuestion, question_id)
    if not gq or gq.examination_id != exam.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Question #{question_id} not found in examination #{exam.id}.",
        )

    text_modified = payload.question_text is not None and payload.question_text != gq.question_text
    marks_modified = payload.marks is not None and payload.marks != gq.marks

    if payload.question_text is not None:
        gq.question_text = payload.question_text
    if payload.marks is not None:
        gq.marks = payload.marks
    if payload.question_type is not None:
        gq.question_type = payload.question_type
    if payload.difficulty is not None:
        gq.difficulty = payload.difficulty
    if payload.syllabus_topic is not None:
        gq.syllabus_topic = payload.syllabus_topic
    if payload.learning_outcome_code is not None:
        gq.learning_outcome_code = payload.learning_outcome_code
    if payload.expected_answer_points is not None:
        gq.expected_answer_points_json = json.dumps(payload.expected_answer_points)
    if payload.reviewer_comments is not None:
        gq.reviewer_comments = payload.reviewer_comments

    # If text was modified by the human setter, mark as setter_edited
    if text_modified or marks_modified:
        gq.review_status = QuestionReviewStatus.setter_edited
        
        # Re-run validation
        syl_stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
        syl_res = await session.execute(syl_stmt)
        syl = syl_res.scalar_one_or_none()
        syllabus_topics = []
        if syl:
            for u in json.loads(syl.units_json):
                for t in u.get("topics", []):
                    syllabus_topics.append(t.get("name", ""))
                    syllabus_topics.extend(t.get("subtopics", []))

        flags = validate_question(
            question_text=gq.question_text,
            syllabus_topics=syllabus_topics,
            marks=gq.marks,
            question_type=gq.question_type,
        )
        gq.validation_flags_json = json.dumps(flags)
    elif payload.review_status is not None:
        gq.review_status = payload.review_status

    await session.commit()
    await session.refresh(gq)
    return _serialize_generated_question(gq)


@router.post(
    "/examinations/{exam_id}/questions/{question_id}/regenerate",
    response_model=GeneratedQuestionResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def regenerate_single_question(
    exam_id: int,
    question_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Regenerates a single question maintaining unit and marks alignment."""
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)

    gq = await session.get(GeneratedQuestion, question_id)
    if not gq or gq.examination_id != exam.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Question #{question_id} not found in examination #{exam.id}.",
        )

    # Fetch syllabus
    syl_stmt = select(SyllabusStructure).where(SyllabusStructure.examination_id == exam.id)
    syl_res = await session.execute(syl_stmt)
    syl = syl_res.scalar_one_or_none()
    units = json.loads(syl.units_json) if syl else []

    target_unit = next((u for u in units if u.get("unit_number") == gq.unit_number), None)
    if not target_unit and units:
        target_unit = units[0]

    single_blueprint = {
        "sections": [
            {
                "section_name": "Regenerated Item",
                "question_type": gq.question_type,
                "marks_per_question": gq.marks,
                "count": 1,
                "difficulty": gq.difficulty,
            }
        ]
    }

    # Gather existing questions
    other_qs_stmt = select(GeneratedQuestion.question_text).where(
        GeneratedQuestion.examination_id == exam.id,
        GeneratedQuestion.id != gq.id,
    )
    other_qs = (await session.execute(other_qs_stmt)).scalars().all()

    new_questions = generate_blueprint_questions(
        blueprint=single_blueprint,
        units=[target_unit] if target_unit else [],
        learning_outcomes=json.loads(exam.learning_outcomes_json) if exam.learning_outcomes_json else [],
        historical_questions=list(other_qs),
        allow_external_ai=False,
    )

    if new_questions:
        nq = new_questions[0]
        gq.question_text = nq["question_text"]
        gq.syllabus_topic = nq["syllabus_topic"]
        gq.expected_answer_points_json = json.dumps(nq.get("expected_answer_points", []))
        gq.provenance_basis = nq.get("provenance_basis")
        gq.duplicate_risk_score = nq.get("duplicate_risk_score", 0.0)
        gq.validation_flags_json = json.dumps(nq.get("validation_flags", []))
        gq.review_status = QuestionReviewStatus.draft_suggestion
        gq.reviewer_comments = "Regenerated by exam setter."

        await session.commit()
        await session.refresh(gq)

    return _serialize_generated_question(gq)


# =========================================================================
# 7. EXAM PAPER FINALIZATION
# =========================================================================


@router.post(
    "/examinations/{exam_id}/finalize",
    response_model=FinalizeExaminationResponse,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def finalize_examination_paper(
    exam_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Institutional Quality Safeguard:
    Finalizes the examination paper.
    Requirements:
    - Every question must be explicitly reviewed (setter_accepted or setter_edited).
    - Zero questions permitted in 'draft_suggestion' or 'setter_rejected'.
    - Sum of approved questions marks must match examination.total_marks.
    - No unresolved critical validation flags (e.g., OUT_OF_SYLLABUS, UNSUPPORTED_REFERENCE).
    """
    exam = await _get_exam_with_auth(exam_id, session, current_user, require_owner=True)

    stmt = select(GeneratedQuestion).where(GeneratedQuestion.examination_id == exam.id)
    res = await session.execute(stmt)
    questions = res.scalars().all()

    if not questions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot finalize examination: No questions exist in this paper.",
        )

    # 1. Human review check
    unreviewed = [q.id for q in questions if q.review_status == QuestionReviewStatus.draft_suggestion]
    if unreviewed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot finalize: Human review is mandatory. {len(unreviewed)} question(s) "
                f"(IDs: {unreviewed[:5]}) remain in 'draft_suggestion' state and must be accepted, edited, or rejected."
            ),
        )

    # 2. Rejection check
    rejected = [q.id for q in questions if q.review_status == QuestionReviewStatus.setter_rejected]
    if rejected:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Cannot finalize: {len(rejected)} rejected question(s) remain in the paper. "
                "Regenerate or remove rejected questions before final approval."
            ),
        )

    # 3. Marks check
    approved_questions = [q for q in questions if q.review_status in [QuestionReviewStatus.setter_accepted, QuestionReviewStatus.setter_edited]]
    total_approved_marks = sum(q.marks for q in approved_questions)

    if total_approved_marks != exam.total_marks:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Total marks mismatch: Approved questions sum to {total_approved_marks} marks, "
                f"but target examination requires {exam.total_marks} marks."
            ),
        )

    # 4. Critical validation flag check
    for q in approved_questions:
        if q.validation_flags_json:
            flags = json.loads(q.validation_flags_json)
            critical = [f for f in flags if "OUT_OF_SYLLABUS" in f or "UNSUPPORTED_REFERENCE" in f]
            if critical:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot finalize: Question #{q.id} has critical unresolved validation issues: {critical[0]}",
                )

    exam.status = ExamStatus.finalized
    await session.commit()
    await session.refresh(exam)

    return FinalizeExaminationResponse(
        examination_id=exam.id,
        status=exam.status,
        total_approved_questions=len(approved_questions),
        total_approved_marks=total_approved_marks,
        message="Examination paper verified and finalized successfully by authorized exam setter.",
    )


# =========================================================================
# HELPER SERIALIZERS
# =========================================================================


def _serialize_exam(exam: Examination) -> ExaminationResponse:
    return ExaminationResponse(
        id=exam.id,
        title=exam.title,
        subject=exam.subject,
        course=exam.course,
        semester=exam.semester,
        department=exam.department,
        syllabus_version=exam.syllabus_version,
        total_marks=exam.total_marks,
        duration_minutes=exam.duration_minutes,
        learning_outcomes=json.loads(exam.learning_outcomes_json) if exam.learning_outcomes_json else [],
        blueprint=json.loads(exam.blueprint_json) if exam.blueprint_json else None,
        status=exam.status,
        created_by=exam.created_by,
        created_at=exam.created_at,
        updated_at=exam.updated_at,
    )


def _serialize_generated_question(q: GeneratedQuestion) -> GeneratedQuestionResponse:
    return GeneratedQuestionResponse(
        id=q.id,
        examination_id=q.examination_id,
        question_text=q.question_text,
        marks=q.marks,
        question_type=q.question_type,
        difficulty=q.difficulty,
        unit_number=q.unit_number,
        syllabus_topic=q.syllabus_topic,
        learning_outcome_code=q.learning_outcome_code,
        expected_answer_points=json.loads(q.expected_answer_points_json) if q.expected_answer_points_json else [],
        provenance_basis=q.provenance_basis,
        duplicate_risk_score=q.duplicate_risk_score,
        validation_flags=json.loads(q.validation_flags_json) if q.validation_flags_json else [],
        review_status=q.review_status,
        reviewer_comments=q.reviewer_comments,
        created_at=q.created_at,
        updated_at=q.updated_at,
    )
