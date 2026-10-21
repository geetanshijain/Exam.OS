import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class ExamStatus(str, enum.Enum):
    draft = "draft"
    blueprint_ready = "blueprint_ready"
    questions_generated = "questions_generated"
    under_review = "under_review"
    finalized = "finalized"


class DocumentType(str, enum.Enum):
    syllabus = "syllabus"
    previous_paper = "previous_paper"
    reference = "reference"


class QuestionReviewStatus(str, enum.Enum):
    draft_suggestion = "draft_suggestion"
    setter_accepted = "setter_accepted"
    setter_edited = "setter_edited"
    setter_rejected = "setter_rejected"


class Examination(Base):
    __tablename__ = "examinations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    course: Mapped[str] = mapped_column(String(255), nullable=False)
    semester: Mapped[int] = mapped_column(Integer, nullable=False)
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    syllabus_version: Mapped[str] = mapped_column(String(50), default="2026-v1", nullable=False)
    total_marks: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=180, nullable=False)

    # JSON lists: Learning Outcomes & Examination Blueprint
    learning_outcomes_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    blueprint_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[ExamStatus] = mapped_column(
        Enum(ExamStatus, native_enum=False), default=ExamStatus.draft, nullable=False
    )
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class UploadedDocument(Base):
    __tablename__ = "uploaded_documents"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    examination_id: Mapped[int] = mapped_column(ForeignKey("examinations.id"), nullable=False, index=True)
    document_type: Mapped[DocumentType] = mapped_column(
        Enum(DocumentType, native_enum=False), nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    file_path: Mapped[str] = mapped_column(String(1000), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    page_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Text extracted per page with provenance (page_number, text, character_count)
    extracted_text_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Quality control: flags documents with low text density or requiring OCR
    requires_manual_review: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    review_reason: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Confidentiality guarantee: institutional opt-in for external cloud AI processing
    allow_external_ai: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class SyllabusStructure(Base):
    __tablename__ = "syllabus_structures"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    examination_id: Mapped[int] = mapped_column(ForeignKey("examinations.id"), nullable=False, unique=True, index=True)
    
    # JSON structure: units -> [ {unit_number, title, weighting_percentage, topics: [ {name, subtopics} ] } ]
    units_json: Mapped[str] = mapped_column(Text, nullable=False)

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class HistoricalQuestion(Base):
    __tablename__ = "historical_questions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    examination_id: Mapped[int] = mapped_column(ForeignKey("examinations.id"), nullable=False, index=True)
    source_doc_id: Mapped[int | None] = mapped_column(ForeignKey("uploaded_documents.id"), nullable=True)
    
    question_text: Mapped[str] = mapped_column(Text, nullable=False)
    year: Mapped[str | None] = mapped_column(String(50), nullable=True)
    marks: Mapped[int | None] = mapped_column(Integer, nullable=True)
    question_type: Mapped[str] = mapped_column(String(50), default="descriptive", nullable=False)
    difficulty: Mapped[str] = mapped_column(String(50), default="medium", nullable=False)
    
    # Provenance tracking: exact page / reference in previous paper
    source_provenance: Mapped[str | None] = mapped_column(String(500), nullable=True)
    topics_detected_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class GeneratedQuestion(Base):
    __tablename__ = "generated_questions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    examination_id: Mapped[int] = mapped_column(ForeignKey("examinations.id"), nullable=False, index=True)
    
    question_text: Mapped[str] = mapped_column(Text, nullable=False)
    marks: Mapped[int] = mapped_column(Integer, nullable=False)
    question_type: Mapped[str] = mapped_column(String(50), nullable=False)
    difficulty: Mapped[str] = mapped_column(String(50), nullable=False)
    
    unit_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    syllabus_topic: Mapped[str | None] = mapped_column(String(255), nullable=True)
    learning_outcome_code: Mapped[str | None] = mapped_column(String(50), nullable=True)
    
    # Provenance & marking scheme
    expected_answer_points_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    provenance_basis: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Validation & Duplicate Detection
    duplicate_risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    validation_flags_json: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Human-in-the-loop review state
    review_status: Mapped[QuestionReviewStatus] = mapped_column(
        Enum(QuestionReviewStatus, native_enum=False),
        default=QuestionReviewStatus.draft_suggestion,
        nullable=False,
    )
    reviewer_comments: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
