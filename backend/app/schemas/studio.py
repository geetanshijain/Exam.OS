from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.studio import DocumentType, ExamStatus, QuestionReviewStatus


class LearningOutcomeItem(BaseModel):
    code: str = Field(..., description="E.g. CO1, CO2, LO1")
    description: str = Field(..., description="Learning outcome description")


class ExaminationCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=500)
    subject: str = Field(..., min_length=2, max_length=255)
    course: str = Field(..., min_length=2, max_length=255)
    semester: int = Field(..., ge=1, le=12)
    department: str = Field(..., min_length=2, max_length=100)
    syllabus_version: str = Field(default="2026-v1", max_length=50)
    total_marks: int = Field(default=100, ge=10, le=500)
    duration_minutes: int = Field(default=180, ge=30, le=360)
    learning_outcomes: list[LearningOutcomeItem] = Field(default_factory=list)
    blueprint: dict[str, Any] | None = None


class ExaminationUpdate(BaseModel):
    title: str | None = None
    subject: str | None = None
    course: str | None = None
    semester: int | None = None
    department: str | None = None
    syllabus_version: str | None = None
    total_marks: int | None = None
    duration_minutes: int | None = None
    learning_outcomes: list[LearningOutcomeItem] | None = None
    blueprint: dict[str, Any] | None = None
    status: ExamStatus | None = None


class ExaminationResponse(BaseModel):
    id: int
    title: str
    subject: str
    course: str
    semester: int
    department: str
    syllabus_version: str
    total_marks: int
    duration_minutes: int
    learning_outcomes: list[dict[str, Any]]
    blueprint: dict[str, Any] | None
    status: ExamStatus
    created_by: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UploadedDocumentResponse(BaseModel):
    id: int
    examination_id: int
    document_type: DocumentType
    original_filename: str
    mime_type: str
    page_count: int
    requires_manual_review: bool
    review_reason: str | None
    allow_external_ai: bool
    uploaded_at: datetime
    extracted_pages: list[dict[str, Any]] | None = None

    model_config = ConfigDict(from_attributes=True)


class SyllabusUnitTopic(BaseModel):
    name: str
    subtopics: list[str] = Field(default_factory=list)


class SyllabusUnit(BaseModel):
    unit_number: int
    title: str
    weighting_percentage: float
    topics: list[SyllabusUnitTopic] = Field(default_factory=list)
    source_page: int | None = 1


class SyllabusStructureUpdate(BaseModel):
    units: list[SyllabusUnit]


class SyllabusStructureResponse(BaseModel):
    examination_id: int
    units: list[dict[str, Any]]
    updated_at: datetime


class HistoricalQuestionResponse(BaseModel):
    id: int
    examination_id: int
    source_doc_id: int | None
    question_text: str
    year: str | None
    marks: int | None
    question_type: str
    difficulty: str
    source_provenance: str | None
    topics_detected: list[str] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class HistoricalAnalysisResponse(BaseModel):
    total_historical_questions: int
    repetition_count: int
    repetition_clusters: list[dict[str, Any]] = Field(default_factory=list)
    unit_coverage: dict[str, int] = Field(default_factory=dict)
    frequently_asked_topics: list[list[Any]] = Field(default_factory=list)
    type_distribution: dict[str, float] = Field(default_factory=dict)
    difficulty_distribution: dict[str, float] = Field(default_factory=dict)


class GenerateQuestionsRequest(BaseModel):
    blueprint: dict[str, Any] | None = None
    allow_external_ai: bool = False


class GeneratedQuestionUpdate(BaseModel):
    question_text: str | None = None
    marks: int | None = None
    question_type: str | None = None
    difficulty: str | None = None
    syllabus_topic: str | None = None
    learning_outcome_code: str | None = None
    expected_answer_points: list[str] | None = None
    review_status: QuestionReviewStatus | None = None
    reviewer_comments: str | None = None


class GeneratedQuestionResponse(BaseModel):
    id: int
    examination_id: int
    question_text: str
    marks: int
    question_type: str
    difficulty: str
    unit_number: int | None
    syllabus_topic: str | None
    learning_outcome_code: str | None
    expected_answer_points: list[str] | None
    provenance_basis: str | None
    duplicate_risk_score: float
    validation_flags: list[str] | None
    review_status: QuestionReviewStatus
    reviewer_comments: str | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FinalizeExaminationResponse(BaseModel):
    examination_id: int
    status: ExamStatus
    total_approved_questions: int
    total_approved_marks: int
    message: str
