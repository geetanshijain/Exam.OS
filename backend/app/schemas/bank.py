from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.bank import BankQuestionApprovalStatus


class BankQuestionCreate(BaseModel):
    subject: str = Field(..., min_length=2, max_length=255)
    topic: str = Field(..., min_length=2, max_length=255)
    unit: int = Field(..., ge=1, le=50)
    subtopics: list[str] = Field(default_factory=list)
    question_text: str = Field(..., min_length=5)
    marks: int = Field(..., ge=1, le=100)
    difficulty: str = Field(default="medium", pattern="^(easy|medium|hard)$")
    question_type: str = Field(default="descriptive", pattern="^(mcq|short_answer|descriptive|numerical)$")
    syllabus_version: str = Field(default="2026-v1", max_length=50)
    learning_outcome_code: str | None = Field(default=None, max_length=50)
    source_provenance: str = Field(default="Manual Entry", max_length=500)
    expected_answer_points: list[str] = Field(default_factory=list)
    department: str = Field(..., min_length=2, max_length=100)
    approval_status: BankQuestionApprovalStatus = BankQuestionApprovalStatus.draft


class BankQuestionUpdate(BaseModel):
    subject: str | None = None
    topic: str | None = None
    unit: int | None = None
    subtopics: list[str] | None = None
    question_text: str | None = None
    marks: int | None = None
    difficulty: str | None = None
    question_type: str | None = None
    syllabus_version: str | None = None
    learning_outcome_code: str | None = None
    source_provenance: str | None = None
    expected_answer_points: list[str] | None = None
    approval_status: BankQuestionApprovalStatus | None = None


class BankQuestionResponse(BaseModel):
    id: int
    subject: str
    topic: str
    unit: int
    subtopics: list[str]
    question_text: str
    marks: int
    difficulty: str
    question_type: str
    syllabus_version: str
    learning_outcome_code: str | None
    approval_status: BankQuestionApprovalStatus
    source_provenance: str
    expected_answer_points: list[str]
    department: str
    created_by: int
    approved_by: int | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BankQuestionListResponse(BaseModel):
    total: int
    items: list[BankQuestionResponse]


class ImportStudioQuestionsRequest(BaseModel):
    exam_id: int
    promote_only_accepted: bool = True
