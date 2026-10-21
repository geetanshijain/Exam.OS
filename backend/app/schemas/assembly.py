from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.assembly import AssembledPaperStatus


class QuestionChoiceItem(BaseModel):
    question_id: int | None = None
    question_text: str = Field(..., min_length=5)
    marks: int = Field(..., ge=1)
    difficulty: str = Field(default="medium", pattern="^(easy|medium|hard)$")
    question_type: str = Field(default="descriptive", pattern="^(mcq|short_answer|descriptive|numerical)$")
    unit: int = Field(default=1, ge=1)
    topic: str = Field(..., min_length=2)
    learning_outcome_code: str | None = None
    expected_answer_points: list[str] = Field(default_factory=list)
    source_provenance: str | None = None


class PaperQuestionItem(BaseModel):
    item_number: int = Field(..., ge=1)
    has_internal_choice: bool = False
    marks: int = Field(..., ge=1)
    choice_a: QuestionChoiceItem
    choice_b: QuestionChoiceItem | None = None


class SectionRuleConfig(BaseModel):
    section_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=2)
    instructions: str = Field(default="Answer the designated questions.")
    selection_rule: str = Field(default="all_compulsory", pattern="^(all_compulsory|answer_n_of_m|internal_choice)$")
    questions_to_answer: int = Field(..., ge=1)
    marks_per_question: int = Field(..., ge=1)
    total_section_marks: int = Field(..., ge=1)
    questions: list[PaperQuestionItem] = Field(default_factory=list)


class PaperBlueprintConfig(BaseModel):
    total_marks: int = Field(default=100, ge=10, le=500)
    duration_minutes: int = Field(default=180, ge=30, le=360)
    sections: list[SectionRuleConfig] = Field(..., min_length=1)
    mandatory_topics: list[str] = Field(default_factory=list)
    learning_outcome_quotas: dict[str, int] = Field(default_factory=dict)
    difficulty_distribution: dict[str, float] = Field(default_factory=dict)
    question_type_distribution: dict[str, float] = Field(default_factory=dict)
    seed: int | None = None


class AssemblePaperRequest(BaseModel):
    paper_code: str = Field(..., min_length=3, max_length=100)
    title: str = Field(..., min_length=3, max_length=500)
    subject: str = Field(..., min_length=2, max_length=255)
    course: str = Field(..., min_length=2, max_length=255)
    semester: int = Field(..., ge=1, le=12)
    department: str = Field(..., min_length=2, max_length=100)
    syllabus_version: str = Field(default="2026-v1", max_length=50)
    blueprint: PaperBlueprintConfig


class UpdateAssembledPaperRequest(BaseModel):
    title: str | None = None
    sections: list[SectionRuleConfig] | None = None
    change_reason: str | None = Field(default=None, description="Explanation for editing paper content")


class ApprovePaperRequest(BaseModel):
    comment: str | None = Field(default=None, description="Reviewer endorsement / approval remarks")


class PaperValidationReport(BaseModel):
    is_valid: bool
    total_marks_valid: bool
    mandatory_topics_covered: bool
    duplicate_check_passed: bool
    section_rules_valid: bool
    syllabus_coverage_valid: bool
    issues: list[str] = Field(default_factory=list)


class AssembledPaperResponse(BaseModel):
    id: int
    paper_code: str
    title: str
    subject: str
    course: str
    semester: int
    department: str
    total_marks: int
    duration_minutes: int
    syllabus_version: str
    blueprint: dict[str, Any]
    sections: list[dict[str, Any]]
    version: int
    generation_seed: int | None
    generation_version: str
    status: AssembledPaperStatus
    approval_history: list[dict[str, Any]]
    created_by: int
    last_edited_by: int
    approved_by: int | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaperPreviewResponse(BaseModel):
    paper_id: int
    paper_code: str
    title: str
    subject: str
    course: str
    semester: int
    department: str
    duration_minutes: int
    total_marks: int
    version: int
    status: AssembledPaperStatus
    is_approved: bool
    sections: list[dict[str, Any]]
    html_preview: str
