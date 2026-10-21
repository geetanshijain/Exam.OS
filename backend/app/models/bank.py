import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class BankQuestionApprovalStatus(str, enum.Enum):
    draft = "draft"
    under_review = "under_review"
    approved = "approved"
    retired = "retired"


class BankQuestion(Base):
    __tablename__ = "bank_questions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    topic: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    unit: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    subtopics_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    question_text: Mapped[str] = mapped_column(Text, nullable=False)
    marks: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    difficulty: Mapped[str] = mapped_column(String(50), default="medium", nullable=False, index=True)
    question_type: Mapped[str] = mapped_column(String(50), default="descriptive", nullable=False, index=True)
    syllabus_version: Mapped[str] = mapped_column(String(50), default="2026-v1", nullable=False, index=True)
    learning_outcome_code: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    
    approval_status: Mapped[BankQuestionApprovalStatus] = mapped_column(
        Enum(BankQuestionApprovalStatus, native_enum=False),
        default=BankQuestionApprovalStatus.draft,
        nullable=False,
        index=True,
    )
    source_provenance: Mapped[str] = mapped_column(String(500), default="Manual Entry", nullable=False)
    expected_answer_points_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    approved_by: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

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
