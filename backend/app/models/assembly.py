import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class AssembledPaperStatus(str, enum.Enum):
    draft = "draft"
    review_pending = "review_pending"
    approved = "approved"
    archived = "archived"


class AssembledPaper(Base):
    __tablename__ = "assembled_papers"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    paper_code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    course: Mapped[str] = mapped_column(String(255), nullable=False)
    semester: Mapped[int] = mapped_column(Integer, nullable=False)
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    total_marks: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=180, nullable=False)
    syllabus_version: Mapped[str] = mapped_column(String(50), default="2026-v1", nullable=False)
    
    # Assembly snapshots
    blueprint_json: Mapped[str] = mapped_column(Text, nullable=False)
    sections_json: Mapped[str] = mapped_column(Text, nullable=False)
    
    # Versioning & deterministic reproducibility tracking
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    generation_seed: Mapped[int | None] = mapped_column(Integer, nullable=True)
    generation_version: Mapped[str] = mapped_column(String(50), default="v1.0-deterministic", nullable=False)
    
    # Approval lifecycle
    status: Mapped[AssembledPaperStatus] = mapped_column(
        Enum(AssembledPaperStatus, native_enum=False),
        default=AssembledPaperStatus.draft,
        nullable=False,
        index=True,
    )
    # JSON list of approval events, invalidations, and comments:
    # [ { "event": "SUBMITTED", "actor_id": 1, "timestamp": "...", "version": 1 },
    #   { "event": "APPROVED", "actor_id": 2, "timestamp": "...", "version": 1, "comment": "..." },
    #   { "event": "APPROVAL_INVALIDATED", "actor_id": 1, "timestamp": "...", "invalidated_version": 1, "reason": "..." } ]
    approval_history_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    last_edited_by: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
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
