import enum
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ExamScheduleStatus(str, enum.Enum):
    scheduled = "scheduled"
    active_in_progress = "active_in_progress"
    completed = "completed"
    cancelled = "cancelled"
    reissued = "reissued"


class StudentSessionStatus(str, enum.Enum):
    active = "active"
    submitted = "submitted"
    timed_out = "timed_out"
    cancelled = "cancelled"
    interrupted = "interrupted"


class ReleaseJobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ExamSchedule(Base):
    __tablename__ = "exam_schedules"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    vault_paper_id: Mapped[int | None] = mapped_column(ForeignKey("vault_papers.id"), nullable=True)
    paper_code: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    approved_paper_version: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    # Scheduling & Center Constraints
    exam_center_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    eligible_group_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    timezone: Mapped[str] = mapped_column(String(50), default="UTC", nullable=False)
    
    start_time_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=180, nullable=False)
    end_time_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    grace_period_minutes: Mapped[int] = mapped_column(Integer, default=15, nullable=False)
    
    status: Mapped[ExamScheduleStatus] = mapped_column(
        Enum(ExamScheduleStatus, native_enum=False),
        default=ExamScheduleStatus.scheduled,
        nullable=False,
        index=True,
    )
    
    # Emergency cancellation & reissue tracking
    cancellation_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancellation_approvals_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    reissued_schedule_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    
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


class StudentGroupRegistration(Base):
    __tablename__ = "student_group_registrations"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    group_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    exam_center_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    is_eligible: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


class StudentExamSession(Base):
    __tablename__ = "student_exam_sessions"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    schedule_id: Mapped[int] = mapped_column(ForeignKey("exam_schedules.id"), nullable=False, index=True)
    student_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    
    # Single-use authenticated session & interrupted recovery tokens
    session_token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    recovery_token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
    # Candidate responses autosave state
    answers_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[StudentSessionStatus] = mapped_column(
        Enum(StudentSessionStatus, native_enum=False),
        default=StudentSessionStatus.active,
        nullable=False,
        index=True,
    )
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    client_ip: Mapped[str] = mapped_column(String(50), default="127.0.0.1", nullable=False)

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


class ReleaseQueueJob(Base):
    __tablename__ = "release_queue_jobs"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    schedule_id: Mapped[int] = mapped_column(ForeignKey("exam_schedules.id"), nullable=False, index=True)
    status: Mapped[ReleaseJobStatus] = mapped_column(
        Enum(ReleaseJobStatus, native_enum=False),
        default=ReleaseJobStatus.pending,
        nullable=False,
        index=True,
    )
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_retries: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
