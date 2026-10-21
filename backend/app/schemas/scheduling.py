from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.scheduling import ExamScheduleStatus, ReleaseJobStatus, StudentSessionStatus


class ScheduleCreate(BaseModel):
    paper_code: str = Field(..., min_length=3, max_length=100)
    approved_paper_version: int = Field(..., ge=1)
    title: str = Field(..., min_length=3, max_length=500)
    department: str = Field(..., min_length=2, max_length=100)
    exam_center_id: str = Field(..., min_length=2, max_length=100)
    eligible_group_id: str = Field(..., min_length=2, max_length=100)
    timezone: str = Field(default="UTC", max_length=50)
    start_time_utc: datetime
    duration_minutes: int = Field(default=180, ge=1, le=1440)
    grace_period_minutes: int = Field(default=15, ge=0, le=120)
    vault_paper_id: int | None = None


class ScheduleResponse(BaseModel):
    id: int
    vault_paper_id: int | None
    paper_code: str
    approved_paper_version: int
    title: str
    department: str
    exam_center_id: str
    eligible_group_id: str
    timezone: str
    start_time_utc: datetime
    duration_minutes: int
    end_time_utc: datetime
    grace_period_minutes: int
    status: ExamScheduleStatus
    cancellation_reason: str | None
    cancellation_approvals_json: str | None
    reissued_schedule_id: int | None
    created_by: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class StudentRegistrationCreate(BaseModel):
    student_id: int
    group_id: str = Field(..., min_length=2, max_length=100)
    exam_center_id: str = Field(..., min_length=2, max_length=100)
    is_eligible: bool = True


class StudentRegistrationResponse(BaseModel):
    id: int
    student_id: int
    group_id: str
    exam_center_id: str
    is_eligible: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExamStartRequest(BaseModel):
    exam_center_id: str = Field(..., min_length=2, max_length=100)


class ExamStartResponse(BaseModel):
    session_id: int
    session_token: str
    recovery_token: str
    schedule_id: int
    student_id: int
    started_at: datetime
    expires_at: datetime
    remaining_seconds: int
    questions: list[dict[str, Any]]
    watermark: dict[str, Any]
    security_notice: str = (
        "CRITICAL NOTICE: Browser restrictions cannot reliably prevent screenshots or physical photography. "
        "All candidate interactions are cryptographically signed, timestamped, "
        "and watermarked with recipient identifiers."
    )


class AutosaveRequest(BaseModel):
    session_token: str
    answers: dict[str, Any]


class AutosaveResponse(BaseModel):
    saved: bool
    last_heartbeat_at: datetime
    remaining_seconds: int


class SessionRecoveryRequest(BaseModel):
    recovery_token: str


class SessionRecoveryResponse(BaseModel):
    session_id: int
    new_session_token: str
    recovery_token: str
    status: StudentSessionStatus
    saved_answers: dict[str, Any]
    questions: list[dict[str, Any]]
    remaining_seconds: int
    expires_at: datetime
    watermark: dict[str, Any]


class SubmitExamRequest(BaseModel):
    session_token: str
    final_answers: dict[str, Any] | None = None


class SubmitExamResponse(BaseModel):
    session_id: int
    status: StudentSessionStatus
    submitted_at: datetime
    message: str


class EmergencyCancelRequest(BaseModel):
    reason: str = Field(..., min_length=5)
    approval_officials: list[str] = Field(..., min_length=1)


class ReissueScheduleRequest(BaseModel):
    new_start_time_utc: datetime
    reason: str = Field(..., min_length=5)
    approval_officials: list[str] = Field(..., min_length=1)


class ReleaseQueueJobResponse(BaseModel):
    id: int
    idempotency_key: str
    schedule_id: int
    status: ReleaseJobStatus
    retry_count: int
    max_retries: int
    last_error: str | None
    executed_at: datetime | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
