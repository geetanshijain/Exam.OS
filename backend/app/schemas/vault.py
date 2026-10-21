from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.vault import VaultStatus


class VaultIngestRequest(BaseModel):
    paper_code: str = Field(..., min_length=3, max_length=100)
    title: str = Field(..., min_length=3, max_length=500)
    department: str = Field(..., min_length=2, max_length=100)
    version: int = Field(default=1, ge=1)
    approval_threshold: int = Field(default=2, ge=1, le=5)
    scheduled_release_start: datetime
    scheduled_release_end: datetime


class VaultApprovalRequest(BaseModel):
    comment: str | None = Field(default=None, description="Reviewer justification or endorsement remarks")


class EmergencyLockRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Institutional reason for emergency lock and token revocation")


class VaultPaperResponse(BaseModel):
    id: int
    paper_code: str
    title: str
    department: str
    version: int
    status: VaultStatus
    approval_threshold: int
    current_approvals_count: int
    approvals: list[dict[str, Any]]
    scheduled_release_start: datetime
    scheduled_release_end: datetime
    kek_version: str
    payload_sha256: str
    created_by: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class KeyRotationResponse(BaseModel):
    old_version: str
    new_version: str
    papers_rewrapped_count: int
    message: str


class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_entries_verified: int
    issues: list[str] = Field(default_factory=list)
