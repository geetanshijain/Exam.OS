from datetime import datetime
from typing import Any
from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.alert import AlertSeverity
from app.models.incident import IncidentSeverity, IncidentStatus
from app.models.user import UserRole


# =========================================================================
# 1. USER & ROLE MANAGEMENT SCHEMAS
# =========================================================================


class UserAdminCreate(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8)
    full_name: str = Field(..., min_length=2, max_length=255)
    department: str = Field(default="General", max_length=100)
    role: UserRole
    is_active: bool = True


class UserAdminUpdate(BaseModel):
    full_name: str | None = None
    department: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    unlock_account: bool | None = None
    reset_password: str | None = Field(default=None, min_length=8)


class UserAdminResponse(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    department: str
    role: UserRole
    is_active: bool
    failed_login_attempts: int
    locked_until: datetime | None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RolePermissionResponse(BaseModel):
    role: UserRole
    permissions: list[str]


# =========================================================================
# 2. SUBJECT & EXAMINATION CENTER SCHEMAS
# =========================================================================


class SubjectCreate(BaseModel):
    code: str = Field(..., min_length=2, max_length=50)
    name: str = Field(..., min_length=2, max_length=255)
    department: str = Field(..., min_length=2, max_length=100)
    credits: int = Field(default=4, ge=1, le=10)
    syllabus_version: str = Field(default="2026-v1", max_length=50)
    is_active: bool = True


class SubjectUpdate(BaseModel):
    name: str | None = None
    department: str | None = None
    credits: int | None = None
    syllabus_version: str | None = None
    is_active: bool | None = None


class SubjectResponse(BaseModel):
    id: int
    code: str
    name: str
    department: str
    credits: int
    syllabus_version: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExamCenterCreate(BaseModel):
    center_code: str = Field(..., min_length=2, max_length=100)
    name: str = Field(..., min_length=2, max_length=255)
    city: str = Field(default="Main Campus", max_length=100)
    capacity: int = Field(default=100, ge=1)
    department: str = Field(default="General", max_length=100)
    is_active: bool = True


class ExamCenterUpdate(BaseModel):
    name: str | None = None
    city: str | None = None
    capacity: int | None = None
    department: str | None = None
    is_active: bool | None = None


class ExamCenterResponse(BaseModel):
    id: int
    center_code: str
    name: str
    city: str
    capacity: int
    department: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================================
# 3. AUDIT TRAIL & LOG SEARCH SCHEMAS
# =========================================================================


class AuditLogResponse(BaseModel):
    id: int
    actor_id: int
    actor_username: str | None = None
    actor_email: str | None = None
    action: str
    entity_type: str
    entity_id: int | None
    outcome: str
    correlation_id: str | None
    ip_address: str | None
    metadata_json: str | None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditSearchResponse(BaseModel):
    total_matches: int
    page: int
    page_size: int
    items: list[AuditLogResponse]
    verified_clock_offset_ms: float = 0.0
    storage_type: str = "append_only_authenticated_db"


# =========================================================================
# 4. SECURITY ALERTS & ANOMALY DETECTION
# =========================================================================


class AlertItemResponse(BaseModel):
    id: int
    severity: AlertSeverity
    message: str
    paper_id: int | None
    actor_id: int | None
    actor_username: str | None = None
    resolved: bool
    resolution_notes: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertResolveRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=5)


# =========================================================================
# 5. SECURITY INCIDENT & EVIDENCE MANAGEMENT SCHEMAS
# =========================================================================


class IncidentCreate(BaseModel):
    title: str = Field(..., min_length=5, max_length=500)
    severity: IncidentSeverity = IncidentSeverity.medium
    category: str = Field(..., min_length=3, max_length=100)
    description: str = Field(..., min_length=10)
    assigned_to_id: int | None = None
    related_exam_id: int | None = None
    related_paper_code: str | None = None


class IncidentNoteAdd(BaseModel):
    note: str = Field(..., min_length=3)


class IncidentEvidenceAdd(BaseModel):
    evidence_type: str = Field(..., min_length=2, max_length=50)  # e.g., "audit_log", "hash_digest", "ip_pcap"
    reference_id: str = Field(..., min_length=2, max_length=255)
    description: str = Field(..., min_length=3)


class IncidentClosureRequest(BaseModel):
    root_cause: str = Field(..., min_length=10)
    remediation_steps: str = Field(..., min_length=10)
    closure_approval_notes: str = Field(..., min_length=10)


class IncidentResponse(BaseModel):
    id: int
    incident_code: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    category: str
    description: str
    assigned_to_id: int | None
    related_exam_id: int | None
    related_paper_code: str | None
    investigation_notes: list[dict[str, Any]]
    evidence_references: list[dict[str, Any]]
    root_cause: str | None
    remediation_steps: str | None
    closed_by_id: int | None
    closed_at: datetime | None
    closure_approval_notes: str | None
    created_by_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# =========================================================================
# 6. APPROVAL QUEUES & PENDING ACTIONS SCHEMAS
# =========================================================================


class PendingApprovalItem(BaseModel):
    queue_type: str  # "vault_quorum", "assembled_paper", "release_queue"
    item_id: int
    identifier: str
    title: str
    department: str
    current_status: str
    pending_since: datetime
    details: dict[str, Any]


class PendingApprovalsSummary(BaseModel):
    total_pending: int
    vault_quorum_pending: int
    assembled_papers_pending: int
    release_queue_pending: int
    items: list[PendingApprovalItem]


# =========================================================================
# 7. SYSTEM HEALTH & REAL OPERATIONAL TELEMETRY SCHEMAS
# =========================================================================


class DatabaseHealth(BaseModel):
    status: str
    roundtrip_latency_ms: float
    pool_connected: bool
    engine: str


class StorageHealth(BaseModel):
    vault_storage_path: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    free_percent: float
    encrypted_payload_files_count: int
    status: str


class BackgroundJobsHealth(BaseModel):
    total_jobs: int
    pending_jobs: int
    running_jobs: int
    failed_jobs: int
    completed_jobs: int
    status: str


class BackupHealth(BaseModel):
    last_backup_timestamp_utc: datetime | None
    backup_file_present: bool
    backup_size_bytes: int
    status: str


class IntegrationHealth(BaseModel):
    kms_status: str
    kms_active_kek_version: str
    kms_keys_count: int
    ai_service_status: str
    ai_service_configured: bool
    audit_chain_integrity: bool


class SystemHealthConsole(BaseModel):
    status: str
    server_time_utc: datetime
    server_clock_synchronized: bool
    is_synthetic_telemetry: bool = False
    telemetry_type: str = "REAL_OPERATIONAL_MEASUREMENT"
    database: DatabaseHealth
    storage: StorageHealth
    background_jobs: BackgroundJobsHealth
    backup: BackupHealth
    integrations: IntegrationHealth
