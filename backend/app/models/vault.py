import enum
from datetime import datetime, timezone

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class VaultStatus(str, enum.Enum):
    encrypted_draft = "encrypted_draft"
    pending_approvals = "pending_approvals"
    approved_locked = "approved_locked"
    released = "released"
    emergency_locked = "emergency_locked"
    revoked = "revoked"


class VaultPaper(Base):
    __tablename__ = "vault_papers"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    paper_code: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    
    status: Mapped[VaultStatus] = mapped_column(
        Enum(VaultStatus, native_enum=False),
        default=VaultStatus.encrypted_draft,
        nullable=False,
        index=True,
    )
    
    # Private encrypted payload storage (public access strictly disabled)
    ciphertext_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    
    # Envelope Encryption: Unique DEK encrypted under managed KMS KEK
    wrapped_dek: Mapped[str] = mapped_column(String(500), nullable=False)
    kek_version: Mapped[str] = mapped_column(String(50), default="v1", nullable=False)
    
    # Authenticated Encryption primitives (AES-256-GCM)
    nonce_b64: Mapped[str] = mapped_column(String(100), nullable=False)
    tag_b64: Mapped[str] = mapped_column(String(100), nullable=False)
    aad_json: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    
    # Multi-Party Quorum Governance (K-of-N Separation of Duties)
    approval_threshold: Mapped[int] = mapped_column(Integer, default=2, nullable=False)
    current_approvals_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    approvals_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Controlled Scheduled Release Window
    scheduled_release_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scheduled_release_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    
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


class VaultAuditEntry(Base):
    __tablename__ = "vault_audit_entries"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    sequence_num: Mapped[int] = mapped_column(Integer, unique=True, nullable=False, index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    
    vault_paper_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    paper_version: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    
    # Cryptographic Hash Chain for Tamper-Evidence
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )
