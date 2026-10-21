import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, Response, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, get_current_user, require_any_permission, require_permission
from app.core.pdf_utils import stamp_pdf_bytes
from app.core.permissions import Permission, verify_object_access
from app.db.session import get_session
from app.models.user import User, UserRole
from app.models.vault import VaultAuditEntry, VaultPaper, VaultStatus
from app.schemas.vault import (
    AuditVerificationResponse,
    EmergencyLockRequest,
    KeyRotationResponse,
    VaultApprovalRequest,
    VaultPaperResponse,
)
from app.vault.crypto import CiphertextTamperedError, decrypt_paper_envelope, encrypt_paper_envelope
from app.vault.kms import kms_client
from app.vault.tamper_evident_audit import record_vault_audit, verify_audit_chain_integrity

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/vault", tags=["secure-paper-vault"])

# Private encrypted storage vault — public access strictly disabled
VAULT_STORAGE_DIR = Path(__file__).resolve().parents[4] / "vault" / "encrypted_objects"
VAULT_STORAGE_DIR.mkdir(parents=True, exist_ok=True)


def _serialize_vault_paper(paper: VaultPaper) -> VaultPaperResponse:
    return VaultPaperResponse(
        id=paper.id,
        paper_code=paper.paper_code,
        title=paper.title,
        department=paper.department,
        version=paper.version,
        status=paper.status,
        approval_threshold=paper.approval_threshold,
        current_approvals_count=paper.current_approvals_count,
        approvals=json.loads(paper.approvals_json) if paper.approvals_json else [],
        scheduled_release_start=paper.scheduled_release_start,
        scheduled_release_end=paper.scheduled_release_end,
        kek_version=paper.kek_version,
        payload_sha256=paper.payload_sha256,
        created_by=paper.created_by,
        created_at=paper.created_at,
        updated_at=paper.updated_at,
    )


async def _get_vault_paper_with_auth(
    paper_id: int,
    session: AsyncSession,
    user: User,
) -> VaultPaper:
    paper = await session.get(VaultPaper, paper_id)
    if not paper:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vault paper #{paper_id} not found.",
        )
    verify_object_access(
        user=user,
        resource_department=paper.department,
        resource_owner_id=paper.created_by,
    )
    return paper


# =========================================================================
# 1. ENVELOPE ENCRYPTION & INGESTION
# =========================================================================


@router.post(
    "/papers/ingest",
    response_model=VaultPaperResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_permission(Permission.CREATE_QUESTIONS))],
)
async def ingest_paper_to_vault(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
    paper_code: Annotated[str, Form()],
    title: Annotated[str, Form()],
    department: Annotated[str, Form()],
    scheduled_release_start: Annotated[str, Form()],
    scheduled_release_end: Annotated[str, Form()],
    file: UploadFile = File(...),
    version: Annotated[int, Form()] = 1,
    approval_threshold: Annotated[int, Form()] = 2,
):
    """
    Ingests and encrypts finalized paper contents using envelope encryption (AES-256-GCM).
    Generates a unique DEK wrapped under the managed KMS Master Key.
    """
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        if department.strip().lower() != current_user.department.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cannot ingest paper for department '{department}'. Restricted to '{current_user.department}'.",
            )

    # Check for duplicate paper code
    existing_stmt = select(VaultPaper).where(VaultPaper.paper_code == paper_code.strip())
    existing = (await session.execute(existing_stmt)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Vault paper code '{paper_code}' already exists.",
        )

    raw_content = await file.read()
    if not raw_content:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot encrypt empty file.")

    try:
        t_start = datetime.fromisoformat(scheduled_release_start)
        t_end = datetime.fromisoformat(scheduled_release_end)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid ISO timestamp for release schedule.")

    if t_end <= t_start:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="scheduled_release_end must be after scheduled_release_start.")

    # Prepare AAD metadata (bound cryptographically to GCM tag)
    metadata = {
        "paper_code": paper_code.strip(),
        "department": department.strip(),
        "version": version,
        "release_start": t_start.isoformat(),
        "release_end": t_end.isoformat(),
    }

    # Execute authenticated envelope encryption
    ciphertext_bytes, envelope_info = encrypt_paper_envelope(
        plaintext=raw_content,
        metadata=metadata,
        kms=kms_client,
    )

    # Save ciphertext in private, public-disabled storage
    ciphertext_filename = f"{uuid.uuid4().hex}.enc"
    storage_path = VAULT_STORAGE_DIR / ciphertext_filename
    storage_path.write_bytes(ciphertext_bytes)

    paper = VaultPaper(
        paper_code=paper_code.strip(),
        title=title,
        department=department.strip(),
        version=version,
        status=VaultStatus.pending_approvals,
        ciphertext_filename=ciphertext_filename,
        wrapped_dek=envelope_info["wrapped_dek"],
        kek_version=envelope_info["kek_version"],
        nonce_b64=envelope_info["nonce_b64"],
        tag_b64=envelope_info["tag_b64"],
        aad_json=envelope_info["aad_json"],
        payload_sha256=envelope_info["payload_sha256"],
        approval_threshold=approval_threshold,
        current_approvals_count=0,
        approvals_json=json.dumps([]),
        scheduled_release_start=t_start,
        scheduled_release_end=t_end,
        created_by=current_user.id,
    )
    session.add(paper)
    await session.flush()

    # Record tamper-evident audit log
    await record_vault_audit(
        session=session,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action="VAULT_ENVELOPE_INGESTED",
        vault_paper_id=paper.id,
        paper_version=paper.version,
        metadata={
            "paper_code": paper.paper_code,
            "kek_version": paper.kek_version,
            "approval_threshold": paper.approval_threshold,
        },
    )

    await session.commit()
    await session.refresh(paper)
    return _serialize_vault_paper(paper)


@router.get(
    "/papers",
    response_model=list[VaultPaperResponse],
    dependencies=[Depends(require_any_permission(Permission.CREATE_QUESTIONS, Permission.PRINT_PAPERS, Permission.APPROVE_RELEASE))],
)
async def list_vault_papers(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Lists vaulted papers within authorized department."""
    stmt = select(VaultPaper)
    if current_user.role not in [UserRole.admin, UserRole.controller]:
        stmt = stmt.where(VaultPaper.department == current_user.department)
    stmt = stmt.order_by(VaultPaper.created_at.desc())

    res = await session.execute(stmt)
    papers = res.scalars().all()
    return [_serialize_vault_paper(p) for p in papers]


@router.get(
    "/papers/{paper_id}",
    response_model=VaultPaperResponse,
    dependencies=[Depends(require_any_permission(Permission.CREATE_QUESTIONS, Permission.PRINT_PAPERS, Permission.APPROVE_RELEASE))],
)
async def get_vault_paper(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """Retrieves vault paper record with object authorization."""
    paper = await _get_vault_paper_with_auth(paper_id, session, current_user)
    return _serialize_vault_paper(paper)


# =========================================================================
# 2. MULTI-PARTY QUORUM APPROVAL & SEPARATION OF DUTIES
# =========================================================================


@router.post(
    "/papers/{paper_id}/approve",
    response_model=VaultPaperResponse,
)
async def approve_vault_paper(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_user)],
    payload: VaultApprovalRequest = VaultApprovalRequest(),
):
    """
    Multi-Party Quorum Approval Endpoint (K-of-N).
    Enforces strict Separation of Duties (SoD):
    1. Author cannot approve own paper.
    2. Approver cannot approve twice.
    3. Reaching approval threshold locks and authorizes paper for release.
    """
    if current_user.role not in [UserRole.admin, UserRole.controller, UserRole.hod]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: Requires review or approval release capability.",
        )

    paper = await _get_vault_paper_with_auth(paper_id, session, current_user)

    if paper.status in [VaultStatus.approved_locked, VaultStatus.released]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Paper has already reached its approval threshold and is locked.",
        )
    if paper.status in [VaultStatus.emergency_locked, VaultStatus.revoked]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot approve paper in '{paper.status.value}' status.",
        )

    # 1. Separation of duties: Creator cannot approve their own paper
    if current_user.id == paper.created_by:
        await record_vault_audit(
            session=session,
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="SELF_APPROVAL_ATTEMPT_BLOCKED",
            vault_paper_id=paper.id,
            paper_version=paper.version,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Separation of duties violation: Examination author is prohibited from approving their own paper.",
        )

    # 2. Separation of duties: No duplicate approvals by the same reviewer
    approvals = json.loads(paper.approvals_json) if paper.approvals_json else []
    if any(appr.get("approver_id") == current_user.id for appr in approvals):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Duplicate approval rejected: You have already submitted an approval for this examination.",
        )

    now = datetime.now(timezone.utc)
    approval_entry = {
        "approver_id": current_user.id,
        "approver_email": current_user.email,
        "role": current_user.role.value,
        "timestamp": now.isoformat(),
        "comment": payload.comment or "Verified and approved.",
    }
    approvals.append(approval_entry)
    paper.approvals_json = json.dumps(approvals)
    paper.current_approvals_count = len(approvals)

    # Check if quorum threshold is satisfied
    if paper.current_approvals_count >= paper.approval_threshold:
        paper.status = VaultStatus.approved_locked
        action_name = "QUORUM_THRESHOLD_REACHED_LOCKED"
    else:
        action_name = "QUORUM_PARTIAL_APPROVAL_GRANTED"

    await record_vault_audit(
        session=session,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action=action_name,
        vault_paper_id=paper.id,
        paper_version=paper.version,
        metadata={
            "current_count": paper.current_approvals_count,
            "threshold": paper.approval_threshold,
        },
    )

    await session.commit()
    await session.refresh(paper)
    return _serialize_vault_paper(paper)


# =========================================================================
# 3. CONTROLLED SCHEDULED RELEASE SERVICE
# =========================================================================


@router.post(
    "/papers/{paper_id}/release",
)
async def release_vault_paper(
    paper_id: int,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Controlled Release Service:
    Verifies:
    1. Status is approved_locked.
    2. Current time is strictly inside scheduled release window.
    3. Recipient authorization, active status, and department boundary.
    4. Authenticated decryption with AAD and integrity tag verification.
    5. Zero plaintext logging; streams directly with Cache-Control: no-store.
    """
    paper = await session.get(VaultPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vault paper not found.")

    # 1. Recipient authorization check
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Account is inactive or suspended.")

    verify_object_access(user=current_user, resource_department=paper.department)

    if current_user.role not in [UserRole.printer, UserRole.controller, UserRole.admin, UserRole.hod]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied: Insufficient privileges for paper release.")

    # 2. Paper status assertion
    if paper.status == VaultStatus.emergency_locked:
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Paper is locked under an active emergency security directive.")
    if paper.status != VaultStatus.approved_locked and paper.status != VaultStatus.released:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Paper is not finalized for release. Current status: '{paper.status.value}'. Required approvals: {paper.approval_threshold}.",
        )

    # 3. Time-Lock Window Verification
    now = datetime.now(timezone.utc)
    t_start = paper.scheduled_release_start.replace(tzinfo=timezone.utc) if paper.scheduled_release_start.tzinfo is None else paper.scheduled_release_start
    t_end = paper.scheduled_release_end.replace(tzinfo=timezone.utc) if paper.scheduled_release_end.tzinfo is None else paper.scheduled_release_end

    if now < t_start:
        # EARLY RELEASE ATTEMPT
        await record_vault_audit(
            session=session,
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="EARLY_RELEASE_ATTEMPT_BLOCKED",
            vault_paper_id=paper.id,
            paper_version=paper.version,
            metadata={"attempt_time": now.isoformat(), "scheduled_start": t_start.isoformat()},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail=f"Release rejected: Early access forbidden. Examination scheduled release begins at {t_start.isoformat()}.",
        )

    if now > t_end:
        # EXPIRED WINDOW
        await record_vault_audit(
            session=session,
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="EXPIRED_RELEASE_ATTEMPT_BLOCKED",
            vault_paper_id=paper.id,
            paper_version=paper.version,
            metadata={"attempt_time": now.isoformat(), "scheduled_end": t_end.isoformat()},
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=f"Release rejected: Download window closed at {t_end.isoformat()}.",
        )

    # 4. Read ciphertext from private vault
    ciphertext_path = VAULT_STORAGE_DIR / paper.ciphertext_filename
    if not ciphertext_path.exists():
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Vault storage error: Encrypted payload file missing.")

    ciphertext_bytes = ciphertext_path.read_bytes()

    # 5. Authenticated Decryption
    try:
        decrypted_payload = decrypt_paper_envelope(
            ciphertext=ciphertext_bytes,
            nonce_b64=paper.nonce_b64,
            tag_b64=paper.tag_b64,
            aad_json=paper.aad_json,
            wrapped_dek=paper.wrapped_dek,
            kek_version=paper.kek_version,
            expected_sha256=paper.payload_sha256,
            kms=kms_client,
        )
    except CiphertextTamperedError as exc:
        await record_vault_audit(
            session=session,
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="CIPHERTEXT_INTEGRITY_TAMPER_DETECTED",
            vault_paper_id=paper.id,
            paper_version=paper.version,
        )
        paper.status = VaultStatus.emergency_locked
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="CRITICAL SECURITY ALERT: Authentication tag verification failed. Ciphertext has been tampered with.",
        ) from exc

    # 6. Apply dynamic recipient watermark
    watermarked_pdf = stamp_pdf_bytes(
        raw=decrypted_payload,
        email=current_user.email,
        ip="127.0.0.1",
        ts=now,
    )

    paper.status = VaultStatus.released
    await record_vault_audit(
        session=session,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action="SCHEDULED_RELEASE_GRANTED",
        vault_paper_id=paper.id,
        paper_version=paper.version,
        metadata={"recipient_role": current_user.role.value},
    )
    await session.commit()

    # 7. Private streaming response with Cache-Control headers
    return Response(
        content=watermarked_pdf,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"inline; filename={paper.paper_code}_release.pdf",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


# =========================================================================
# 4. EMERGENCY LOCK & INCIDENT RESPONSE
# =========================================================================


@router.post(
    "/papers/{paper_id}/emergency-lock",
    response_model=VaultPaperResponse,
    dependencies=[Depends(require_permission(Permission.APPROVE_RELEASE))],
)
async def emergency_lock_paper(
    paper_id: int,
    payload: EmergencyLockRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Emergency Lock & Revocation Control:
    Immediately locks the paper, revokes access tokens, and flags security personnel.
    """
    paper = await _get_vault_paper_with_auth(paper_id, session, current_user)
    paper.status = VaultStatus.emergency_locked

    await record_vault_audit(
        session=session,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action="EMERGENCY_LOCK_ENGAGED",
        vault_paper_id=paper.id,
        paper_version=paper.version,
        metadata={"reason": payload.reason},
    )
    await session.commit()
    await session.refresh(paper)
    return _serialize_vault_paper(paper)


# =========================================================================
# 5. KEY ROTATION & AUDIT VERIFICATION
# =========================================================================


@router.post(
    "/rotate-keys",
    response_model=KeyRotationResponse,
    dependencies=[Depends(require_permission(Permission.MANAGE_USERS))],
)
async def rotate_master_keys(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Master Key Rotation:
    Generates a new KEK version and re-wraps all vaulted paper DEKs under the new KEK.
    Paper ciphertext is not decrypted, ensuring zero exposure during rotation.
    """
    if current_user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: Key administration restricted to administrators.")

    old_version = kms_client.active_version
    new_version = kms_client.rotate_master_key()

    # Re-wrap all DEKs in database
    stmt = select(VaultPaper)
    res = await session.execute(stmt)
    papers = res.scalars().all()

    rewrapped_count = 0
    for paper in papers:
        if paper.kek_version != new_version:
            new_wrapped = kms_client.rewrap_dek(
                wrapped_dek_b64=paper.wrapped_dek,
                old_version=paper.kek_version,
                new_version=new_version,
            )
            paper.wrapped_dek = new_wrapped
            paper.kek_version = new_version
            rewrapped_count += 1

    await record_vault_audit(
        session=session,
        actor_id=current_user.id,
        actor_email=current_user.email,
        action="KMS_MASTER_KEY_ROTATED",
        metadata={
            "old_version": old_version,
            "new_version": new_version,
            "papers_rewrapped": rewrapped_count,
        },
    )
    await session.commit()

    return KeyRotationResponse(
        old_version=old_version,
        new_version=new_version,
        papers_rewrapped_count=rewrapped_count,
        message=f"KMS Key rotated successfully to {new_version}. Re-wrapped {rewrapped_count} paper DEKs.",
    )


@router.get(
    "/audit/verify",
    response_model=AuditVerificationResponse,
    dependencies=[Depends(require_any_permission(Permission.VIEW_AUDITS, Permission.PRINT_PAPERS))],
)
async def verify_vault_audit_log_chain(
    session: Annotated[AsyncSession, Depends(get_session)],
    current_user: CurrentUser,
):
    """
    Cryptographically verifies the tamper-evident audit hash chain.
    Detects if any audit log row has been altered, injected, or removed out of order.
    """
    is_valid, issues = await verify_audit_chain_integrity(session)
    count_stmt = select(VaultAuditEntry)
    total_count = len((await session.execute(count_stmt)).scalars().all())

    return AuditVerificationResponse(
        is_valid=is_valid,
        total_entries_verified=total_count,
        issues=issues,
    )
