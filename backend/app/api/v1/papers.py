import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import CurrentUser, get_current_user, require_permission
from app.core.pdf_utils import build_decoy_pdf, stamp_pdf_bytes
from app.core.permissions import Permission, verify_paper_object_access
from app.db.session import get_session
from app.models.alert import Alert, AlertSeverity
from app.models.approval import Approval, ApprovalStatus
from app.models.audit_log import AuditLog
from app.models.print_history import PrintHistory
from app.models.question_paper import PaperStatus, QuestionPaper
from app.models.risk_score import RiskScore
from app.models.user import User, UserRole

router = APIRouter(prefix="/papers", tags=["papers"])

VAULT_DIR = Path(__file__).resolve().parents[4] / "vault"
VAULT_DIR.mkdir(parents=True, exist_ok=True)

DOWNLOAD_WINDOW_MINUTES = 30


def _aes_encrypt(data: bytes) -> tuple[bytes, bytes, bytes]:
    key = get_random_bytes(32)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return key, cipher.nonce, tag + ciphertext


def _aes_decrypt(key_hex: str, nonce_hex: str, payload: bytes) -> bytes:
    key = bytes.fromhex(key_hex)
    nonce = bytes.fromhex(nonce_hex)
    tag = payload[:16]
    ciphertext = payload[16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _fire_honeytoken(
    session: AsyncSession,
    actor: User,
    paper_id: int | None,
    reason: str,
    ip: str,
) -> None:
    """Synchronous honeytoken trigger. Strictly avoids unmanaged background tasks."""
    meta = json.dumps({"ip": ip, "reason": reason, "paper_id": paper_id})

    alert = Alert(
        severity=AlertSeverity.critical,
        message=f"Honeytoken triggered by {actor.email}: {reason}",
        paper_id=paper_id,
        actor_id=actor.id,
        resolved=False,
    )
    audit = AuditLog(
        actor_id=actor.id,
        action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
        entity_type="QuestionPaper",
        entity_id=paper_id,
        metadata_json=meta,
    )
    session.add(alert)
    session.add(audit)

    if paper_id is not None:
        existing = await session.scalar(
            select(RiskScore).where(RiskScore.paper_id == paper_id)
        )
        if existing:
            existing.score = min(existing.score + 50.0, 100.0)
            existing.factors_json = json.dumps(
                {"last_trigger": reason, "ip": ip, "actor": actor.email}
            )
            existing.computed_at = datetime.now(timezone.utc)
        else:
            session.add(
                RiskScore(
                    paper_id=paper_id,
                    score=50.0,
                    factors_json=json.dumps(
                        {"trigger": reason, "ip": ip, "actor": actor.email}
                    ),
                )
            )

    await session.commit()


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_paper(
    current_user: Annotated[User, Depends(require_permission(Permission.CREATE_QUESTIONS))],
    session: Annotated[AsyncSession, Depends(get_session)],
    title: Annotated[str, Form()],
    subject: Annotated[str, Form()],
    exam_date: Annotated[str, Form()],
    department: Annotated[str | None, Form()] = None,
    description: Annotated[str | None, Form()] = None,
    file: UploadFile = File(...),
) -> dict:
    """
    Upload question paper with AES-256 vault encryption and
    department object-level assignment.
    """
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file upload.")

    # Target department defaults to setter's assigned department
    target_dept = department.strip() if (department and department.strip()) else current_user.department

    # Cross-department prevention: Setters cannot author papers outside their department
    if current_user.role == UserRole.setter and target_dept.lower() != current_user.department.lower():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Cannot create question papers outside assigned department.",
        )

    key, nonce, payload = _aes_encrypt(raw)
    blob_name = f"{uuid.uuid4().hex}.enc"
    blob_path = VAULT_DIR / blob_name
    blob_path.write_bytes(payload)

    key_meta = json.dumps({"key": key.hex(), "nonce": nonce.hex()})

    try:
        exam_dt = datetime.fromisoformat(exam_date)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Invalid exam_date format. Please use ISO 8601.",
        )

    paper = QuestionPaper(
        title=title.strip(),
        subject=subject.strip(),
        department=target_dept,
        exam_date=exam_dt,
        description=description,
        file_path=str(blob_path),
        encrypted_key=key_meta,
        status=PaperStatus.pending_hod,
        created_by=current_user.id,
    )
    session.add(paper)
    await session.commit()
    await session.refresh(paper)

    return {
        "id": paper.id,
        "title": paper.title,
        "subject": paper.subject,
        "department": paper.department,
        "status": paper.status.value,
        "created_at": paper.created_at.isoformat(),
    }


@router.get("/")
async def list_papers(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[dict]:
    """
    List papers scoped by object-level authorization and department boundaries.
    """
    stmt = select(QuestionPaper)

    # Setters only see their own authored papers
    if current_user.role == UserRole.setter:
        stmt = stmt.where(QuestionPaper.created_by == current_user.id)
    # HODs only see papers within their department
    elif current_user.role == UserRole.hod:
        stmt = stmt.where(QuestionPaper.department.ilike(current_user.department))
    # Controllers and Admins see all institutional papers

    result = await session.execute(stmt.order_by(QuestionPaper.created_at.desc()))
    papers = result.scalars().all()

    return [
        {
            "id": p.id,
            "title": p.title,
            "subject": p.subject,
            "department": p.department,
            "exam_date": p.exam_date.isoformat(),
            "status": p.status.value,
            "created_by": p.created_by,
            "created_at": p.created_at.isoformat(),
            "description": p.description,
        }
        for p in papers
    ]


@router.get("/{paper_id}")
async def get_paper(
    paper_id: int,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    """Get single paper detail with object-level IDOR validation."""
    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found.")

    verify_paper_object_access(current_user, paper)

    return {
        "id": paper.id,
        "title": paper.title,
        "subject": paper.subject,
        "department": paper.department,
        "exam_date": paper.exam_date.isoformat(),
        "status": paper.status.value,
        "created_by": paper.created_by,
        "created_at": paper.created_at.isoformat(),
        "description": paper.description,
    }


@router.patch("/{paper_id}/hod-review")
async def hod_review(
    paper_id: int,
    action: str,
    current_user: Annotated[User, Depends(require_permission(Permission.REVIEW_PAPERS))],
    session: Annotated[AsyncSession, Depends(get_session)],
    comment: str | None = None,
) -> dict:
    """
    Department Head review stage. Enforces departmental object-level boundary
    and creates an immutable Approval record.
    """
    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found.")

    # Object-level check: HOD can only review papers within their department
    verify_paper_object_access(current_user, paper)

    if paper.status != PaperStatus.pending_hod:
        raise HTTPException(
            status_code=409,
            detail=f"Paper is not in Pending_HOD state (current: {paper.status.value})",
        )

    if action == "approve":
        paper.status = PaperStatus.pending_controller
        approval_status = ApprovalStatus.approved
    elif action == "reject":
        paper.status = PaperStatus.rejected
        approval_status = ApprovalStatus.rejected
    else:
        raise HTTPException(status_code=422, detail="action must be 'approve' or 'reject'")

    approval = Approval(
        paper_id=paper.id,
        approver_id=current_user.id,
        status=approval_status,
        comment=comment,
        approved_at=datetime.now(timezone.utc),
    )
    session.add(approval)
    await session.commit()

    return {"id": paper.id, "status": paper.status.value, "stage": "hod_completed"}


@router.patch("/{paper_id}/controller-review")
async def controller_review(
    paper_id: int,
    action: str,
    current_user: Annotated[User, Depends(require_permission(Permission.APPROVE_RELEASE, require_mfa=True))],
    session: Annotated[AsyncSession, Depends(get_session)],
    comment: str | None = None,
) -> dict:
    """
    Institutional Controller approval. Requires verified MFA and enforces dual-custody
    (controller cannot be the same user who approved HOD step).
    """
    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found.")

    if paper.status != PaperStatus.pending_controller:
        raise HTTPException(
            status_code=409,
            detail=f"Paper is not in Pending_Controller state (current: {paper.status.value})",
        )

    # Dual-Custody Check: Verify controller is not the original HOD approver
    last_approval_stmt = (
        select(Approval)
        .where(Approval.paper_id == paper.id, Approval.status == ApprovalStatus.approved)
        .order_by(Approval.created_at.desc())
    )
    last_approval = (await session.execute(last_approval_stmt)).scalars().first()
    if last_approval and last_approval.approver_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Dual-custody policy violation: Final release approver cannot be the same individual as the initial department reviewer.",
        )

    if action == "approve":
        paper.status = PaperStatus.approved_locked
        approval_status = ApprovalStatus.approved
    elif action == "reject":
        paper.status = PaperStatus.rejected
        approval_status = ApprovalStatus.rejected
    else:
        raise HTTPException(status_code=422, detail="action must be 'approve' or 'reject'")

    approval = Approval(
        paper_id=paper.id,
        approver_id=current_user.id,
        status=approval_status,
        comment=comment,
        approved_at=datetime.now(timezone.utc),
    )
    session.add(approval)
    await session.commit()

    return {"id": paper.id, "status": paper.status.value, "stage": "release_approved"}


@router.get("/{paper_id}/download")
async def download_paper(
    paper_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    """
    Time-locked paper extraction with dynamic forensic watermarking
    and stealth decoy honeytoken delivery for out-of-window requests.
    """
    ip = _client_ip(request)
    now = datetime.now(timezone.utc)

    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found")

    # Object-level check: Ensure user has rights to this paper
    verify_paper_object_access(current_user, paper)

    allowed_roles = {UserRole.printer, UserRole.controller, UserRole.admin}
    is_authorized_role = current_user.role in allowed_roles

    exam_dt = paper.exam_date
    if exam_dt.tzinfo is None:
        exam_dt = exam_dt.replace(tzinfo=timezone.utc)

    window_open = exam_dt - timedelta(minutes=DOWNLOAD_WINDOW_MINUTES)
    is_within_window = now >= window_open
    is_approved = paper.status == PaperStatus.approved_locked

    # Trigger stealth honeytoken if access attempt is out-of-bounds
    if not is_authorized_role or not is_approved or not is_within_window:
        reason_parts = []
        if not is_authorized_role:
            reason_parts.append(f"role={current_user.role.value} not permitted")
        if not is_approved:
            reason_parts.append(f"status={paper.status.value}")
        if not is_within_window:
            delta = window_open - now
            minutes_left = int(delta.total_seconds() / 60)
            reason_parts.append(f"time-locked ({minutes_left}min remaining)")

        reason = "; ".join(reason_parts)
        await _fire_honeytoken(session, current_user, paper_id, reason, ip)

        decoy = build_decoy_pdf()
        safe_title = paper.title.replace(" ", "_")[:40]
        return Response(
            content=decoy,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{safe_title}_DRAFT.pdf"',
            },
        )

    if not paper.file_path or not paper.encrypted_key:
        raise HTTPException(status_code=500, detail="Vault asset record incomplete.")

    blob_path = Path(paper.file_path)
    if not blob_path.exists():
        raise HTTPException(status_code=500, detail="Encrypted asset missing from vault storage.")

    key_meta = json.loads(paper.encrypted_key)
    encrypted_payload = blob_path.read_bytes()
    clear_bytes = _aes_decrypt(key_meta["key"], key_meta["nonce"], encrypted_payload)

    # Record AuditLog and PrintHistory models
    audit = AuditLog(
        actor_id=current_user.id,
        action="AUTHORIZED_DOWNLOAD",
        entity_type="QuestionPaper",
        entity_id=paper_id,
        metadata_json=json.dumps({"ip": ip, "email": current_user.email}),
    )
    print_log = PrintHistory(
        paper_id=paper.id,
        printer_id=current_user.id,
        copies=1,
        location=f"IP: {ip}",
    )
    session.add(audit)
    session.add(print_log)
    await session.commit()

    # Dynamic forensic watermark
    stamped = stamp_pdf_bytes(clear_bytes, current_user.email, ip, now)
    safe_title = paper.title.replace(" ", "_")[:40]

    return Response(
        content=stamped,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_title}_SECURE.pdf"',
        },
    )
