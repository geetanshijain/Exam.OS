import asyncio
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

from app.core.deps import ControllerUser, HODUser, SetterUser, get_current_user
from app.core.pdf_utils import build_decoy_pdf, stamp_pdf_bytes
from app.db.session import get_session
from app.models.alert import Alert, AlertSeverity
from app.models.audit_log import AuditLog
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
    current_user: SetterUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    title: Annotated[str, Form()],
    subject: Annotated[str, Form()],
    exam_date: Annotated[str, Form()],
    description: Annotated[str | None, Form()] = None,
    file: UploadFile = File(...),
) -> dict:
    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file")

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
            detail="Invalid exam_date format (use ISO 8601)",
        )

    paper = QuestionPaper(
        title=title,
        subject=subject,
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
        "status": paper.status.value,
        "created_at": paper.created_at.isoformat(),
    }


@router.get("/")
async def list_papers(
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[dict]:
    if current_user.role.value == "setter":
        stmt = select(QuestionPaper).where(QuestionPaper.created_by == current_user.id)
    else:
        stmt = select(QuestionPaper)

    result = await session.execute(stmt.order_by(QuestionPaper.created_at.desc()))
    papers = result.scalars().all()

    return [
        {
            "id": p.id,
            "title": p.title,
            "subject": p.subject,
            "exam_date": p.exam_date.isoformat(),
            "status": p.status.value,
            "created_by": p.created_by,
            "created_at": p.created_at.isoformat(),
            "description": p.description,
        }
        for p in papers
    ]


@router.get("/{paper_id}/download")
async def download_paper(
    paper_id: int,
    request: Request,
    current_user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Response:
    ip = _client_ip(request)
    now = datetime.now(timezone.utc)

    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found")

    allowed_roles = {UserRole.printer, UserRole.controller, UserRole.admin}
    is_authorized_role = current_user.role in allowed_roles

    exam_dt = paper.exam_date
    if exam_dt.tzinfo is None:
        exam_dt = exam_dt.replace(tzinfo=timezone.utc)

    window_open = exam_dt - timedelta(minutes=DOWNLOAD_WINDOW_MINUTES)
    is_within_window = now >= window_open
    is_approved = paper.status == PaperStatus.approved_locked

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
        asyncio.ensure_future(
            _fire_honeytoken(session, current_user, paper_id, reason, ip)
        )

        decoy = build_decoy_pdf()
        return Response(
            content=decoy,
            media_type="application/pdf",
            headers={
                "Content-Disposition": 'attachment; filename="ExamOS_Decoy_Document.pdf"',
            },
        )

    if not paper.file_path or not paper.encrypted_key:
        raise HTTPException(status_code=500, detail="Vault record incomplete")

    blob_path = Path(paper.file_path)
    if not blob_path.exists():
        raise HTTPException(status_code=500, detail="Encrypted asset missing from vault")

    key_meta = json.loads(paper.encrypted_key)
    encrypted_payload = blob_path.read_bytes()
    clear_bytes = _aes_decrypt(key_meta["key"], key_meta["nonce"], encrypted_payload)

    audit = AuditLog(
        actor_id=current_user.id,
        action="AUTHORIZED_DOWNLOAD",
        entity_type="QuestionPaper",
        entity_id=paper_id,
        metadata_json=json.dumps({"ip": ip, "email": current_user.email}),
    )
    session.add(audit)
    await session.commit()

    stamped = stamp_pdf_bytes(clear_bytes, current_user.email, ip, now)
    safe_title = paper.title.replace(" ", "_")[:40]

    return Response(
        content=stamped,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{safe_title}_SECURE.pdf"',
        },
    )


@router.patch("/{paper_id}/hod-review")
async def hod_review(
    paper_id: int,
    action: str,
    current_user: HODUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found")
    if paper.status != PaperStatus.pending_hod:
        raise HTTPException(
            status_code=409,
            detail=f"Paper is not in Pending_HOD state (current: {paper.status.value})",
        )

    if action == "approve":
        paper.status = PaperStatus.pending_controller
    elif action == "reject":
        paper.status = PaperStatus.rejected
    else:
        raise HTTPException(status_code=422, detail="action must be 'approve' or 'reject'")

    await session.commit()
    return {"id": paper.id, "status": paper.status.value}


@router.patch("/{paper_id}/controller-review")
async def controller_review(
    paper_id: int,
    action: str,
    current_user: ControllerUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict:
    paper = await session.get(QuestionPaper, paper_id)
    if not paper:
        raise HTTPException(status_code=404, detail="Paper not found")
    if paper.status != PaperStatus.pending_controller:
        raise HTTPException(
            status_code=409,
            detail=f"Paper is not in Pending_Controller state (current: {paper.status.value})",
        )

    if action == "approve":
        paper.status = PaperStatus.approved_locked
    elif action == "reject":
        paper.status = PaperStatus.rejected
    else:
        raise HTTPException(status_code=422, detail="action must be 'approve' or 'reject'")

    await session.commit()
    return {"id": paper.id, "status": paper.status.value}
