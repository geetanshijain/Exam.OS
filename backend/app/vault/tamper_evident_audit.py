import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vault import VaultAuditEntry

logger = logging.getLogger(__name__)

GENESIS_PREV_HASH = "0000000000000000000000000000000000000000000000000000000000000000"


def format_audit_timestamp(ts: datetime) -> str:
    """Canonical UTC string formatted to second precision to prevent DB driver drift."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_audit_hash(
    sequence_num: int,
    actor_id: int,
    actor_email: str,
    action: str,
    vault_paper_id: int | None,
    paper_version: int | None,
    timestamp_iso: str,
    metadata_json: str | None,
    previous_hash: str,
) -> str:
    """Computes deterministic SHA-256 hash for audit entry chaining."""
    payload = (
        f"{sequence_num}|{actor_id}|{actor_email}|{action}|"
        f"{vault_paper_id or ''}|{paper_version or ''}|"
        f"{timestamp_iso}|{metadata_json or ''}|{previous_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def record_vault_audit(
    session: AsyncSession,
    actor_id: int,
    actor_email: str,
    action: str,
    vault_paper_id: int | None = None,
    paper_version: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> VaultAuditEntry:
    """
    Appends a tamper-evident audit record cryptographically chained to the previous entry.
    Never logs passwords, tokens, or plaintext paper contents.
    """
    # Fetch previous entry
    stmt = select(VaultAuditEntry).order_by(VaultAuditEntry.sequence_num.desc()).limit(1)
    res = await session.execute(stmt)
    latest = res.scalar_one_or_none()

    if latest:
        next_seq = latest.sequence_num + 1
        prev_hash = latest.entry_hash
    else:
        next_seq = 1
        prev_hash = GENESIS_PREV_HASH

    now = datetime.now(timezone.utc)
    now_iso = format_audit_timestamp(now)
    meta_json = json.dumps(metadata, sort_keys=True) if metadata else None

    entry_hash = compute_audit_hash(
        sequence_num=next_seq,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        vault_paper_id=vault_paper_id,
        paper_version=paper_version,
        timestamp_iso=now_iso,
        metadata_json=meta_json,
        previous_hash=prev_hash,
    )

    entry = VaultAuditEntry(
        sequence_num=next_seq,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        vault_paper_id=vault_paper_id,
        paper_version=paper_version,
        metadata_json=meta_json,
        previous_hash=prev_hash,
        entry_hash=entry_hash,
        timestamp=now,
    )
    session.add(entry)
    await session.flush()
    return entry


async def verify_audit_chain_integrity(session: AsyncSession) -> tuple[bool, list[str]]:
    """
    Validates the entire audit log hash chain to ensure tamper-evidence.
    Detects if any row has been altered, deleted, or injected.
    """
    stmt = select(VaultAuditEntry).order_by(VaultAuditEntry.sequence_num.asc())
    res = await session.execute(stmt)
    entries = res.scalars().all()

    issues: list[str] = []
    expected_prev = GENESIS_PREV_HASH

    for idx, entry in enumerate(entries):
        # 1. Verify sequence monotonicity
        if entry.sequence_num != idx + 1:
            issues.append(f"Broken audit sequence: expected {idx + 1}, found {entry.sequence_num}")

        # 2. Verify previous hash chaining
        if entry.previous_hash != expected_prev:
            issues.append(
                f"Broken audit chain at sequence {entry.sequence_num}: "
                f"recorded prev_hash '{entry.previous_hash}' does not match expected '{expected_prev}'"
            )

        # 3. Verify entry hash integrity
        calculated_hash = compute_audit_hash(
            sequence_num=entry.sequence_num,
            actor_id=entry.actor_id,
            actor_email=entry.actor_email,
            action=entry.action,
            vault_paper_id=entry.vault_paper_id,
            paper_version=entry.paper_version,
            timestamp_iso=format_audit_timestamp(entry.timestamp),
            metadata_json=entry.metadata_json,
            previous_hash=entry.previous_hash,
        )

        if calculated_hash != entry.entry_hash:
            issues.append(
                f"Audit record tampering detected at sequence {entry.sequence_num}: "
                f"recalculated digest '{calculated_hash}' does not match stored '{entry.entry_hash}'"
            )

        expected_prev = entry.entry_hash

    is_valid = (len(issues) == 0)
    return is_valid, issues
