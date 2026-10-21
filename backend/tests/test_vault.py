import base64
import io
from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.vault import VaultAuditEntry, VaultPaper, VaultStatus
from app.vault.crypto import (
    CiphertextTamperedError,
    decrypt_paper_envelope,
    encrypt_paper_envelope,
)
from app.vault.kms import KMSKeyStore, kms_client
from app.vault.tamper_evident_audit import verify_audit_chain_integrity


# =========================================================================
# 1. UNIT TESTS: CRYPTOGRAPHIC ENVELOPE ENCRYPTION & KMS ROTATION
# =========================================================================


def test_envelope_encryption_tamper_detection_and_aad_binding():
    local_kms = KMSKeyStore()
    plaintext = b"CONFIDENTIAL UNIVERSITY FINAL EXAMINATION QUESTIONS 2026"
    metadata = {
        "paper_code": "CS-TEST-001",
        "department": "Computer Science",
        "version": 1,
        "release_start": "2026-10-15T10:00:00Z",
        "release_end": "2026-10-15T10:30:00Z",
    }

    # 1. Successful Encryption & Decryption
    ciphertext, envelope = encrypt_paper_envelope(plaintext, metadata, local_kms)
    assert len(ciphertext) > 0
    assert envelope["kek_version"] == "v1"

    decrypted = decrypt_paper_envelope(
        ciphertext=ciphertext,
        nonce_b64=envelope["nonce_b64"],
        tag_b64=envelope["tag_b64"],
        aad_json=envelope["aad_json"],
        wrapped_dek=envelope["wrapped_dek"],
        kek_version=envelope["kek_version"],
        expected_sha256=envelope["payload_sha256"],
        kms=local_kms,
    )
    assert decrypted == plaintext

    # 2. Tampered Ciphertext Test: Modify 1 byte of ciphertext
    tampered_ciphertext = bytearray(ciphertext)
    tampered_ciphertext[0] ^= 0xFF  # Flip bits of first byte

    with pytest.raises(CiphertextTamperedError) as exc_info:
        decrypt_paper_envelope(
            ciphertext=bytes(tampered_ciphertext),
            nonce_b64=envelope["nonce_b64"],
            tag_b64=envelope["tag_b64"],
            aad_json=envelope["aad_json"],
            wrapped_dek=envelope["wrapped_dek"],
            kek_version=envelope["kek_version"],
            expected_sha256=envelope["payload_sha256"],
            kms=local_kms,
        )
    assert "authentication tag verification failed" in str(exc_info.value).lower()

    # 3. Tampered AAD Test: Modify metadata bound to GCM tag
    tampered_metadata = dict(metadata)
    tampered_metadata["version"] = 2  # Tamper with version
    tampered_aad_json = '{"department":"Computer Science","paper_code":"CS-TEST-001","release_end":"2026-10-15T10:30:00Z","release_start":"2026-10-15T10:00:00Z","version":2}'

    with pytest.raises(CiphertextTamperedError):
        decrypt_paper_envelope(
            ciphertext=ciphertext,
            nonce_b64=envelope["nonce_b64"],
            tag_b64=envelope["tag_b64"],
            aad_json=tampered_aad_json,
            wrapped_dek=envelope["wrapped_dek"],
            kek_version=envelope["kek_version"],
            expected_sha256=envelope["payload_sha256"],
            kms=local_kms,
        )


def test_kms_master_key_rotation_and_zero_ciphertext_exposure():
    local_kms = KMSKeyStore()
    plaintext = b"UNIVERSITY EXAM PAPER PAYLOAD"
    metadata = {"paper_code": "ROTATION-01", "version": 1}

    ciphertext, envelope = encrypt_paper_envelope(plaintext, metadata, local_kms)
    assert envelope["kek_version"] == "v1"

    # Rotate Master Key (creates v2)
    new_version = local_kms.rotate_master_key()
    assert new_version == "v2"

    # Re-wrap DEK under v2 without decrypting ciphertext
    new_wrapped_dek = local_kms.rewrap_dek(envelope["wrapped_dek"], old_version="v1", new_version="v2")
    assert new_wrapped_dek != envelope["wrapped_dek"]

    # Decrypt with v2 wrapped DEK
    decrypted = decrypt_paper_envelope(
        ciphertext=ciphertext,
        nonce_b64=envelope["nonce_b64"],
        tag_b64=envelope["tag_b64"],
        aad_json=envelope["aad_json"],
        wrapped_dek=new_wrapped_dek,
        kek_version="v2",
        expected_sha256=envelope["payload_sha256"],
        kms=local_kms,
    )
    assert decrypted == plaintext


# =========================================================================
# 2. INTEGRATION TESTS: FULL VAULT LIFECYCLE & SECURITY CONTROLS
# =========================================================================


@pytest.mark.asyncio
async def test_vault_lifecycle_security_and_governance(client: AsyncClient, db_session: AsyncSession):
    now = datetime.now(timezone.utc)
    t_start = (now - timedelta(minutes=10)).isoformat()
    t_end = (now + timedelta(minutes=20)).isoformat()

    # 1. Register Actors
    # Setter (Creator)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "vault_setter@examos.edu", "username": "vault_setter", "password": "ValidPassword123!", "full_name": "Vault Author", "department": "Computer Science", "role": "setter"},
    )
    setter_login = await client.post("/api/v1/auth/login", json={"username_or_email": "vault_setter", "password": "ValidPassword123!"})
    setter_token = setter_login.json()["access_token"]
    setter_headers = {"Authorization": f"Bearer {setter_token}"}

    # Approver 1 (HOD)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "vault_hod@examos.edu", "username": "vault_hod", "password": "ValidPassword123!", "full_name": "Vault HOD", "department": "Computer Science", "role": "hod"},
    )
    hod_login = await client.post("/api/v1/auth/login", json={"username_or_email": "vault_hod", "password": "ValidPassword123!"})
    hod_token = hod_login.json()["access_token"]
    hod_headers = {"Authorization": f"Bearer {hod_token}"}

    # Approver 2 (Controller of Examinations)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "vault_coe@examos.edu", "username": "vault_coe", "password": "ValidPassword123!", "full_name": "Vault Controller", "department": "Computer Science", "role": "controller"},
    )
    coe_login = await client.post("/api/v1/auth/login", json={"username_or_email": "vault_coe", "password": "ValidPassword123!"})
    coe_token = coe_login.json()["access_token"]
    coe_headers = {"Authorization": f"Bearer {coe_token}"}

    # Printer / Invigilator
    await client.post(
        "/api/v1/auth/register",
        json={"email": "vault_printer@examos.edu", "username": "vault_printer", "password": "ValidPassword123!", "full_name": "Exam Center Printer", "department": "Computer Science", "role": "printer"},
    )
    printer_login = await client.post("/api/v1/auth/login", json={"username_or_email": "vault_printer", "password": "ValidPassword123!"})
    printer_token = printer_login.json()["access_token"]
    printer_headers = {"Authorization": f"Bearer {printer_token}"}

    # 2. Ingest Paper to Vault (AES-256-GCM Envelope Encryption)
    paper_payload = b"%PDF-1.4 Mock Encrypted Examination Paper Payload"
    ingest_res = await client.post(
        "/api/v1/vault/papers/ingest",
        headers=setter_headers,
        data={
            "paper_code": "CS-VAULT-2026",
            "title": "Advanced Operating Systems Final",
            "department": "Computer Science",
            "version": "1",
            "approval_threshold": "2",  # Requires 2 distinct approvals
            "scheduled_release_start": t_start,
            "scheduled_release_end": t_end,
        },
        files={"file": ("exam.pdf", paper_payload, "application/pdf")},
    )
    assert ingest_res.status_code == 201
    paper_data = ingest_res.json()
    paper_id = paper_data["id"]
    assert paper_data["status"] == VaultStatus.pending_approvals.value
    assert paper_data["approval_threshold"] == 2
    assert paper_data["current_approvals_count"] == 0

    # 3. Security Test: Premature Release Attempt (Before reaching approval quorum)
    premature_release = await client.post(f"/api/v1/vault/papers/{paper_id}/release", headers=printer_headers)
    assert premature_release.status_code == 403
    assert "not finalized for release" in premature_release.json()["detail"].lower()

    # 4a. Security Test: Role check (Setter cannot approve papers)
    setter_approval = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=setter_headers,
        json={"comment": "Setter attempting approval"},
    )
    assert setter_approval.status_code == 403
    assert "permission denied" in setter_approval.json()["detail"].lower()

    # 4b. Security Test: Separation of Duties Violation (HOD who authored a paper is strictly forbidden from self-approving)
    hod_authored = await client.post(
        "/api/v1/vault/papers/ingest",
        headers=hod_headers,
        data={
            "paper_code": "CS-HOD-AUTHORED",
            "title": "HOD Authored Exam",
            "department": "Computer Science",
            "scheduled_release_start": t_start,
            "scheduled_release_end": t_end,
        },
        files={"file": ("exam.pdf", paper_payload, "application/pdf")},
    )
    hod_paper_id = hod_authored.json()["id"]

    self_approval = await client.post(
        f"/api/v1/vault/papers/{hod_paper_id}/approve",
        headers=hod_headers,
        json={"comment": "HOD attempting self-approval on own authored paper"},
    )
    assert self_approval.status_code == 403
    assert "author is prohibited from approving" in self_approval.json()["detail"].lower()

    # 5. Approver 1 (HOD) votes
    appr1_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=hod_headers,
        json={"comment": "HOD review verified syllabus alignment."},
    )
    assert appr1_res.status_code == 200
    appr1_data = appr1_res.json()
    assert appr1_data["current_approvals_count"] == 1
    # Still pending_approvals because threshold is 2
    assert appr1_data["status"] == VaultStatus.pending_approvals.value

    # Security Test: Duplicate Approval by same reviewer forbidden!
    dup_approval = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=hod_headers,
        json={"comment": "Duplicate attempt"},
    )
    assert dup_approval.status_code == 400
    assert "duplicate approval rejected" in dup_approval.json()["detail"].lower()

    # 6. Approver 2 (Controller of Examinations) votes -> Quorum reached!
    appr2_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=coe_headers,
        json={"comment": "Controller formal endorsement."},
    )
    assert appr2_res.status_code == 200
    appr2_data = appr2_res.json()
    assert appr2_data["current_approvals_count"] == 2
    assert appr2_data["status"] == VaultStatus.approved_locked.value

    # 7. Controlled Release Service: Authorized Printer downloads paper
    release_res = await client.post(f"/api/v1/vault/papers/{paper_id}/release", headers=printer_headers)
    assert release_res.status_code == 200
    assert release_res.headers["content-type"] == "application/pdf"
    assert release_res.headers["cache-control"] == "no-store, no-cache, must-revalidate, private"
    assert release_res.headers["pragma"] == "no-cache"
    assert release_res.content.startswith(b"%PDF")

    # 8. Security Test: Early Release Attempt with Future Time Window
    future_start = (now + timedelta(hours=2)).isoformat()
    future_end = (now + timedelta(hours=3)).isoformat()

    future_ingest = await client.post(
        "/api/v1/vault/papers/ingest",
        headers=setter_headers,
        data={
            "paper_code": "CS-FUTURE-2026",
            "title": "Tomorrow Examination",
            "department": "Computer Science",
            "approval_threshold": "1",
            "scheduled_release_start": future_start,
            "scheduled_release_end": future_end,
        },
        files={"file": ("future.pdf", paper_payload, "application/pdf")},
    )
    future_paper_id = future_ingest.json()["id"]

    # Approve future paper
    future_appr = await client.post(
        f"/api/v1/vault/papers/{future_paper_id}/approve",
        headers=hod_headers,
        json={"comment": "Approved future paper"},
    )
    assert future_appr.status_code == 200

    # Attempt release before start window -> MUST FAIL with 425 Too Early
    early_attempt = await client.post(f"/api/v1/vault/papers/{future_paper_id}/release", headers=printer_headers)
    assert early_attempt.status_code == 425
    assert "early access forbidden" in early_attempt.json()["detail"].lower()

    # 9. Security Test: IDOR Protection (Cross-Department Access Rejected)
    await client.post(
        "/api/v1/auth/register",
        json={"email": "printer_civil@examos.edu", "username": "printer_civil", "password": "ValidPassword123!", "full_name": "Civil Printer", "department": "Civil Engineering", "role": "printer"},
    )
    civil_login = await client.post("/api/v1/auth/login", json={"username_or_email": "printer_civil", "password": "ValidPassword123!"})
    civil_headers = {"Authorization": f"Bearer {civil_login.json()['access_token']}"}

    idor_res = await client.post(f"/api/v1/vault/papers/{paper_id}/release", headers=civil_headers)
    assert idor_res.status_code == 403
    assert "cross-department" in idor_res.json()["detail"].lower()

    # 10. Security Test: Inactive / Revoked Account Rejected
    # Suspend printer account
    printer_user = (await db_session.execute(
        select(User).where(User.username == "vault_printer")
    )).scalar_one()
    printer_user.is_active = False
    await db_session.commit()

    revoked_res = await client.post(f"/api/v1/vault/papers/{paper_id}/release", headers=printer_headers)
    assert revoked_res.status_code == 403
    assert "inactive" in revoked_res.json()["detail"].lower()

    # Re-activate printer for subsequent checks
    printer_user.is_active = True
    await db_session.commit()

    # 11. Security Test: Emergency Lock
    lock_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/emergency-lock",
        headers=coe_headers,
        json={"reason": "Security directive: Paper compromised in field transit."},
    )
    assert lock_res.status_code == 200
    assert lock_res.json()["status"] == VaultStatus.emergency_locked.value

    # Subsequent release attempt must be rejected with 423 Locked
    post_lock_attempt = await client.post(f"/api/v1/vault/papers/{paper_id}/release", headers=printer_headers)
    assert post_lock_attempt.status_code == 423

    # 12. Security Test: Tamper-Evident Audit Chain Integrity Verification
    audit_verify_res = await client.get("/api/v1/vault/audit/verify", headers=coe_headers)
    assert audit_verify_res.status_code == 200
    audit_data = audit_verify_res.json()
    assert audit_data["is_valid"] is True
    assert audit_data["total_entries_verified"] > 5
    assert len(audit_data["issues"]) == 0


@pytest.mark.asyncio
async def test_tamper_evident_audit_log_break_detection(db_session: AsyncSession):
    from app.models.user import UserRole
    from app.vault.tamper_evident_audit import record_vault_audit

    # 1. Create user
    user = User(
        email="auditor@examos.edu",
        username="auditor_test",
        full_name="Auditor",
        hashed_password="hashed_placeholder",
        department="Computer Science",
        role=UserRole.admin,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # 2. Record two audit entries
    e1 = await record_vault_audit(db_session, user.id, user.email, "ACTION_ONE", vault_paper_id=1, paper_version=1)
    e2 = await record_vault_audit(db_session, user.id, user.email, "ACTION_TWO", vault_paper_id=1, paper_version=1)
    await db_session.commit()

    # Integrity check should be valid initially
    is_valid, issues = await verify_audit_chain_integrity(db_session)
    assert is_valid is True
    assert len(issues) == 0

    # 3. Tamper with e1 (alter actor_email)
    e1.actor_email = "tampered_adversary@evil.org"
    await db_session.commit()

    # Integrity check must detect break in cryptographic hash chain!
    is_valid, issues = await verify_audit_chain_integrity(db_session)
    assert is_valid is False
    assert any("Audit record tampering detected" in issue for issue in issues)
