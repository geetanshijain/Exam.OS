import io
import os
import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from app.models.vault import VaultPaper, VaultStatus


@pytest.mark.asyncio
async def test_secure_vault_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Secure Vault & Paper Status page:
    1. Envelope ingestion with AES-256-GCM and KEK wrapping.
    2. Listing vault inventory scoped to department / controller clearance.
    3. Separation of duties: Creator cannot approve their own paper (HTTP 403).
    4. Second authorized officer can contribute to multi-party quorum.
    5. Time-lock window protection: Premature release attempt triggers HTTP 425.
    6. Emergency lock directive: Suspends paper (HTTP 423 on release).
    7. Cryptographic tamper-evident audit chain verification.
    """
    # 1. Create Setter (Creator)
    setter = User(
        email="vault_setter_p@examos.edu",
        username="vault_setter_p",
        full_name="Prof. Alex Setter",
        department="Computer Science",
        role=UserRole.setter,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 2. Create HOD (Approver 1)
    hod = User(
        email="vault_hod_p@examos.edu",
        username="vault_hod_p",
        full_name="Dr. Marcus Vance",
        department="Computer Science",
        role=UserRole.hod,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 3. Create Controller (Approver 2 & Security Admin)
    coe = User(
        email="vault_coe_p@examos.edu",
        username="vault_coe_p",
        full_name="Dr. Eleanor Vance",
        department="Computer Science",
        role=UserRole.controller,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    # 4. Create Printer / Proctor (Authorized release consumer)
    printer = User(
        email="vault_printer_p@examos.edu",
        username="vault_printer_p",
        full_name="Exam Center Operator",
        department="Computer Science",
        role=UserRole.printer,
        hashed_password=hash_password("Pass123!"),
        is_active=True,
    )
    db_session.add_all([setter, hod, coe, printer])
    await db_session.commit()
    await db_session.refresh(setter)
    await db_session.refresh(hod)
    await db_session.refresh(coe)
    await db_session.refresh(printer)

    setter_token, _, _ = create_access_token(
        subject=setter.id,
        role=setter.role.value,
        department=setter.department,
        mfa_verified=True,
    )
    setter_headers = {"Authorization": f"Bearer {setter_token}"}

    hod_token, _, _ = create_access_token(
        subject=hod.id,
        role=hod.role.value,
        department=hod.department,
        mfa_verified=True,
    )
    hod_headers = {"Authorization": f"Bearer {hod_token}"}

    coe_token, _, _ = create_access_token(
        subject=coe.id,
        role=coe.role.value,
        department=coe.department,
        mfa_verified=True,
    )
    coe_headers = {"Authorization": f"Bearer {coe_token}"}

    printer_token, _, _ = create_access_token(
        subject=printer.id,
        role=printer.role.value,
        department=printer.department,
        mfa_verified=True,
    )
    printer_headers = {"Authorization": f"Bearer {printer_token}"}

    # 5. Ingest Paper Envelope via Setter
    now = datetime.now(timezone.utc)
    future_start = (now + timedelta(hours=2)).isoformat()
    future_end = (now + timedelta(hours=3)).isoformat()

    file_payload = b"%PDF-1.4 Vault Ingestion Automated Test Content"
    files = {"file": ("vault_test.pdf", io.BytesIO(file_payload), "application/pdf")}
    data = {
        "paper_code": "CS-VAULT-AUTO-01",
        "title": "CS-VAULT-01: Advanced Cryptography",
        "department": "Computer Science",
        "scheduled_release_start": future_start,
        "scheduled_release_end": future_end,
        "approval_threshold": "2",
    }

    ingest_res = await client.post(
        "/api/v1/vault/papers/ingest",
        headers=setter_headers,
        data=data,
        files=files,
    )
    assert ingest_res.status_code == 201, f"Ingestion failed: {ingest_res.text}"
    paper_info = ingest_res.json()
    paper_id = paper_info["id"]
    assert paper_info["paper_code"] == "CS-VAULT-AUTO-01"
    assert paper_info["status"] == VaultStatus.pending_approvals.value
    assert "v" in paper_info["kek_version"]
    assert len(paper_info["payload_sha256"]) == 64

    # 6. List Vault Papers (Setter or HOD with CREATE_QUESTIONS permission)
    list_res = await client.get("/api/v1/vault/papers", headers=setter_headers)
    assert list_res.status_code == 200
    papers_list = list_res.json()
    assert any(p["id"] == paper_id for p in papers_list)

    # 7. Separation of Duties: Setter attempts self-approval -> 403 Forbidden
    self_approve_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=setter_headers,
        json={"comment": "Self-approval attempt by creator"},
    )
    assert self_approve_res.status_code == 403

    # 8. Valid Quorum Sign by HOD (Vote 1 of 2)
    hod_vote_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=hod_headers,
        json={"comment": "HOD review verified syllabus alignment"},
    )
    assert hod_vote_res.status_code == 200
    assert hod_vote_res.json()["current_approvals_count"] == 1
    assert hod_vote_res.json()["status"] == VaultStatus.pending_approvals.value

    # 9. Quorum Sign by Controller (Vote 2 of 2 -> Quorum Reached -> Approved & Locked)
    coe_vote_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/approve",
        headers=coe_headers,
        json={"comment": "Controller final seal confirmed"},
    )
    assert coe_vote_res.status_code == 200
    assert coe_vote_res.json()["current_approvals_count"] == 2
    assert coe_vote_res.json()["status"] == VaultStatus.approved_locked.value

    # 10. Premature Release Attempt (Time-Lock Window Protection)
    # Release window starts in 2 hours -> MUST return HTTP 425 Too Early
    early_release = await client.post(
        f"/api/v1/vault/papers/{paper_id}/release",
        headers=printer_headers,
    )
    assert early_release.status_code == 425
    assert "early access forbidden" in early_release.json()["detail"].lower()

    # 11. Emergency Lock Directive executed by Controller
    emergency_res = await client.post(
        f"/api/v1/vault/papers/{paper_id}/emergency-lock",
        headers=coe_headers,
        json={"reason": "Audit discrepancy detected during pre-flight validation"},
    )
    assert emergency_res.status_code == 200
    assert emergency_res.json()["status"] == VaultStatus.emergency_locked.value

    # 12. Post-Emergency Lock Release Attempt -> MUST return HTTP 423 Locked
    locked_release = await client.post(
        f"/api/v1/vault/papers/{paper_id}/release",
        headers=printer_headers,
    )
    assert locked_release.status_code == 423

    # 13. Audit Chain Verification
    audit_verify_res = await client.get("/api/v1/vault/audit/verify", headers=coe_headers)
    assert audit_verify_res.status_code == 200
    audit_data = audit_verify_res.json()
    assert audit_data["is_valid"] is True
    assert audit_data["total_entries_verified"] > 0
    assert len(audit_data["issues"]) == 0


def test_secure_vault_page_html_and_reference_fidelity():
    """
    Verifies that frontend/secure-vault.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "secure-vault.html")
    assert os.path.exists(page_path), "frontend/secure-vault.html must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Header Landmarks & Navigation
    assert '<header class="site-header"' in html
    assert 'Security Architecture' in html
    assert 'Secure Vault &amp; Paper Status' in html
    assert 'id="vault-headline"' in html
    assert 'AES-256 Envelope Vault &amp; Paper Lifecycle Security' in html

    # 2. Context Action Controls
    assert 'id="btn-emergency-lock-global"' in html
    assert 'Emergency Lock' in html
    assert 'id="btn-verify-audit-chain"' in html
    assert 'Verify Audit Chain' in html
    assert 'id="btn-open-ingest-modal"' in html
    assert '+ Ingest Paper Envelope' in html

    # 3. Top Security KPI Strip (4 Cards Matching Reference Design)
    assert 'id="kpi-active-vault"' in html
    assert '14 Encrypted Blobs' in html
    assert 'id="kpi-timelock-window"' in html
    assert '30 Mins Pre-Exam' in html
    assert 'id="kpi-kms-key"' in html
    assert 'v3 Active, Zero Plaintext' in html
    assert 'id="kpi-audit-integrity"' in html
    assert '100% Verified, 0 Breaks' in html

    # 4. High-Security Examination Inventory Section & Table
    assert 'High-security examination inventory' in html
    assert 'id="vault-search-input"' in html
    assert 'id="vault-table-wrapper"' in html
    assert 'id="vault-table-body"' in html
    assert 'Paper Code' in html
    assert 'Encryption Standard' in html
    assert 'Multi-Party Quorum' in html
    assert 'Time-Lock Release Window' in html
    assert 'SHA-256 payload' in html

    # 5. Cryptographic Tamper-Evident Audit Ledger Stream
    assert 'Cryptographic tamper-evident Audit Ledger stream' in html
    assert 'id="audit-stream-container"' in html
    assert 'SHA-256 Hash Chain Valid' in html

    # 6. Six UI States
    assert 'id="vault-loading-state"' in html
    assert 'id="vault-permission-denied"' in html
    assert 'id="vault-empty-state"' in html
    assert 'id="vault-alert"' in html
    assert 'id="ingest-modal-alert"' in html

    # 7. Accessible Dialogs / Modals
    assert 'id="modal-ingest-vault"' in html
    assert 'id="form-ingest-envelope"' in html
    assert 'id="modal-quorum-sign"' in html
    assert 'id="btn-submit-quorum"' in html
    assert 'id="modal-emergency-dialog"' in html
    assert 'id="btn-confirm-emergency"' in html

    # 8. Institutional Footer Notice
    assert 'Zero Plaintext Logging' in html
    assert 'Cryptographic Separation of Duties Enforced' in html
    assert 'DEV ENVIRONMENT' in html
