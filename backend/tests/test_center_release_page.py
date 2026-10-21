import os
import json
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole
from app.models.vault import VaultPaper, VaultStatus
from app.vault.crypto import encrypt_paper_envelope
from app.vault.kms import kms_client
from app.vault.tamper_evident_audit import record_vault_audit


@pytest.mark.asyncio
async def test_center_release_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts for the Examination-Center Release Console:
    1. Authorized printer role (Custodial Printing Officer) access.
    2. Listing vault papers for center extraction.
    3. Time-locked paper extraction rejection (HTTP 425 Too Early) prior to window start.
    4. Successful paper release within extraction window returning watermarked PDF stream.
    5. Emergency lockdown directive transition and access revocation.
    6. Tamper-evident cryptographic audit ledger verification.
    """
    now = datetime.now(timezone.utc)

    # 1. Setup Printing Officer and Controller
    printer = User(
        email="test_custodian@examos.edu",
        username="custodian_pat",
        full_name="Pat Printer",
        department="Computer Science",
        role=UserRole.printer,
        hashed_password=hash_password("password123"),
        is_active=True,
    )
    controller = User(
        email="test_coe_rel@examos.edu",
        username="coe_pat",
        full_name="Sam Controller",
        department="Computer Science",
        role=UserRole.controller,
        hashed_password=hash_password("password123"),
        is_active=True,
    )
    db_session.add_all([printer, controller])
    await db_session.commit()
    await db_session.refresh(printer)
    await db_session.refresh(controller)

    printer_token, _, _ = create_access_token(
        subject=printer.id,
        role=printer.role.value,
        department=printer.department,
        mfa_verified=False,
    )
    printer_headers = {"Authorization": f"Bearer {printer_token}"}

    controller_token, _, _ = create_access_token(
        subject=controller.id,
        role=controller.role.value,
        department=controller.department,
        mfa_verified=True,
    )
    controller_headers = {"Authorization": f"Bearer {controller_token}"}

    # 2. Setup Real Encrypted Vault Papers
    vault_storage = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "vault", "encrypted_objects")
    os.makedirs(vault_storage, exist_ok=True)

    dummy_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n180\n%%EOF"
    
    # Paper A: Window Open Now (Start: now - 10m, End: now + 30m)
    meta_open = {"paper_code": "REL-TEST-01", "department": "Computer Science", "version": 1, "title": "Operating Systems"}
    ct_open, env_open = encrypt_paper_envelope(dummy_pdf, meta_open, kms_client)
    file_open = "REL-TEST-01_ct.bin"
    with open(os.path.join(vault_storage, file_open), "wb") as f:
        f.write(ct_open)

    approvals_data = [
        {"approver_id": controller.id, "approver_email": controller.email, "role": "controller", "timestamp": now.isoformat()},
        {"approver_id": controller.id + 10, "approver_email": "hod@examos.edu", "role": "hod", "timestamp": now.isoformat()},
    ]

    paper_open = VaultPaper(
        paper_code="REL-TEST-01",
        title="CS-401 Advanced Operating Systems",
        department="Computer Science",
        version=1,
        status=VaultStatus.approved_locked,
        ciphertext_filename=file_open,
        wrapped_dek=env_open["wrapped_dek"],
        kek_version=env_open["kek_version"],
        nonce_b64=env_open["nonce_b64"],
        tag_b64=env_open["tag_b64"],
        aad_json=env_open["aad_json"],
        payload_sha256=env_open["payload_sha256"],
        approval_threshold=2,
        current_approvals_count=2,
        approvals_json=json.dumps(approvals_data),
        scheduled_release_start=now - timedelta(minutes=10),
        scheduled_release_end=now + timedelta(minutes=30),
        created_by=controller.id,
    )

    # Paper B: Time-Locked (Start: now + 40m, End: now + 90m)
    meta_locked = {"paper_code": "REL-TEST-02", "department": "Computer Science", "version": 1, "title": "Distributed Systems"}
    ct_locked, env_locked = encrypt_paper_envelope(dummy_pdf, meta_locked, kms_client)
    file_locked = "REL-TEST-02_ct.bin"
    with open(os.path.join(vault_storage, file_locked), "wb") as f:
        f.write(ct_locked)

    paper_locked = VaultPaper(
        paper_code="REL-TEST-02",
        title="CS-502 Distributed Systems Final",
        department="Computer Science",
        version=1,
        status=VaultStatus.approved_locked,
        ciphertext_filename=file_locked,
        wrapped_dek=env_locked["wrapped_dek"],
        kek_version=env_locked["kek_version"],
        nonce_b64=env_locked["nonce_b64"],
        tag_b64=env_locked["tag_b64"],
        aad_json=env_locked["aad_json"],
        payload_sha256=env_locked["payload_sha256"],
        approval_threshold=2,
        current_approvals_count=2,
        approvals_json=json.dumps(approvals_data),
        scheduled_release_start=now + timedelta(minutes=40),
        scheduled_release_end=now + timedelta(minutes=90),
        created_by=controller.id,
    )

    db_session.add_all([paper_open, paper_locked])
    await db_session.commit()
    await db_session.refresh(paper_open)
    await db_session.refresh(paper_locked)

    # 3. List Papers via Custodian
    list_res = await client.get("/api/v1/vault/papers", headers=printer_headers)
    assert list_res.status_code == 200
    papers_list = list_res.json()
    assert any(p["paper_code"] == "REL-TEST-01" for p in papers_list)
    assert any(p["paper_code"] == "REL-TEST-02" for p in papers_list)

    # 4. Assert Time-Lock Rejection (HTTP 425 Too Early) on Paper B
    early_res = await client.post(f"/api/v1/vault/papers/{paper_locked.id}/release", headers=printer_headers)
    assert early_res.status_code == 425
    assert "Early access forbidden" in early_res.text

    # 5. Assert Successful Release & Watermarked PDF Stream on Paper A
    release_res = await client.post(f"/api/v1/vault/papers/{paper_open.id}/release", headers=printer_headers)
    assert release_res.status_code == 200
    assert release_res.headers["content-type"] == "application/pdf"
    assert "no-store" in release_res.headers.get("cache-control", "")
    assert release_res.content.startswith(b"%PDF")

    # 6. Assert Emergency Lock Directive Engagement
    lock_payload = {"reason": "Perimeter alarm triggered at Center Hall A1."}
    lock_res = await client.post(
        f"/api/v1/vault/papers/{paper_open.id}/emergency-lock",
        headers=controller_headers,
        json=lock_payload,
    )
    assert lock_res.status_code == 200
    locked_data = lock_res.json()
    assert locked_data["status"] == VaultStatus.emergency_locked.value

    # 7. Post-Lockout Rejection (HTTP 423 Locked)
    post_lock_res = await client.post(f"/api/v1/vault/papers/{paper_open.id}/release", headers=printer_headers)
    assert post_lock_res.status_code == 423
    assert "emergency security directive" in post_lock_res.text

    # 8. Cryptographic Audit Chain Verification
    audit_res = await client.get("/api/v1/vault/audit/verify", headers=printer_headers)
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert audit_data["is_valid"] is True
    assert audit_data["total_entries_verified"] >= 1


def test_center_release_html_and_reference_fidelity():
    """
    Verifies that frontend/center-release.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference design.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    page_path = os.path.join(frontend_dir, "center-release.html")
    js_path = os.path.join(frontend_dir, "js", "center-release.js")
    css_path = os.path.join(frontend_dir, "css", "design-system.css")

    assert os.path.exists(page_path), "frontend/center-release.html must exist"
    assert os.path.exists(js_path), "frontend/js/center-release.js must exist"
    assert os.path.exists(css_path), "frontend/css/design-system.css must exist"

    with open(page_path, "r", encoding="utf-8") as f:
        html = f.read()
    with open(js_path, "r", encoding="utf-8") as f:
        js = f.read()
    with open(css_path, "r", encoding="utf-8") as f:
        css = f.read()

    # 1. Semantic Landmarks & Skip Link
    assert '<header class="center-release-header"' in html
    assert '<main class="dashboard-content-wrap"' in html
    assert 'class="skip-to-main"' in html
    assert 'id="main-content"' in html

    # 2. Header Elements Matching Reference Mockup
    assert 'ExamOS' in html
    assert 'id="center-custodian-pill"' in html
    assert 'Exam Center:' in html
    assert 'id="center-code-display"' in html
    assert 'Custodian:' in html
    assert 'id="custodian-name-display"' in html
    assert 'id="sync-status-pill"' in html
    assert 'UTC Clock Synced | Hardware Audit OK' in html
    assert 'id="btn-emergency-lock-header"' in html
    assert 'Emergency Lock' in html
    assert 'id="btn-verify-audit-header"' in html
    assert 'Verify Audit Chain' in html

    # 3. Top Security KPI Metrics Strip (4 Cards Matching Reference)
    assert 'Station Status' in html
    assert 'id="kpi-station-status"' in html
    assert 'Secure Node' in html
    assert 'Extraction Window' in html
    assert 'id="kpi-window-status"' in html
    assert 'T-30 Min Active' in html
    assert 'Print Queue' in html
    assert 'id="kpi-queue-count"' in html
    assert 'Forensic Stamping' in html
    assert 'id="kpi-stamping-status"' in html
    assert '100% Enforced' in html

    # 4. Examination Release Master Table Pane
    assert 'Examination Release Master Table' in html
    assert 'id="search-papers-input"' in html
    assert 'id="filter-status-select"' in html
    assert 'id="btn-refresh-table"' in html
    assert 'id="release-table-body"' in html
    assert 'Paper Code' in html
    assert 'Scheduled Time' in html
    assert 'Time-Lock Status' in html
    assert 'Quorum Status' in html

    # 5. Extraction & Decryption Inspector Drawer (Right Pane)
    assert 'Extraction &amp; Decryption Inspector' in html
    assert 'Dynamic Watermark Metadata' in html
    assert 'id="inspector-recipient"' in html
    assert 'id="inspector-station-ip"' in html
    assert 'id="inspector-watermark-date"' in html
    assert 'id="inspector-print-window"' in html
    assert 'id="inspector-center-code"' in html
    assert 'id="inspector-kms-version"' in html
    assert 'id="inspector-print-count"' in html
    assert 'Honeytoken Security Notice' in html
    assert 'id="btn-inspector-trigger-release"' in html
    assert 'Trigger Secure Release' in html

    # 6. Operational System States
    assert 'id="state-loading"' in html
    assert 'id="state-empty"' in html
    assert 'id="state-permission-denied"' in html
    assert 'id="main-console-grid"' in html
    assert 'id="release-alert"' in html

    # 7. Modals
    assert 'id="modal-audit-verification"' in html
    assert 'id="modal-emergency-lock"' in html
    assert 'id="audit-entries-body"' in html
    assert 'id="form-emergency-lock"' in html

    # 8. CSS Classes & Responsive Layout
    assert '.center-release-header' in css
    assert '.release-kpi-grid' in css
    assert '.release-layout-grid' in css
    assert '.table-release' in css
    assert '.badge-timelock-open' in css
    assert '.badge-timelock-locked' in css
    assert '.btn-decrypt-print' in css
    assert '.btn-audit-chain' in css
    assert '.inspector-panel' in css

    # 9. Vanilla JS Engine Integrations
    assert 'vault/papers/${paperId}/release' in js
    assert 'vault/papers/${paperId}/emergency-lock' in js
    assert 'vault/audit/verify' in js
    assert 'startLiveCountdownLoop' in js
    assert 'updateInspectorDrawer' in js
