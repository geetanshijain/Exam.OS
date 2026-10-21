from datetime import datetime, timedelta, timezone

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity
from app.models.assembly import AssembledPaper, AssembledPaperStatus
from app.models.audit_log import AuditLog
from app.models.center import ExamCenter
from app.models.incident import IncidentSeverity, IncidentStatus, SecurityIncident
from app.models.subject import Subject
from app.models.user import User, UserRole
from app.models.vault import VaultPaper, VaultStatus


@pytest.mark.asyncio
async def test_admin_console_rbac_audit_and_incident_lifecycle(
    client: AsyncClient, db_session: AsyncSession
):
    """
    Comprehensive test suite testing:
    1. Permission matrix enforcement: unauthorized roles blocked with HTTP 403.
    2. User, role, subject, and center management by authorized administrator.
    3. Consolidated pending approval queues across Vault and Assembly.
    4. Multi-dimensional searchable audit trail with restricted export and credential redaction.
    5. Automated anomaly detection scanning (unusual logins, permission spikes, honeytokens).
    6. Incident response workflow: creation, notes, evidence, authorized closure.
    7. Real system telemetry and operational health console (non-fabricated).
    """
    now = datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # 0. SETUP: Actors (Admin, Controller, Ordinary Student, Setter)
    # -------------------------------------------------------------------------
    # Administrator
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "super_admin@examos.edu",
            "username": "super_admin",
            "password": "ValidPassword123!",
            "full_name": "Chief Security Admin",
            "department": "IT Security",
            "role": "admin",
        },
    )
    admin_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "super_admin", "password": "ValidPassword123!"},
    )
    admin_token = admin_login.json()["access_token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Controller of Examinations
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "coe_officer@examos.edu",
            "username": "coe_officer",
            "password": "ValidPassword123!",
            "full_name": "Controller Officer",
            "department": "Examination Division",
            "role": "controller",
        },
    )
    coe_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "coe_officer", "password": "ValidPassword123!"},
    )
    coe_token = coe_login.json()["access_token"]
    coe_headers = {"Authorization": f"Bearer {coe_token}"}

    # Ordinary Student (Unprivileged)
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "student_user@examos.edu",
            "username": "student_user",
            "password": "ValidPassword123!",
            "full_name": "Ordinary Student",
            "department": "Computer Science",
            "role": "student",
        },
    )
    student_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "student_user", "password": "ValidPassword123!"},
    )
    student_token = student_login.json()["access_token"]
    student_headers = {"Authorization": f"Bearer {student_token}"}

    # Exam Setter (Faculty)
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "setter_faculty@examos.edu",
            "username": "setter_faculty",
            "password": "ValidPassword123!",
            "full_name": "Faculty Setter",
            "department": "Computer Science",
            "role": "setter",
        },
    )
    setter_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "setter_faculty", "password": "ValidPassword123!"},
    )
    setter_token = setter_login.json()["access_token"]
    setter_headers = {"Authorization": f"Bearer {setter_token}"}

    # -------------------------------------------------------------------------
    # 1. PERMISSION MATRIX ENFORCEMENT ON ADMINISTRATIVE CONSOLE
    # -------------------------------------------------------------------------
    # Ordinary student attempts to access admin endpoints -> Must be 403 Forbidden
    student_users_res = await client.get("/api/v1/admin/users", headers=student_headers)
    assert student_users_res.status_code == 403

    student_audits_res = await client.get("/api/v1/admin/audit-logs", headers=student_headers)
    assert student_audits_res.status_code == 403

    student_health_res = await client.get("/api/v1/admin/health-console", headers=student_headers)
    assert student_health_res.status_code == 403

    student_incidents_res = await client.get("/api/v1/admin/incidents", headers=student_headers)
    assert student_incidents_res.status_code == 403

    # Faculty setter attempts to manage users -> Must be 403 Forbidden
    setter_users_res = await client.get("/api/v1/admin/users", headers=setter_headers)
    assert setter_users_res.status_code == 403

    # -------------------------------------------------------------------------
    # 2. USER & ROLE MANAGEMENT (AUTHORIZED ADMIN)
    # -------------------------------------------------------------------------
    # Admin creates new user
    new_user_res = await client.post(
        "/api/v1/admin/users",
        headers=admin_headers,
        json={
            "email": "new_faculty@examos.edu",
            "username": "new_faculty",
            "password": "ValidPassword123!",
            "full_name": "New Professor",
            "department": "Electrical Engineering",
            "role": "setter",
            "is_active": True,
        },
    )
    assert new_user_res.status_code == 201
    created_user_id = new_user_res.json()["id"]

    # Admin updates user (modifies department and locks/unlocks)
    update_res = await client.patch(
        f"/api/v1/admin/users/{created_user_id}",
        headers=admin_headers,
        json={"department": "Electronics & Communication", "unlock_account": True},
    )
    assert update_res.status_code == 200
    assert update_res.json()["department"] == "Electronics & Communication"

    # Query role-permissions matrix
    matrix_res = await client.get("/api/v1/admin/roles/permissions", headers=admin_headers)
    assert matrix_res.status_code == 200
    matrix_data = matrix_res.json()
    assert any(m["role"] == "admin" and "manage_users" in m["permissions"] for m in matrix_data)
    assert any(m["role"] == "student" and "attempt_exam" in m["permissions"] for m in matrix_data)

    # -------------------------------------------------------------------------
    # 3. SUBJECT & EXAMINATION CENTER MANAGEMENT
    # -------------------------------------------------------------------------
    # Admin creates Subject
    subj_res = await client.post(
        "/api/v1/admin/subjects",
        headers=admin_headers,
        json={
            "code": "CS-401",
            "name": "Distributed Systems",
            "department": "Computer Science",
            "credits": 4,
            "syllabus_version": "2026-v1",
        },
    )
    assert subj_res.status_code == 201
    assert subj_res.json()["code"] == "CS-401"

    # Admin creates Center
    center_res = await client.post(
        "/api/v1/admin/centers",
        headers=admin_headers,
        json={
            "center_code": "CTR-WEST-01",
            "name": "West Campus Computing Lab",
            "city": "Metro City",
            "capacity": 250,
            "department": "Computer Science",
        },
    )
    assert center_res.status_code == 201
    assert center_res.json()["center_code"] == "CTR-WEST-01"

    # -------------------------------------------------------------------------
    # 4. CONSOLIDATED APPROVAL QUEUES & PENDING ACTIONS
    # -------------------------------------------------------------------------
    # Seed a Vault Paper in pending_approvals status
    v_paper = VaultPaper(
        paper_code="PEND-VAULT-001",
        title="Pending Quorum Cryptography Paper",
        department="Computer Science",
        version=1,
        status=VaultStatus.pending_approvals,
        ciphertext_filename="test.enc",
        wrapped_dek="wrapped-dek",
        nonce_b64="nonce",
        tag_b64="tag",
        aad_json="{}",
        payload_sha256="abcd",
        approval_threshold=2,
        current_approvals_count=0,
        scheduled_release_start=now,
        scheduled_release_end=now + timedelta(hours=3),
        created_by=1,
    )
    db_session.add(v_paper)

    # Seed an Assembled Paper in review_pending status
    asm_paper = AssembledPaper(
        paper_code="PEND-ASM-002",
        title="Pending Review Operating Systems",
        subject="Operating Systems",
        course="B.Tech",
        semester=6,
        department="Computer Science",
        total_marks=100,
        duration_minutes=180,
        blueprint_json="{}",
        sections_json="[]",
        version=1,
        status=AssembledPaperStatus.review_pending,
        created_by=1,
        last_edited_by=1,
    )
    db_session.add(asm_paper)
    await db_session.commit()

    # Controller lists pending action queues
    pending_res = await client.get("/api/v1/admin/pending-actions", headers=coe_headers)
    assert pending_res.status_code == 200
    p_data = pending_res.json()
    assert p_data["total_pending"] >= 2
    assert p_data["vault_quorum_pending"] >= 1
    assert p_data["assembled_papers_pending"] >= 1

    # -------------------------------------------------------------------------
    # 5. MULTI-DIMENSIONAL AUDIT LOG SEARCH & RESTRICTED EXPORT
    # -------------------------------------------------------------------------
    # Search audit logs with action and outcome filter
    audit_search_res = await client.get(
        "/api/v1/admin/audit-logs?outcome=SUCCESS&page=1&page_size=10",
        headers=admin_headers,
    )
    assert audit_search_res.status_code == 200
    search_data = audit_search_res.json()
    assert search_data["total_matches"] >= 1
    assert search_data["storage_type"] == "append_only_authenticated_db"

    # Verify audit logs do NOT contain plaintext passwords or secrets
    for log_item in search_data["items"]:
        meta_str = str(log_item.get("metadata_json") or "")
        assert "ValidPassword123!" not in meta_str
        assert "argon2" not in meta_str

    # Restricted CSV export
    export_res = await client.get("/api/v1/admin/audit-logs/export?limit=50", headers=coe_headers)
    assert export_res.status_code == 200
    assert "text/csv" in export_res.headers["content-type"]
    assert "timestamp_utc,actor_id,action" in export_res.text

    # -------------------------------------------------------------------------
    # 6. AUTOMATED ANOMALY DETECTION SCANNING & ALERT RESOLUTION
    # -------------------------------------------------------------------------
    # Seed a suspicious honeytoken trip audit event
    honeytoken_audit = AuditLog(
        actor_id=1,
        action="HONEYTOKEN_TRIP",
        entity_type="QuestionPaper",
        entity_id=999,
        outcome="FAILURE",
        correlation_id="suspicious-correlation-001",
        ip_address="198.51.100.42",
        metadata_json='{"ip": "198.51.100.42", "path": "/papers/honeytoken-decoy"}',
        timestamp=now - timedelta(minutes=5),
    )
    db_session.add(honeytoken_audit)
    await db_session.commit()

    # Trigger anomaly detection scan
    scan_res = await client.post("/api/v1/admin/alerts/scan-anomalies", headers=coe_headers)
    assert scan_res.status_code == 200
    anomalies = scan_res.json()
    assert len(anomalies) >= 1
    assert any("Security Violation" in a["message"] for a in anomalies)
    flagged_alert_id = anomalies[0]["id"]

    # Controller resolves the alert with documented investigation notes
    resolve_res = await client.patch(
        f"/api/v1/admin/alerts/{flagged_alert_id}/resolve",
        headers=coe_headers,
        json={"resolution_notes": "Investigated IP 198.51.100.42; identified as external automated scanner, blocked at edge WAF."},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["resolved"] is True

    # -------------------------------------------------------------------------
    # 7. INCIDENT RECORD, NOTES, EVIDENCE, AND AUTHORIZED CLOSURE
    # -------------------------------------------------------------------------
    # Open formal security incident
    inc_create_res = await client.post(
        "/api/v1/admin/incidents",
        headers=coe_headers,
        json={
            "title": "Unauthorized Decoy Honeytoken Access Attempt",
            "severity": "critical",
            "category": "unauthorized_access",
            "description": "An out-of-bounds honeytoken access was tripped by external IP 198.51.100.42 targeting draft question storage.",
            "related_paper_code": "PEND-VAULT-001",
        },
    )
    assert inc_create_res.status_code == 201
    inc_data = inc_create_res.json()
    inc_id = inc_data["id"]
    assert "INC-" in inc_data["incident_code"]
    assert inc_data["status"] == "open"

    # Add immutable investigation note
    note_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/notes",
        headers=coe_headers,
        json={"note": "Examined edge gateway logs. Traffic originated from residential proxy node; access to real vault paper prevented."},
    )
    assert note_res.status_code == 200
    assert len(note_res.json()["investigation_notes"]) == 1

    # Attach evidentiary reference
    evidence_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/evidence",
        headers=coe_headers,
        json={
            "evidence_type": "audit_log",
            "reference_id": "suspicious-correlation-001",
            "description": "AuditLog row #honeytoken_audit with correlation id tracking decoy request.",
        },
    )
    assert evidence_res.status_code == 200
    assert len(evidence_res.json()["evidence_references"]) == 1

    # Execute authorized incident closure
    close_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/close",
        headers=admin_headers,
        json={
            "root_cause": "External recon probe attempting default API paths; caught by honeypot router.",
            "remediation_steps": "IP permanently banned at perimeter reverse-proxy, rate limits reduced to 5 req/min.",
            "closure_approval_notes": "Reviewed and approved by Chief Security Admin and CoE. Incident contained and closed.",
        },
    )
    assert close_res.status_code == 200
    closed_data = close_res.json()
    assert closed_data["status"] == "closed"
    assert closed_data["closed_at"] is not None
    assert closed_data["closed_by_id"] is not None

    # -------------------------------------------------------------------------
    # 8. REAL SYSTEM HEALTH & OPERATIONAL TELEMETRY CONSOLE
    # -------------------------------------------------------------------------
    health_res = await client.get("/api/v1/admin/health-console", headers=admin_headers)
    assert health_res.status_code == 200
    health_data = health_res.json()
    assert health_data["status"] in ["HEALTHY", "DEGRADED"]
    assert health_data["is_synthetic_telemetry"] is False  # Non-fabricated!
    assert health_data["telemetry_type"] == "REAL_OPERATIONAL_MEASUREMENT"
    assert health_data["database"]["roundtrip_latency_ms"] >= 0.0
    assert health_data["storage"]["total_bytes"] > 0
    assert health_data["storage"]["free_bytes"] > 0
    assert health_data["server_clock_synchronized"] is True
    assert health_data["integrations"]["kms_status"] == "HEALTHY"
    assert health_data["integrations"]["audit_chain_integrity"] is True
