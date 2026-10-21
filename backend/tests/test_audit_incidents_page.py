import json
import os
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.alert import Alert, AlertSeverity
from app.models.audit_log import AuditLog
from app.models.incident import IncidentSeverity, IncidentStatus, SecurityIncident
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_audit_incidents_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts supporting Audit Logs and Incident Response:
    1. Clearance Guard: Student/unauthorized users blocked with HTTP 403 Forbidden.
    2. Audit Ledger Querying: GET /api/v1/admin/audit-logs returns real records with search/filters.
    3. Audit Ledger CSV Export: GET /api/v1/admin/audit-logs/export produces downloadable CSV and logs export.
    4. Threat Alerts: GET /api/v1/admin/alerts lists alerts, PATCH resolves with mandatory notes.
    5. Anomaly Scanning: POST /api/v1/admin/alerts/scan-anomalies runs automated heuristic scan.
    6. Incident Lifecycle:
       - POST /api/v1/admin/incidents opens a new case
       - POST /api/v1/admin/incidents/{id}/notes adds immutable note
       - POST /api/v1/admin/incidents/{id}/evidence adds evidentiary reference
       - POST /api/v1/admin/incidents/{id}/close executes authorized closure
    """
    # 1. Setup Admin and Student Users
    admin_user = User(
        email="chief_security_officer@examos.edu",
        username="chief_security_officer",
        full_name="Chief Eleanor Security",
        department="IT Security",
        role=UserRole.admin,
        hashed_password=hash_password("SuperSecret123!"),
        is_active=True,
    )
    student_user = User(
        email="unauth_student@examos.edu",
        username="unauth_student",
        full_name="Unauthorized Student",
        department="Computer Science",
        role=UserRole.student,
        hashed_password=hash_password("SuperSecret123!"),
        is_active=True,
    )
    db_session.add_all([admin_user, student_user])
    await db_session.commit()
    await db_session.refresh(admin_user)
    await db_session.refresh(student_user)

    admin_token, _, _ = create_access_token(
        subject=admin_user.id,
        role=admin_user.role.value,
        department=admin_user.department,
        mfa_verified=True,
    )
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    student_token, _, _ = create_access_token(
        subject=student_user.id,
        role=student_user.role.value,
        department=student_user.department,
        mfa_verified=False,
    )
    student_headers = {"Authorization": f"Bearer {student_token}"}

    # 2. Assert Non-Privileged Access Blocked with HTTP 403
    forbidden_audit = await client.get("/api/v1/admin/audit-logs", headers=student_headers)
    assert forbidden_audit.status_code == 403
    assert "Permission denied" in forbidden_audit.text or "not have permission" in forbidden_audit.text

    forbidden_alerts = await client.get("/api/v1/admin/alerts", headers=student_headers)
    assert forbidden_alerts.status_code == 403

    forbidden_incidents = await client.get("/api/v1/admin/incidents", headers=student_headers)
    assert forbidden_incidents.status_code == 403

    # 3. Seed Realistic Audit Event and Verify Query Contract
    test_audit = AuditLog(
        actor_id=admin_user.id,
        action="TEST_VAULT_DECRYPTION_ATTEMPT",
        entity_type="VaultPaper",
        entity_id=999,
        outcome="SUCCESS",
        correlation_id="corr-test-12345",
        ip_address="192.168.1.100",
        metadata_json=json.dumps({"test_key": "test_val", "classification": "RESTRICTED"}),
    )
    db_session.add(test_audit)
    await db_session.commit()

    # Query audit logs
    audit_res = await client.get("/api/v1/admin/audit-logs?page=1&page_size=10", headers=admin_headers)
    assert audit_res.status_code == 200
    audit_data = audit_res.json()
    assert "items" in audit_data
    assert audit_data["total_matches"] >= 1
    assert any(item["action"] == "TEST_VAULT_DECRYPTION_ATTEMPT" for item in audit_data["items"])

    # Test audit search filter
    filter_res = await client.get(
        "/api/v1/admin/audit-logs?action=TEST_VAULT_DECRYPTION_ATTEMPT&outcome=SUCCESS",
        headers=admin_headers,
    )
    assert filter_res.status_code == 200
    filtered_items = filter_res.json()["items"]
    assert len(filtered_items) >= 1
    assert filtered_items[0]["outcome"] == "SUCCESS"

    # 4. Assert Audit Logs CSV Export
    csv_res = await client.get("/api/v1/admin/audit-logs/export?limit=50", headers=admin_headers)
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers.get("content-type", "")
    assert "id,timestamp_utc,actor_id,action" in csv_res.text
    assert "TEST_VAULT_DECRYPTION_ATTEMPT" in csv_res.text

    # 5. Threat Alert Listing & Resolution
    test_alert = Alert(
        severity=AlertSeverity.high,
        message="Test alert: Honeytoken trip detected on vault artifact",
        actor_id=student_user.id,
        resolved=False,
    )
    db_session.add(test_alert)
    await db_session.commit()
    await db_session.refresh(test_alert)

    alerts_res = await client.get("/api/v1/admin/alerts?resolved=false", headers=admin_headers)
    assert alerts_res.status_code == 200
    alerts_list = alerts_res.json()
    assert any(a["id"] == test_alert.id for a in alerts_list)

    # Resolve Alert
    resolve_payload = {
        "resolution_notes": "Forensic triage completed: Honeytoken accessed from non-whitelisted VLAN."
    }
    resolve_res = await client.patch(
        f"/api/v1/admin/alerts/{test_alert.id}/resolve",
        headers=admin_headers,
        json=resolve_payload,
    )
    assert resolve_res.status_code == 200
    resolved_alert = resolve_res.json()
    assert resolved_alert["resolved"] is True
    assert resolved_alert["resolution_notes"] == resolve_payload["resolution_notes"]

    # 6. Automated Anomaly Detection Scan
    scan_res = await client.post("/api/v1/admin/alerts/scan-anomalies", headers=admin_headers)
    assert scan_res.status_code == 200
    assert isinstance(scan_res.json(), list)

    # 7. Incident Lifecycle
    # A. Open Incident
    new_inc_payload = {
        "title": "Unauthorized Hardware Token Emulation",
        "severity": "high",
        "category": "Perimeter Breach",
        "description": "Detected rogue cryptographic token negotiating key exchange.",
        "related_paper_code": "CS-401",
    }
    create_inc_res = await client.post(
        "/api/v1/admin/incidents",
        headers=admin_headers,
        json=new_inc_payload,
    )
    assert create_inc_res.status_code == 201
    created_inc = create_inc_res.json()
    inc_id = created_inc["id"]
    assert created_inc["incident_code"].startswith("INC-")
    assert created_inc["status"] == "open"

    # B. Add Note
    note_payload = {
        "note": "Perimeter switch port isolated; MAC address isolated from gateway router."
    }
    note_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/notes",
        headers=admin_headers,
        json=note_payload,
    )
    assert note_res.status_code == 200
    note_data = note_res.json()
    assert len(note_data["investigation_notes"]) >= 1
    assert note_data["status"] == "investigating"

    # C. Attach Evidence
    evidence_payload = {
        "evidence_type": "IP_CAPTURE",
        "reference_id": "192.168.10.45",
        "description": "Rogue NIC hardware address captured on port 14 mirror.",
    }
    ev_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/evidence",
        headers=admin_headers,
        json=evidence_payload,
    )
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert len(ev_data["evidence_references"]) >= 1
    assert ev_data["evidence_references"][-1]["reference_id"] == "192.168.10.45"

    # D. Authorized Closure
    close_payload = {
        "root_cause": "Rogue development test bench left plugged into secure vlan.",
        "remediation_steps": "Port shut down, 802.1X certificate enforcement enabled across switch stack.",
        "closure_approval_notes": "Authorized and confirmed by Chief Eleanor Security.",
    }
    close_res = await client.post(
        f"/api/v1/admin/incidents/{inc_id}/close",
        headers=admin_headers,
        json=close_payload,
    )
    assert close_res.status_code == 200
    closed_data = close_res.json()
    assert closed_data["status"] == "closed"
    assert closed_data["root_cause"] == close_payload["root_cause"]
    assert closed_data["closed_at"] is not None


def test_audit_incidents_html_and_reference_fidelity():
    """
    Verifies that frontend/audit-incidents.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference mockup.
    """
    html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend", "audit-incidents.html")
    assert os.path.exists(html_path), "audit-incidents.html must exist in frontend/"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Document Structure & Meta
    assert "<!DOCTYPE html>" in html
    assert "Audit Logs and Incident Response Console — ExamOS" in html
    assert 'rel="stylesheet" href="css/design-system.css"' in html
    assert 'class="skip-to-main"' in html

    # 2. Header & Institutional Breadcrumb
    assert 'class="audit-header"' in html
    assert "Security Governance" in html
    assert "Audit Trails &amp; Incident Response" in html or "Audit Trails & Incident Response" in html
    assert 'id="audit-session-pill"' in html
    assert 'id="btn-signout"' in html

    # 3. 4-Card KPI Strip matching approved mockup
    assert 'class="admin-kpi-grid"' in html
    assert "Total Audit Events" in html
    assert 'id="kpi-total-audits"' in html
    assert "Active Threat Alerts" in html
    assert 'id="kpi-alerts-count"' in html
    assert "Open Security Incidents" in html
    assert 'id="kpi-incidents-count"' in html
    assert "Tamper-Evident Ledger" in html
    assert 'id="kpi-ledger-health"' in html

    # 4. Tab Navigation
    assert 'class="audit-tabs-nav"' in html
    assert 'id="tab-btn-ledger"' in html
    assert 'id="tab-btn-incidents"' in html

    # 5. Tab 1: Master Audit Table & Sentry Drawer
    assert 'id="audit-table-heading"' in html
    assert "Immutable System Audit Trail" in html
    assert 'id="search-audit-input"' in html
    assert 'id="filter-audit-action"' in html
    assert 'id="filter-audit-outcome"' in html
    assert 'id="btn-refresh-audits"' in html
    assert 'id="btn-export-audit-csv"' in html
    assert 'id="audit-table-body"' in html
    assert 'id="btn-audit-prev"' in html
    assert 'id="btn-audit-next"' in html
    assert 'class="sentry-drawer-card"' in html
    assert 'id="sentry-drawer-content"' in html

    # 6. Tab 2: Security Threat Alerts & Incidents Register
    assert 'id="btn-scan-anomalies"' in html
    assert 'id="btn-simulate-drill"' in html
    assert 'id="btn-open-new-incident-modal"' in html
    assert 'id="alerts-table-body"' in html
    assert 'id="incidents-table-body"' in html

    # 7. Six Accessible Modals
    assert 'id="modal-open-incident"' in html
    assert 'id="form-open-incident"' in html
    assert 'id="modal-add-note"' in html
    assert 'id="form-add-note"' in html
    assert 'id="modal-add-evidence"' in html
    assert 'id="form-add-evidence"' in html
    assert 'id="modal-close-incident"' in html
    assert 'id="form-close-incident"' in html
    assert 'id="modal-resolve-alert"' in html
    assert 'id="form-resolve-alert"' in html
    assert 'id="modal-audit-detail"' in html
    assert 'id="detail-json-code"' in html

    # 8. Six Core System States
    assert 'id="state-loading"' in html
    assert 'id="state-permission-denied"' in html
    assert 'id="state-server-error"' in html
    assert 'id="main-audit-console"' in html
    assert 'id="audit-alert"' in html

    # 9. Script Link
    assert 'src="js/audit-incidents.js"' in html
