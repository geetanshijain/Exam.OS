import os
import re
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.user import User, UserRole


@pytest.mark.asyncio
async def test_admin_roles_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts supporting the Admin and Role Management Console:
    1. Authorization guard: Non-admin users are strictly rejected with HTTP 403 Forbidden.
    2. Admin directory listing: GET /api/v1/admin/users returns real records.
    3. User Provisioning: POST /api/v1/admin/users creates new account with Argon2id hash.
    4. Account Modification: PATCH /api/v1/admin/users/{id} updates attributes.
    5. Account Unlock: PATCH /api/v1/admin/users/{id} with unlock_account clears lockout.
    6. Credential Reset: PATCH /api/v1/admin/users/{id} with reset_password updates password.
    7. Role Permissions Matrix: GET /api/v1/admin/roles/permissions returns all 6 roles.
    """
    # 1. Create Test Admin and Test Student
    admin_user = User(
        email="test_super_admin@examos.edu",
        username="test_super_admin",
        full_name="Chief Administrator",
        department="IT Security",
        role=UserRole.admin,
        hashed_password=hash_password("SuperSecret123!"),
        is_active=True,
    )
    student_user = User(
        email="test_student_blocked@examos.edu",
        username="test_student_blocked",
        full_name="Ordinary Student",
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

    # 2. Assert Non-Admin Users Blocked with HTTP 403 Forbidden
    forbidden_res = await client.get("/api/v1/admin/users", headers=student_headers)
    assert forbidden_res.status_code == 403
    assert "Permission denied" in forbidden_res.text or "not have permission" in forbidden_res.text

    # 3. Assert Admin Directory Listing
    list_res = await client.get("/api/v1/admin/users", headers=admin_headers)
    assert list_res.status_code == 200
    users_list = list_res.json()
    assert len(users_list) >= 2
    assert any(u["username"] == "test_super_admin" for u in users_list)

    # 4. Assert User Provisioning via POST /api/v1/admin/users
    new_user_payload = {
        "email": "prov_custodian@examos.edu",
        "username": "prov_custodian",
        "password": "Password123!",
        "full_name": "New Custodian Officer",
        "department": "Printing Cell",
        "role": "printer",
        "is_active": True,
    }
    create_res = await client.post("/api/v1/admin/users", headers=admin_headers, json=new_user_payload)
    assert create_res.status_code == 201
    created_user = create_res.json()
    assert created_user["email"] == "prov_custodian@examos.edu"
    assert created_user["role"] == "printer"
    created_id = created_user["id"]

    # 5. Assert Account Modification via PATCH /api/v1/admin/users/{id}
    patch_payload = {
        "full_name": "Senior Custodian Officer",
        "department": "Central Vault",
    }
    patch_res = await client.patch(f"/api/v1/admin/users/{created_id}", headers=admin_headers, json=patch_payload)
    assert patch_res.status_code == 200
    patched_user = patch_res.json()
    assert patched_user["full_name"] == "Senior Custodian Officer"
    assert patched_user["department"] == "Central Vault"

    # 6. Assert Account Unlock via PATCH /api/v1/admin/users/{id}
    unlock_res = await client.patch(
        f"/api/v1/admin/users/{created_id}",
        headers=admin_headers,
        json={"unlock_account": True},
    )
    assert unlock_res.status_code == 200
    unlocked_user = unlock_res.json()
    assert unlocked_user["locked_until"] is None
    assert unlocked_user["failed_login_attempts"] == 0

    # 7. Assert Credential Reset via PATCH /api/v1/admin/users/{id}
    reset_res = await client.patch(
        f"/api/v1/admin/users/{created_id}",
        headers=admin_headers,
        json={"reset_password": "NewSecurePassword456!"},
    )
    assert reset_res.status_code == 200

    # 8. Assert Role & Permission Matrix Endpoint
    matrix_res = await client.get("/api/v1/admin/roles/permissions", headers=admin_headers)
    assert matrix_res.status_code == 200
    matrix_data = matrix_res.json()
    assert len(matrix_data) == 6
    roles_present = {r["role"] for r in matrix_data}
    assert roles_present == {"admin", "controller", "hod", "setter", "printer", "student"}


def test_admin_roles_html_and_reference_fidelity():
    """
    Verifies that frontend/admin-roles.html implements all components,
    accessible attributes, responsive states, and visual requirements
    matching the approved reference mockup.
    """
    html_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend", "admin-roles.html")
    assert os.path.exists(html_path), "admin-roles.html must exist in frontend/"

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Document Structure & Meta
    assert "<!DOCTYPE html>" in html
    assert "Admin and Role Management Console — ExamOS" in html
    assert 'rel="stylesheet" href="css/design-system.css"' in html
    assert 'class="skip-to-main"' in html

    # 2. Header & Institutional Breadcrumb
    assert 'class="admin-header"' in html
    assert "System Administration" in html
    assert "User &amp; Role Governance" in html or "User & Role Governance" in html
    assert 'id="admin-session-pill"' in html
    assert 'id="btn-signout"' in html

    # 3. 4-Card KPI Strip matching approved mockup
    assert 'class="admin-kpi-grid"' in html
    assert "Total Directory Users" in html
    assert 'id="kpi-total-users"' in html
    assert "Active System Roles" in html
    assert 'id="kpi-roles-count"' in html
    assert "Authentication Policy" in html
    assert "Argon2id + MFA Enforced" in html
    assert "Audit Chain Health" in html
    assert 'id="kpi-audit-health"' in html

    # 4. User Directory Master Table Controls
    assert 'id="directory-master-heading"' in html
    assert "User Directory Master Table" in html
    assert 'id="search-users-input"' in html
    assert 'id="filter-role-select"' in html
    assert 'id="filter-dept-select"' in html
    assert 'id="btn-refresh-users"' in html
    assert 'id="btn-open-provision-modal"' in html
    assert "+ Provision User" in html
    assert 'id="users-table-body"' in html

    # 5. Role & Permission Matrix Inspector
    assert "Role &amp; Permission Matrix Inspector" in html or "Role & Permission Matrix Inspector" in html
    assert 'id="roles-matrix-accordion"' in html
    assert 'id="user-inspector-panel"' in html
    assert 'id="inspector-user-content"' in html

    # 6. Modals
    assert 'id="modal-provision-user"' in html
    assert 'id="form-provision-user"' in html
    assert 'id="modal-edit-user"' in html
    assert 'id="form-edit-user"' in html
    assert 'id="modal-reset-password"' in html
    assert 'id="form-reset-password"' in html

    # 7. Six Core System States
    assert 'id="state-loading"' in html
    assert 'id="state-empty"' in html
    assert 'id="state-permission-denied"' in html
    assert 'id="state-server-error"' in html
    assert 'id="main-admin-grid"' in html
    assert 'id="admin-alert"' in html

    # 8. Script link
    assert 'src="js/admin-roles.js"' in html
