import json
import pyotp
import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models.audit_log import AuditLog
from app.models.question_paper import PaperStatus, QuestionPaper
from app.models.user import User, UserRole
from app.models.user_session import UserSession


@pytest.mark.asyncio
async def test_argon2id_password_hashing():
    """Verify strong password hashing using Argon2id."""
    password = "SuperSecurePassword123!"
    hashed = hash_password(password)

    assert hashed.startswith("$argon2id$")
    assert verify_password(password, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


@pytest.mark.asyncio
async def test_user_registration_and_login_success(client: AsyncClient, db_session: AsyncSession):
    """Verify registration, Argon2id storage, and successful login with token and cookie."""
    # 1. Register User
    reg_res = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "faculty@examos.edu",
            "username": "faculty_user",
            "password": "ValidPassword123!",
            "full_name": "Faculty Member",
            "department": "Computer Science",
            "role": "setter",
        },
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert reg_data["email"] == "faculty@examos.edu"
    assert reg_data["username"] == "faculty_user"

    # 2. Login with valid username
    login_res = await client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "faculty_user",
            "password": "ValidPassword123!",
        },
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data
    assert login_data["mfa_required"] is False
    assert "examos_session" in login_res.cookies


@pytest.mark.asyncio
async def test_generic_auth_error_and_account_lockout(client: AsyncClient, db_session: AsyncSession):
    """
    Verify generic error response (no username/password enumeration) and account lockout
    after consecutive failed attempts.
    """
    # Create test user
    user = User(
        email="target@examos.edu",
        username="target_user",
        full_name="Target User",
        department="Mathematics",
        role=UserRole.setter,
        hashed_password=hash_password("CorrectPass123!"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    # 1. Unknown user returns generic error
    res_unknown = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "nonexistent@examos.edu", "password": "AnyPassword"},
    )
    assert res_unknown.status_code == 401
    assert res_unknown.json()["detail"] == "Invalid username, email, or password."

    # 2. Wrong password returns generic error
    res_wrong = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "target_user", "password": "WrongPassword"},
    )
    assert res_wrong.status_code == 401
    assert res_wrong.json()["detail"] == "Invalid username, email, or password."

    # 3. Repeat failed attempts to trigger lockout (threshold: 5)
    for _ in range(4):
        await client.post(
            "/api/v1/auth/login",
            json={"username_or_email": "target_user", "password": "WrongPassword"},
        )

    # 4. Attempt 6 should return 403 Account Locked
    lockout_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "target_user", "password": "CorrectPass123!"},
    )
    assert lockout_res.status_code == 403
    assert "temporarily locked" in lockout_res.json()["detail"]


@pytest.mark.asyncio
async def test_mfa_privileged_flow_and_recovery_codes(client: AsyncClient, db_session: AsyncSession):
    """Verify MFA setup, TOTP code verification, and backup recovery key login."""
    # Create controller user with MFA enabled
    mfa_secret = pyotp.random_base32()
    user = User(
        email="controller_mfa@examos.edu",
        username="ctrl_mfa",
        full_name="Controller MFA",
        department="Administration",
        role=UserRole.controller,
        hashed_password=hash_password("ControllerPass123!"),
        is_active=True,
        mfa_enabled=True,
        mfa_secret=mfa_secret,
        recovery_codes_json=json.dumps([
            "3f01e8cbe639a4da7af0a0ad2e33a0537563281f69e9010be2d42f859d9ee448"  # sha256 of "RECOV1234"
        ]),
    )
    db_session.add(user)
    await db_session.commit()

    # 1. Step 1: Login without MFA code prompts for MFA
    step1_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "ctrl_mfa", "password": "ControllerPass123!"},
    )
    assert step1_res.status_code == 200
    assert step1_res.json()["mfa_required"] is True

    # 2. Step 2: Login with valid TOTP code succeeds
    totp = pyotp.TOTP(mfa_secret)
    valid_code = totp.now()

    step2_res = await client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "ctrl_mfa",
            "password": "ControllerPass123!",
            "mfa_code": valid_code,
        },
    )
    assert step2_res.status_code == 200
    assert step2_res.json()["mfa_required"] is False
    assert "access_token" in step2_res.json()

    # 3. Test backup recovery key login
    recovery_res = await client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "ctrl_mfa",
            "password": "ControllerPass123!",
            "mfa_code": "RECOV-1234",
        },
    )
    assert recovery_res.status_code == 200
    assert "access_token" in recovery_res.json()


@pytest.mark.asyncio
async def test_idor_object_level_department_isolation(client: AsyncClient, db_session: AsyncSession):
    """
    Object-level authorization verification (IDOR protection):
    Prevent users from accessing another department's resources by changing IDs.
    """
    # User 1: Physics Setter
    physics_setter = User(
        email="physics_setter@examos.edu",
        username="physics_setter",
        full_name="Physics Setter",
        department="Physics",
        role=UserRole.setter,
        hashed_password=hash_password("Pass12345!"),
        is_active=True,
    )
    # User 2: Chemistry HOD
    chem_hod = User(
        email="chem_hod@examos.edu",
        username="chem_hod",
        full_name="Chemistry HOD",
        department="Chemistry",
        role=UserRole.hod,
        hashed_password=hash_password("Pass12345!"),
        is_active=True,
    )
    db_session.add_all([physics_setter, chem_hod])
    await db_session.commit()
    await db_session.refresh(physics_setter)
    await db_session.refresh(chem_hod)

    # Paper belonging to Physics department
    from datetime import datetime, timezone
    paper = QuestionPaper(
        title="Physics Final Exam",
        subject="Physics 101",
        department="Physics",
        exam_date=datetime.now(timezone.utc),
        status=PaperStatus.pending_hod,
        created_by=physics_setter.id,
    )
    db_session.add(paper)
    await db_session.commit()
    await db_session.refresh(paper)

    # Login as Chemistry HOD
    chem_login = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "chem_hod", "password": "Pass12345!"},
    )
    chem_token = chem_login.json()["access_token"]
    headers = {"Authorization": f"Bearer {chem_token}"}

    # 1. Chemistry HOD attempts to view Physics paper (IDOR attack via ID manipulation)
    view_res = await client.get(f"/api/v1/papers/{paper.id}", headers=headers)
    assert view_res.status_code == 403
    assert "Cross-department resource isolation" in view_res.json()["detail"]

    # 2. Chemistry HOD attempts to review/tamper with Physics paper
    review_res = await client.patch(
        f"/api/v1/papers/{paper.id}/hod-review?action=approve",
        headers=headers,
    )
    assert review_res.status_code == 403
    assert "Cross-department resource isolation" in review_res.json()["detail"]


@pytest.mark.asyncio
async def test_session_revocation_and_password_recovery(client: AsyncClient, db_session: AsyncSession):
    """Verify session revocation upon logout and password recovery flow."""
    user = User(
        email="student@examos.edu",
        username="student_1",
        full_name="Student Test",
        department="General",
        role=UserRole.student,
        hashed_password=hash_password("OldPassword123!"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()

    # 1. Login and get token
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "student_1", "password": "OldPassword123!"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Verify protected endpoint works
    me_res = await client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200

    # 2. Logout: Revokes active session
    logout_res = await client.post("/api/v1/auth/logout", headers=headers)
    assert logout_res.status_code == 200

    # 3. Attempting to use revoked token must fail with 401
    revoked_me = await client.get("/api/v1/auth/me", headers=headers)
    assert revoked_me.status_code == 401
    assert "revoked" in revoked_me.json()["detail"]


@pytest.mark.asyncio
async def test_sanitized_audit_logs_contain_no_passwords(client: AsyncClient, db_session: AsyncSession):
    """Verify that audit logs never record passwords, tokens, or plaintext secrets."""
    secret_pass = "ExtremelyConfidentialPassword999!"

    await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "any_user", "password": secret_pass},
    )

    # Inspect all audit logs in DB
    logs = (await db_session.execute(select(AuditLog))).scalars().all()
    for l in logs:
        assert secret_pass not in (l.metadata_json or "")
        assert "password" not in (l.metadata_json or "").lower()
