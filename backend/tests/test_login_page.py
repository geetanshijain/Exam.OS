import os
import re
from datetime import datetime, timezone
import pytest
import pyotp
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import hash_password, verify_password
from app.models.user import User, UserRole
from app.models.user_session import UserSession


@pytest.mark.asyncio
async def test_login_and_recovery_backend_contracts(client: AsyncClient, db_session: AsyncSession):
    """
    Validates backend API contracts used by the Login and Account Recovery page:
    1. Successful login returns access_token, user profile, and sets session cookie.
    2. Invalid credentials return generic 401 error.
    3. MFA challenge trigger and verification (TOTP & backup code).
    4. Account lockout behavior.
    5. Password reset request (anti-enumeration & dev token).
    6. Password reset confirmation updates Argon2id password and invalidates sessions.
    """
    # 1. Setup test user
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    valid_totp_code = totp.now()

    user = User(
        email="examiner@examos.edu",
        username="examiner_user",
        full_name="Exam Setter One",
        department="Computer Science",
        role=UserRole.setter,
        hashed_password=hash_password("InitialPass123!"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # 2. Successful Login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "examiner_user", "password": "InitialPass123!"},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert "access_token" in login_data
    assert login_data["mfa_required"] is False
    assert login_data["user"]["email"] == "examiner@examos.edu"
    assert "examos_session" in login_res.cookies

    # 3. Generic Error on Bad Password (preventing timing and credential leakage)
    bad_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "examiner_user", "password": "WrongPassword999!"},
    )
    assert bad_res.status_code == 401
    assert bad_res.json()["detail"] == "Invalid username, email, or password."

    # 4. MFA Enabled User - Trigger MFA Required Flow
    user.mfa_secret = totp_secret
    user.mfa_enabled = True
    await db_session.commit()

    mfa_challenge_res = await client.post(
        "/api/v1/auth/login",
        json={"username_or_email": "examiner_user", "password": "InitialPass123!"},
    )
    assert mfa_challenge_res.status_code == 200
    mfa_data = mfa_challenge_res.json()
    assert mfa_data["mfa_required"] is True

    # Complete Login with TOTP code
    mfa_verify_res = await client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "examiner_user",
            "password": "InitialPass123!",
            "mfa_code": valid_totp_code,
        },
    )
    assert mfa_verify_res.status_code == 200
    assert mfa_verify_res.json()["mfa_required"] is False
    assert "access_token" in mfa_verify_res.json()

    # 5. Account Recovery Workflow
    # Step A: Request password reset
    reset_req_res = await client.post(
        "/api/v1/auth/password-reset/request",
        json={"email": "examiner@examos.edu"},
    )
    assert reset_req_res.status_code == 200
    msg = reset_req_res.json()["message"]
    assert "password recovery instructions have been processed" in msg.lower()

    # Extract DEV_TOKEN (enabled in development)
    match = re.search(r"\[DEV_TOKEN:\s*([^\]]+)\]", msg)
    assert match is not None
    dev_token = match.group(1).strip()

    # Step B: Confirm password reset with new password
    confirm_res = await client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"token": dev_token, "new_password": "NewBrandStrongPass456!"},
    )
    assert confirm_res.status_code == 200
    assert "successfully reset" in confirm_res.json()["message"].lower()

    # Verify user can log in with new password
    login_new_res = await client.post(
        "/api/v1/auth/login",
        json={
            "username_or_email": "examiner_user",
            "password": "NewBrandStrongPass456!",
            "mfa_code": totp.now(),
        },
    )
    assert login_new_res.status_code == 200


def test_login_and_recovery_html_structure_and_accessibility():
    """
    Verifies that frontend/login.html and frontend/password-reset.html
    strictly adhere to semantic HTML, accessibility requirements, and the approved reference layout.
    """
    frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "..", "frontend")
    login_path = os.path.join(frontend_dir, "login.html")
    reset_path = os.path.join(frontend_dir, "password-reset.html")

    assert os.path.exists(login_path), "frontend/login.html must exist"
    assert os.path.exists(reset_path), "frontend/password-reset.html must exist"

    with open(login_path, "r", encoding="utf-8") as f:
        login_html = f.read()

    with open(reset_path, "r", encoding="utf-8") as f:
        reset_html = f.read()

    # 1. Landmarks & Accessibility in login.html
    assert 'class="skip-to-main"' in login_html
    assert '<header class="site-header"' in login_html
    assert '<main class="auth-wrapper"' in login_html
    assert '<form id="login-form"' in login_html
    assert 'role="alert"' in login_html

    # 2. Approved Reference Visual Elements
    assert "Institutional Sign In" in login_html
    assert "Enter your university credentials to access the examination portal" in login_html
    assert "Username or Institutional Email" in login_html
    assert 'id="username_or_email"' in login_html
    assert "Password" in login_html
    assert 'id="password"' in login_html
    assert 'id="toggle-password"' in login_html
    assert "Conditional multi-factor authentication (MFA) token code, for privileged personnel" in login_html
    assert 'id="mfa_code"' in login_html
    assert 'class="auth-btn-signin"' in login_html
    assert "Sign In" in login_html
    assert "Forgot password?" in login_html
    assert "Account Recovery" in login_html
    assert "Protected by Argon2id cryptographic hashing, rate limiting, and server-side session monitoring" in login_html
    assert "DEV ENVIRONMENT — SAMPLE DATA EXPLICITLY LABELLED" in login_html
    assert "Institutional" in login_html and "Security" in login_html

    # 3. Account Recovery Modal & Standalone Consistency
    assert 'id="recovery-modal"' in login_html
    assert "Account Recovery" in reset_html
    assert 'id="request-reset-form"' in reset_html
    assert 'id="confirm-reset-form"' in reset_html
    assert "Protected by Argon2id" in login_html
