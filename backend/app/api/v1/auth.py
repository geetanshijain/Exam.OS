import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import CurrentSession, CurrentUser, get_current_user_and_session
from app.core.middleware import (
    auth_rate_limiter,
    client_ip_from_request,
    log_security_event,
    mfa_rate_limiter,
    reset_rate_limiter,
)
from app.core.security import (
    create_access_token,
    decode_token,
    generate_csrf_token,
    generate_mfa_secret,
    generate_password_reset_token,
    generate_recovery_codes,
    get_mfa_provisioning_uri,
    hash_password,
    needs_rehash,
    verify_and_consume_recovery_code,
    verify_mfa_code,
    verify_password,
    verify_password_reset_token_hash,
)
from app.db.session import get_session
from app.models.password_reset import PasswordResetToken
from app.models.user import User, UserRole
from app.models.user_session import UserSession
from app.schemas.common import MessageResponse
from app.schemas.user import (
    LoginRequest,
    LoginResponse,
    MFASetupResponse,
    MFAVerifyRequest,
    PasswordResetConfirm,
    PasswordResetRequest,
    SessionRead,
    UserCreate,
    UserRead,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
async def register_user(
    payload: UserCreate,
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
) -> UserRead:
    """Register a new user account with Argon2id hashing."""
    ip = client_ip_from_request(request)

    # Check email and username uniqueness
    stmt = select(User).where(or_(User.email == payload.email, User.username == payload.username))
    existing = await session.scalar(stmt)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address or username already exists.",
        )

    user = User(
        email=payload.email.lower().strip(),
        username=payload.username.lower().strip(),
        full_name=payload.full_name.strip(),
        department=payload.department.strip(),
        role=payload.role,
        hashed_password=hash_password(payload.password),
        is_active=True,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    await log_security_event(
        session=session,
        action="AUTH_USER_REGISTERED",
        ip=ip,
        actor_id=user.id,
        details={"email": user.email, "role": user.role.value, "dept": user.department},
    )

    return UserRead.model_validate(user)


@router.post("/login", response_model=LoginResponse)
async def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> LoginResponse:
    """
    Secure login with rate limiting, lockout protection, Argon2id,
    MFA enforcement for privileged roles, and HTTP-only session cookies.
    """
    ip = client_ip_from_request(request)
    now = datetime.now(timezone.utc)

    # 1. Rate Limiting Check
    if not auth_rate_limiter.is_allowed(ip):
        await log_security_event(
            session=session,
            action="AUTH_RATE_LIMIT_EXCEEDED",
            ip=ip,
            details={"attempted_id": payload.username_or_email},
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many authentication attempts. Please pause and try again in one minute.",
        )

    # 2. Lookup User
    identifier = payload.username_or_email.lower().strip()
    stmt = select(User).where(or_(User.email == identifier, User.username == identifier))
    user = await session.scalar(stmt)

    # 3. Handle Non-Existent User (Timing attack mitigation)
    if not user:
        # Perform dummy verify to simulate cryptographic workload
        verify_password("dummy_password_timing_pad", "$argon2id$v=19$m=65536,t=3,p=4$dummyhashpad$dummyhashpad")
        await log_security_event(
            session=session,
            action="AUTH_LOGIN_FAILED_UNKNOWN_USER",
            ip=ip,
            details={"identifier": identifier},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username, email, or password.",
        )

    # 4. Check Account Lockout
    if user.locked_until:
        locked_dt = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked_dt > now:
            minutes_remaining = int((locked_dt - now).total_seconds() / 60) + 1
            await log_security_event(
                session=session,
                action="AUTH_LOGIN_ATTEMPT_LOCKED_ACCOUNT",
                ip=ip,
                actor_id=user.id,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to repeated failed logins. Try again in {minutes_remaining} minutes.",
            )

    # 5. Check Inactive Status
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact the system administrator.",
        )

    # 6. Verify Password
    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=settings.ACCOUNT_LOCKOUT_MINUTES)
            await log_security_event(
                session=session,
                action="AUTH_ACCOUNT_LOCKED",
                ip=ip,
                actor_id=user.id,
                details={"failed_attempts": user.failed_login_attempts},
            )
        else:
            await log_security_event(
                session=session,
                action="AUTH_LOGIN_FAILED_BAD_PASSWORD",
                ip=ip,
                actor_id=user.id,
                details={"failed_attempts": user.failed_login_attempts},
            )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username, email, or password.",
        )

    # Successful Password: Reset lockout counters
    user.failed_login_attempts = 0
    user.locked_until = None

    # Upgrade password to Argon2id if legacy hash
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(payload.password)

    # 7. Multi-Factor Authentication Check
    requires_mfa = user.mfa_enabled or (user.role.value in settings.MFA_REQUIRED_ROLES and user.mfa_secret)
    is_mfa_verified = False

    if requires_mfa:
        if not payload.mfa_code:
            # Issue a temporary 5-minute pre-auth token for MFA verification step
            pre_auth_token, _, _ = create_access_token(
                subject=user.id,
                role=user.role.value,
                department=user.department,
                mfa_verified=False,
                expires_delta=timedelta(minutes=5),
            )
            await session.commit()
            return LoginResponse(
                access_token=pre_auth_token,
                csrf_token="",
                mfa_required=True,
                user=UserRead.model_validate(user),
            )

        # Validate provided MFA code (TOTP or Backup Recovery Code)
        code = payload.mfa_code.strip()
        totp_valid = verify_mfa_code(user.mfa_secret or "", code)

        if not totp_valid:
            # Check backup recovery codes
            recovery_valid = False
            if user.recovery_codes_json:
                stored_hashes = json.loads(user.recovery_codes_json)
                matched, remaining = verify_and_consume_recovery_code(code, stored_hashes)
                if matched:
                    recovery_valid = True
                    user.recovery_codes_json = json.dumps(remaining)
                    await log_security_event(
                        session=session,
                        action="AUTH_MFA_RECOVERY_CODE_CONSUMED",
                        ip=ip,
                        actor_id=user.id,
                    )

            if not recovery_valid:
                await log_security_event(
                    session=session,
                    action="AUTH_MFA_INVALID_CODE",
                    ip=ip,
                    actor_id=user.id,
                )
                await session.commit()
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid multi-factor authentication code or backup recovery key.",
                )

        is_mfa_verified = True
    else:
        # Standard unprivileged user without MFA configured
        is_mfa_verified = True

    # 8. Create Active DB Session Record
    session_id = uuid.uuid4().hex
    token_jti = uuid.uuid4().hex
    session_expires = now + timedelta(hours=settings.SESSION_EXPIRE_HOURS)

    user_agent = request.headers.get("User-Agent", "Unknown")[:500]
    user_sess = UserSession(
        session_id=session_id,
        user_id=user.id,
        token_jti=token_jti,
        ip_address=ip,
        user_agent=user_agent,
        expires_at=session_expires,
        revoked=False,
    )
    session.add(user_sess)
    await session.commit()

    # 9. Create Access Token & CSRF Token
    token_str, _, token_exp = create_access_token(
        subject=user.id,
        role=user.role.value,
        department=user.department,
        jti=token_jti,
        mfa_verified=is_mfa_verified,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    csrf_token = generate_csrf_token(session_id)

    # 10. Set Secure HTTP-Only Cookie
    response.set_cookie(
        key=settings.COOKIE_NAME,
        value=token_str,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        expires=int(token_exp.timestamp()),
        path="/",
    )

    await log_security_event(
        session=session,
        action="AUTH_LOGIN_SUCCESS",
        ip=ip,
        actor_id=user.id,
        details={"session_id": session_id, "mfa": is_mfa_verified},
    )

    return LoginResponse(
        access_token=token_str,
        csrf_token=csrf_token,
        mfa_required=False,
        user=UserRead.model_validate(user),
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    response: Response,
    request: Request,
    auth_tuple: Annotated[tuple[User, UserSession, dict], Depends(get_current_user_and_session)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MessageResponse:
    """Explicitly revoke user session and clear authentication cookies."""
    user, user_sess, _ = auth_tuple
    ip = client_ip_from_request(request)

    if user_sess:
        user_sess.revoked = True
        await session.commit()

    response.delete_cookie(key=settings.COOKIE_NAME, path="/")

    await log_security_event(
        session=session,
        action="AUTH_LOGOUT",
        ip=ip,
        actor_id=user.id,
        details={"session_id": user_sess.session_id if user_sess else "none"},
    )
    return MessageResponse(message="Session successfully terminated.")


@router.get("/me", response_model=UserRead)
async def get_current_user_profile(
    current_user: CurrentUser,
) -> UserRead:
    """Return profile details for the currently authenticated user."""
    return UserRead.model_validate(current_user)


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
) -> MFASetupResponse:
    """
    Generate TOTP secret and backup recovery codes for authenticator app enrollment.
    """
    secret = generate_mfa_secret()
    uri = get_mfa_provisioning_uri(secret, current_user.email)
    plain_codes, hashed_codes = generate_recovery_codes(8)

    # Save pending secret and backup hashes to user
    current_user.mfa_secret = secret
    current_user.recovery_codes_json = json.dumps(hashed_codes)
    await session.commit()

    ip = client_ip_from_request(request)
    await log_security_event(
        session=session,
        action="AUTH_MFA_SETUP_INITIATED",
        ip=ip,
        actor_id=current_user.id,
    )

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=uri,
        recovery_codes=plain_codes,
    )


@router.post("/mfa/verify", response_model=MessageResponse)
async def verify_and_enable_mfa(
    payload: MFAVerifyRequest,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
) -> MessageResponse:
    """Verify enrolled TOTP code and finalize MFA activation."""
    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup has not been initiated.",
        )

    if not verify_mfa_code(current_user.mfa_secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification code is invalid. Check your authenticator app and system clock.",
        )

    current_user.mfa_enabled = True
    await session.commit()

    ip = client_ip_from_request(request)
    await log_security_event(
        session=session,
        action="AUTH_MFA_ENABLED",
        ip=ip,
        actor_id=current_user.id,
    )

    return MessageResponse(message="Multi-factor authentication successfully activated.")


@router.post("/password-reset/request", response_model=MessageResponse)
async def request_password_reset(
    payload: PasswordResetRequest,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MessageResponse:
    """
    Initiate account recovery. Generates single-use reset token.
    Generic response prevents user enumeration.
    """
    ip = client_ip_from_request(request)
    if not reset_rate_limiter.is_allowed(ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password reset requests. Please wait before trying again.",
        )

    stmt = select(User).where(User.email == payload.email.lower().strip())
    user = await session.scalar(stmt)

    debug_token = None
    if user and user.is_active:
        plain_token, token_hash = generate_password_reset_token()
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)

        reset_record = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False,
        )
        session.add(reset_record)
        await session.commit()

        await log_security_event(
            session=session,
            action="AUTH_PASSWORD_RESET_REQUESTED",
            ip=ip,
            actor_id=user.id,
        )
        if settings.ENVIRONMENT == "development":
            debug_token = plain_token

    msg = "If an account matching that email exists, password recovery instructions have been processed."
    if debug_token:
        msg += f" [DEV_TOKEN: {debug_token}]"

    return MessageResponse(message=msg)


@router.post("/password-reset/confirm", response_model=MessageResponse)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> MessageResponse:
    """Confirm password recovery using valid reset token and update password."""
    ip = client_ip_from_request(request)
    now = datetime.now(timezone.utc)

    # Find unexpired, unused reset tokens
    stmt = (
        select(PasswordResetToken)
        .where(PasswordResetToken.used == False, PasswordResetToken.expires_at > now)
        .order_by(PasswordResetToken.created_at.desc())
    )
    candidates = (await session.execute(stmt)).scalars().all()

    matched_record = None
    for cand in candidates:
        if verify_password_reset_token_hash(payload.token, cand.token_hash):
            matched_record = cand
            break

    if not matched_record:
        await log_security_event(
            session=session,
            action="AUTH_PASSWORD_RESET_INVALID_TOKEN",
            ip=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password recovery link is invalid or has expired.",
        )

    user = await session.get(User, matched_record.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="User associated with token not found.")

    # Update password with Argon2id and unlock account
    user.hashed_password = hash_password(payload.new_password)
    user.failed_login_attempts = 0
    user.locked_until = None
    matched_record.used = True

    # Invalidate all active sessions for this user (forced re-login)
    sess_stmt = select(UserSession).where(UserSession.user_id == user.id, UserSession.revoked == False)
    active_sessions = (await session.execute(sess_stmt)).scalars().all()
    for s in active_sessions:
        s.revoked = True

    await session.commit()

    await log_security_event(
        session=session,
        action="AUTH_PASSWORD_RESET_COMPLETED",
        ip=ip,
        actor_id=user.id,
    )

    return MessageResponse(message="Password successfully reset. Please sign in with your new credentials.")


@router.get("/sessions", response_model=list[SessionRead])
async def list_active_sessions(
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> list[SessionRead]:
    """List all active, unrevoked sessions for the current user."""
    stmt = (
        select(UserSession)
        .where(UserSession.user_id == current_user.id, UserSession.revoked == False)
        .order_by(UserSession.created_at.desc())
    )
    records = (await session.execute(stmt)).scalars().all()
    return [SessionRead.model_validate(r) for r in records]


@router.delete("/sessions/{session_id}", response_model=MessageResponse)
async def revoke_specific_session(
    session_id: str,
    current_user: CurrentUser,
    session: Annotated[AsyncSession, Depends(get_session)],
    request: Request,
) -> MessageResponse:
    """Revoke a specific session ID belonging to the user."""
    stmt = select(UserSession).where(
        UserSession.session_id == session_id,
        UserSession.user_id == current_user.id,
    )
    user_sess = await session.scalar(stmt)
    if not user_sess:
        raise HTTPException(status_code=404, detail="Session not found.")

    user_sess.revoked = True
    await session.commit()

    ip = client_ip_from_request(request)
    await log_security_event(
        session=session,
        action="AUTH_SESSION_REVOKED",
        ip=ip,
        actor_id=current_user.id,
        details={"revoked_session_id": session_id},
    )

    return MessageResponse(message="Session revoked.")
