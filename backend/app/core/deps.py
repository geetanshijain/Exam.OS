from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.permissions import Permission, has_permission
from app.core.security import decode_token
from app.db.session import get_session
from app.models.user import User, UserRole
from app.models.user_session import UserSession

_bearer_scheme = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: HTTPAuthorizationCredentials | None) -> str | None:
    """Extract token from Authorization header or HTTP-Only cookie."""
    if credentials and credentials.credentials:
        return credentials.credentials
    # Fallback to secure cookie
    return request.cookies.get(settings.COOKIE_NAME)


async def get_current_user_and_session(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)] = None,
) -> tuple[User, UserSession, dict]:
    """
    Core authentication dependency. Validates token, verifies against DB session
    table to ensure no revoked or expired sessions, and checks account status.
    """
    raw_token = _extract_token(request, credentials)
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(raw_token)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = int(payload.get("sub", 0))
    token_jti = payload.get("jti")

    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is currently inactive. Contact system administration.",
        )

    # Check account lockout status
    now = datetime.now(timezone.utc)
    if user.locked_until:
        locked_dt = user.locked_until if user.locked_until.tzinfo else user.locked_until.replace(tzinfo=timezone.utc)
        if locked_dt > now:
            delta = int((locked_dt - now).total_seconds() / 60) + 1
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account is temporarily locked due to excessive failed attempts. Try again in {delta} minutes.",
            )

    # Check active session status in DB
    user_sess = None
    if token_jti:
        stmt = (
            select(UserSession)
            .where(UserSession.token_jti == token_jti, UserSession.user_id == user_id)
            .order_by(UserSession.created_at.desc())
        )
        res = await session.execute(stmt)
        user_sess = res.scalars().first()

        if user_sess:
            if user_sess.revoked:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session was revoked. Please log in again.",
                )
            sess_exp = user_sess.expires_at if user_sess.expires_at.tzinfo else user_sess.expires_at.replace(tzinfo=timezone.utc)
            if sess_exp < now:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired. Please log in again.",
                )

    # If no DB session row (e.g. migration transition), create mock representation
    if not user_sess:
        user_sess = UserSession(
            session_id=token_jti or "adhoc",
            user_id=user.id,
            token_jti=token_jti or "adhoc",
            expires_at=datetime.fromtimestamp(payload.get("exp", now.timestamp() + 3600), timezone.utc),
            revoked=False,
        )

    return user, user_sess, payload


async def get_current_user(
    auth_tuple: Annotated[tuple[User, UserSession, dict], Depends(get_current_user_and_session)],
) -> User:
    """Dependency yielding authenticated User."""
    return auth_tuple[0]


async def get_current_session(
    auth_tuple: Annotated[tuple[User, UserSession, dict], Depends(get_current_user_and_session)],
) -> UserSession:
    """Dependency yielding active UserSession."""
    return auth_tuple[1]


def require_role(*roles: UserRole):
    """Dependency factory checking user role."""
    async def _dep(user: Annotated[User, Depends(get_current_user)]) -> User:
        if user.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Role '{user.role.value}' does not possess required administrative clearance.",
            )
        return user
    return _dep


def require_permission(permission: Permission, require_mfa: bool = False):
    """
    Dependency factory enforcing granular permissions and optional MFA requirement.
    """
    async def _dep(
        auth_tuple: Annotated[tuple[User, UserSession, dict], Depends(get_current_user_and_session)],
    ) -> User:
        user, _, payload = auth_tuple

        # Check role permission
        if not has_permission(user.role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Missing capability '{permission.value}'.",
            )

        # Enforce MFA verification for sensitive operations
        if require_mfa:
            is_mfa_verified = payload.get("mfa", False)
            if not is_mfa_verified:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Multi-factor authentication (MFA) verification required to execute this operation.",
                )

        return user
    return _dep


def require_any_permission(*permissions: Permission, require_mfa: bool = False):
    """
    Dependency factory enforcing that user possesses at least one of the specified permissions.
    """
    async def _dep(
        auth_tuple: Annotated[tuple[User, UserSession, dict], Depends(get_current_user_and_session)],
    ) -> User:
        user, _, payload = auth_tuple

        if not any(has_permission(user.role, p) for p in permissions):
            req_str = ", ".join(p.value for p in permissions)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Requires at least one capability from [{req_str}].",
            )

        if require_mfa:
            is_mfa_verified = payload.get("mfa", False)
            if not is_mfa_verified:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Multi-factor authentication (MFA) verification required to execute this operation.",
                )

        return user
    return _dep


# Typed Convenience Dependencies
CurrentUser = Annotated[User, Depends(get_current_user)]
CurrentSession = Annotated[UserSession, Depends(get_current_session)]

SetterUser = Annotated[User, Depends(require_role(UserRole.setter, UserRole.admin))]
HODUser = Annotated[User, Depends(require_role(UserRole.hod, UserRole.admin))]
ControllerUser = Annotated[User, Depends(require_role(UserRole.controller, UserRole.admin))]
PrinterUser = Annotated[User, Depends(require_role(UserRole.printer, UserRole.admin))]
AdminUser = Annotated[User, Depends(require_role(UserRole.admin))]
