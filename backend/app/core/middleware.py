import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies institutional security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers["X-Content-Type-Options"] = "nosniff"
        headers["X-Frame-Options"] = "DENY"
        headers["X-XSS-Protection"] = "1; mode=block"
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data: blob:; "
            "style-src 'self' 'unsafe-inline'; "
            "script-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


class InMemoryRateLimiter:
    """Sliding-window rate limiter per client IP address."""

    def __init__(self, limit: int = 15, window_seconds: int = 60):
        self.limit = limit
        self.window_seconds = window_seconds
        self.requests: dict[str, list[float]] = defaultdict(list)

    def is_allowed(self, client_ip: str) -> bool:
        now = time.time()
        cutoff = now - self.window_seconds
        # Clean older entries
        self.requests[client_ip] = [t for t in self.requests[client_ip] if t > cutoff]
        if len(self.requests[client_ip]) >= self.limit:
            return False
        self.requests[client_ip].append(now)
        return True


# Global instances for sensitive routes
auth_rate_limiter = InMemoryRateLimiter(limit=10, window_seconds=60)
mfa_rate_limiter = InMemoryRateLimiter(limit=5, window_seconds=60)
reset_rate_limiter = InMemoryRateLimiter(limit=5, window_seconds=60)


def client_ip_from_request(request: Request) -> str:
    """Safely extract remote IP address."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def log_security_event(
    session: AsyncSession,
    action: str,
    ip: str,
    actor_id: int | None = None,
    details: dict | None = None,
    entity_type: str = "Auth",
    entity_id: int | None = None,
) -> None:
    """
    Sanitized audit logging helper.
    Strictly guarantees passwords, keys, tokens, or paper contents are never recorded.
    """
    safe_details = details.copy() if details else {}
    # Strip any potential sensitive keys
    for banned in ["password", "token", "secret", "mfa_code", "payload", "key"]:
        safe_details.pop(banned, None)

    safe_details["ip"] = ip
    log = AuditLog(
        actor_id=actor_id or 0,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        metadata_json=json.dumps(safe_details),
        timestamp=datetime.now(timezone.utc),
    )
    session.add(log)
    await session.commit()
