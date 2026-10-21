import hashlib
import hmac
import secrets
import string
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import argon2
import bcrypt
from jose import JWTError, jwt
import pyotp

from app.core.config import settings

# Initialize Argon2id password hasher with configured parameters
_argon2_hasher = argon2.PasswordHasher(
    time_cost=settings.ARGON2_TIME_COST,
    memory_cost=settings.ARGON2_MEMORY_COST,
    parallelism=settings.ARGON2_PARALLELISM,
    hash_len=32,
    type=argon2.Type.ID,
)


def hash_password(plain: str) -> str:
    """Hash password using Argon2id."""
    return _argon2_hasher.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    """
    Verify password. Supports Argon2id natively, with fallback verification
    for legacy bcrypt hashes.
    """
    if not hashed:
        return False
    # Check if hash is legacy bcrypt ($2b$ or $2a$)
    if hashed.startswith("$2b$") or hashed.startswith("$2a$") or hashed.startswith("$2y$"):
        try:
            return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
        except Exception:
            return False

    # Default to Argon2id
    try:
        return _argon2_hasher.verify(hashed, plain)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError, argon2.exceptions.InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """Determine if a legacy hash needs upgrading to Argon2id."""
    if hashed.startswith("$2b$") or hashed.startswith("$2a$"):
        return True
    try:
        return _argon2_hasher.check_needs_rehash(hashed)
    except Exception:
        return True


# --- Token Management ---

def create_access_token(
    subject: Any,
    role: str,
    department: str | None = None,
    jti: str | None = None,
    mfa_verified: bool = False,
    expires_delta: timedelta | None = None,
) -> tuple[str, str, datetime]:
    """
    Create a signed JWT access token.
    Returns (token_string, jti, expire_datetime).
    """
    token_jti = jti or uuid.uuid4().hex
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload: dict[str, Any] = {
        "sub": str(subject),
        "role": role,
        "dept": department or "",
        "jti": token_jti,
        "mfa": mfa_verified,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    encoded = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded, token_jti, expire


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT access token."""
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError as exc:
        raise ValueError("Invalid or expired session token") from exc


# --- Multi-Factor Authentication (TOTP & Recovery Codes) ---

def generate_mfa_secret() -> str:
    """Generate a high-entropy Base32 secret for TOTP (RFC 6238)."""
    return pyotp.random_base32()


def get_mfa_provisioning_uri(secret: str, email: str) -> str:
    """Get the standard otpauth:// provisioning URI for authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name=settings.MFA_ISSUER_NAME)


def verify_mfa_code(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code with standard ±1 time step tolerance."""
    if not secret or not code:
        return False
    try:
        clean_code = code.replace(" ", "").strip()
        totp = pyotp.TOTP(secret)
        # valid_window=1 allows 30 seconds drift in either direction
        return totp.verify(clean_code, valid_window=1)
    except Exception:
        return False


def generate_recovery_codes(count: int = 8) -> tuple[list[str], list[str]]:
    """
    Generate single-use backup recovery codes.
    Returns (plain_codes_to_show_user_once, hashed_codes_to_store_in_db).
    """
    alphabet = string.ascii_uppercase + string.digits
    plain_codes = []
    hashed_codes = []
    for _ in range(count):
        code = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(2))
        plain_codes.append(code)
        # Store SHA-256 hash of the normalized code
        h = hashlib.sha256(code.replace("-", "").upper().encode()).hexdigest()
        hashed_codes.append(h)
    return plain_codes, hashed_codes


def verify_and_consume_recovery_code(code: str, stored_hashes: list[str]) -> tuple[bool, list[str]]:
    """
    Verify if a recovery code matches any unused hash and remove it.
    Returns (is_valid, remaining_hashes).
    """
    normalized = hashlib.sha256(code.replace("-", "").strip().upper().encode()).hexdigest()
    if normalized in stored_hashes:
        remaining = [h for h in stored_hashes if h != normalized]
        return True, remaining
    return False, stored_hashes


# --- Password Reset Token Handling ---

def generate_password_reset_token() -> tuple[str, str]:
    """
    Generate high-entropy password reset token.
    Returns (plain_token_for_url, hashed_token_for_db).
    """
    plain = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plain.encode()).hexdigest()
    return plain, token_hash


def verify_password_reset_token_hash(plain_token: str, stored_hash: str) -> bool:
    """Verify raw token against stored SHA-256 hash in constant time."""
    computed = hashlib.sha256(plain_token.encode()).hexdigest()
    return hmac.compare_digest(computed, stored_hash)


# --- CSRF Protection ---

def generate_csrf_token(session_id: str) -> str:
    """Generate an HMAC-signed CSRF token tied to the user's session ID."""
    raw = f"{session_id}:{secrets.token_hex(16)}"
    signature = hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}:{signature}"


def verify_csrf_token(csrf_token: str, session_id: str) -> bool:
    """Verify CSRF token authenticity and association with the session."""
    if not csrf_token or not session_id:
        return False
    parts = csrf_token.split(":")
    if len(parts) != 3:
        return False
    token_sess, nonce, sig = parts
    if token_sess != session_id:
        return False
    raw = f"{token_sess}:{nonce}"
    expected_sig = hmac.new(settings.SECRET_KEY.encode(), raw.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(sig, expected_sig)
