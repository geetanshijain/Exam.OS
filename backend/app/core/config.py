from pathlib import Path
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    APP_NAME: str = "ExamOS"
    DEBUG: bool = True
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str = ""

    # Security & Tokens
    SECRET_KEY: str = "dev-insecure-secret-key-change-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30  # Standard session expiry
    SESSION_EXPIRE_HOURS: int = 24

    # Password Policy (Argon2id)
    ARGON2_TIME_COST: int = 3
    ARGON2_MEMORY_COST: int = 65536  # 64 MB
    ARGON2_PARALLELISM: int = 4

    # MFA Configuration
    MFA_ISSUER_NAME: str = "ExamOS"
    MFA_REQUIRED_ROLES: list[str] = ["admin", "controller"]

    # Account Lockout & Rate Limiting
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15
    RATE_LIMIT_LOGIN_PER_MINUTE: int = 10

    # Cookie & CSRF Settings
    COOKIE_NAME: str = "examos_session"
    COOKIE_SECURE: bool = False  # Set to True when HTTPS is enabled
    COOKIE_SAMESITE: str = "lax"
    CSRF_HEADER_NAME: str = "X-CSRF-Token"

    # CORS
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:8080",
        "http://localhost:8000",
        "http://localhost:3000",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:5173",
    ]

    # External AI
    GEMINI_API_KEY: str = ""

    @field_validator("DATABASE_URL", mode="before")
    @classmethod
    def assemble_db_connection(cls, v: str | None) -> str:
        if not v or v.strip() == "":
            # Anchor canonical SQLite DB at project root to prevent dual-file path drift
            root_db = Path(__file__).resolve().parents[3] / "examos.db"
            db_path_str = str(root_db).replace("\\", "/")
            return f"sqlite+aiosqlite:///{db_path_str}"
        if v.startswith("postgres://"):
            return v.replace("postgres://", "postgresql+asyncpg://", 1)
        if v.startswith("postgresql://") and not v.startswith("postgresql+"):
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v


settings = Settings()
