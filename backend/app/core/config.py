from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    APP_NAME: str = "ExamOS"
    DEBUG: bool = True

    DATABASE_URL: str = "sqlite+aiosqlite:///./examos.db"

    SECRET_KEY: str = "change-this-to-a-32-char-secret-before-deploy"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    CORS_ORIGINS: list[str] = ["http://localhost:5173"]


settings = Settings()
