from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

from app.models.user import UserRole


class UserCreate(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2, max_length=100)
    department: str = Field(default="General", max_length=100)
    role: UserRole


class UserRead(BaseModel):
    id: int
    email: str
    username: str
    full_name: str
    department: str
    role: UserRole
    is_active: bool
    mfa_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username_or_email: str
    password: str
    mfa_code: str | None = None


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    csrf_token: str
    mfa_required: bool = False
    user: UserRead | None = None


class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    recovery_codes: list[str]


class MFAVerifyRequest(BaseModel):
    code: str


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str
    new_password: str = Field(min_length=8)


class SessionRead(BaseModel):
    id: int
    session_id: str
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    expires_at: datetime

    model_config = {"from_attributes": True}
