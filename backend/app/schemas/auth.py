from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.entities import Role


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    role: Role
    full_name: str
    badge_number: str
    mfa_enabled: bool = False
    mfa_enrollment_required: bool = False
    signing_key_registered: bool = False


class RefreshRequest(BaseModel):
    refresh_token: str


class CurrentUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    badge_number: str
    full_name: str
    role: Role
    mfa_enabled: bool
    signing_key_fingerprint: str | None = None


class MfaEnrollResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaActivateRequest(BaseModel):
    code: str


class SigningKeyRegisterRequest(BaseModel):
    public_key_pem: str


class SigningKeyResponse(BaseModel):
    id: UUID
    fingerprint: str
    status: str
    public_key_pem: str
    created_at: datetime
    retired_at: datetime | None = None
    revoked_at: datetime | None = None
