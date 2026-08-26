from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from app.models.entities import Role


class UserCreateRequest(BaseModel):
    badge_number: str = Field(min_length=2, max_length=64)
    full_name: str = Field(min_length=2, max_length=255)
    role: Role
    password: str = Field(min_length=12, max_length=256)


class UserUpdateRequest(BaseModel):
    role: Role | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: UUID
    badge_number: str
    full_name: str
    role: Role
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


class EncryptionKeyResponse(BaseModel):
    purpose: str
    version: int
    is_active: bool
    created_at: datetime
    rotated_at: datetime | None = None
