from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.entities import Role


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class CurrentUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    badge_number: str
    full_name: str
    role: Role