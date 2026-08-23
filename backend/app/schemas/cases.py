from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict

from app.models.entities import Role


class CaseCreate(BaseModel):
    fir_number: str
    title: str
    acts_sections: str | None = None


class CaseAssignmentCreate(BaseModel):
    user_id: UUID


class CaseAssignmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: UUID
    assigned_at: datetime


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    fir_number: str
    title: str
    status: str
    acts_sections: str | None
    created_by_id: UUID
    created_at: datetime
    updated_at: datetime