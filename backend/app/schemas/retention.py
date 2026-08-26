from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RetentionPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    retention_minutes: int
    updated_by_id: UUID | None
    updated_at: datetime


class RetentionPolicyUpdate(BaseModel):
    retention_minutes: int = Field(gt=0, le=5_256_000)  # ~ up to 10 years


class PurgeNowResponse(BaseModel):
    purged_count: int
    retention_minutes: int
