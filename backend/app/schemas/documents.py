from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class DocumentUploadResponse(BaseModel):
    id: UUID
    case_id: UUID
    processing_status: str


class DocumentStatusResponse(BaseModel):
    id: UUID
    processing_status: str
    processing_error: str | None = None


class DocumentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    uploaded_by_id: UUID
    original_filename: str
    content_type: str
    sha256_hash: str
    processing_status: str
    redacted_text: str | None
    processing_error: str | None
    created_at: datetime