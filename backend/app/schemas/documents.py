from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class DocumentUploadResponse(BaseModel):
    id: UUID
    case_id: str
    filename: str
    sha256_hash: str
    signature: str
    uploaded_by: str
    uploaded_at: datetime
    ocr_status: str
    classification: str
    redacted_text: str | None = None


class DocumentStatusResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    processing_status: str
    processing_error: str | None = None


class EvidenceSummary(BaseModel):
    id: UUID
    case_id: str
    filename: str
    sha256_hash: str
    uploaded_by: str
    uploaded_at: datetime
    ocr_status: str


class EvidenceDetail(EvidenceSummary):
    signature: str | None
    classification: str
    extracted_text: str | None
    redacted_text: str | None


class DocumentSearchResult(BaseModel):
    id: UUID
    case_id: str
    filename: str
    uploaded_by: str
    uploaded_at: datetime
    ocr_status: str
    snippet: str | None = None
    score: float


class VerifyResponse(BaseModel):
    evidence_id: UUID
    filename: str | None = None
    original_hash: str | None = None
    recomputed_hash: str | None = None
    hash_match: bool | None = None
    signature_valid: bool | None = None
    signed_by: str | None = None
    signing_key_status: str | None = None
    integrity: str
    reason: str | None = None


class ReclassifyRequest(BaseModel):
    classification: str


class AccessGrantRequest(BaseModel):
    grantee_badge_number: str
    reason: str
    duration_hours: int = Field(gt=0, le=72)


class AccessGrantResponse(BaseModel):
    id: UUID
    document_id: UUID
    grantee_badge_number: str
    granted_by_badge_number: str
    reason: str
    expires_at: datetime
    revoked_at: datetime | None
