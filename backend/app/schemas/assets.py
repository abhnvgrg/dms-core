from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class AssetRegisterRequest(BaseModel):
    case_id: str
    item_name: str
    category: str


class AssetResponse(BaseModel):
    id: UUID
    case_id: str
    qr_uuid: UUID
    item_name: str
    category: str
    custody_status: str
    current_custodian_badge_number: str | None
    created_at: datetime


class AssetTransferRequest(BaseModel):
    expected_prior_custody_status: str
    new_custody_status: str
    receiving_officer_badge_number: str
    client_signature: str


class TransferRecordResponse(BaseModel):
    id: UUID
    from_status: str
    to_status: str
    performed_by: str
    received_by: str
    signature_valid: bool
    signing_key_status: str
    created_at: datetime
