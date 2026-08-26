from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditEntryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    action_type: str
    entity_type: str
    entity_id: UUID
    actor_id: UUID | None
    payload: dict
    previous_entry_hash: str | None
    entry_hash: str
    chain_tx_hash: str | None
    chain_block_number: int | None
    chain_anchored_at: datetime | None
    created_at: datetime


class LedgerVerifyResponse(BaseModel):
    status: str
    chain_status: str | None = None
    entries_checked: int | None = None
    broken_at_entry_id: int | None = None
    reason: str | None = None
    checkpoint_status: str | None = None
    checkpoints_checked: int | None = None
    entries_covered_by_checkpoints: int | None = None
    broken_at_checkpoint_id: int | None = None
    mirrored_to_write_once_store: int | None = None


class CheckpointResponse(BaseModel):
    id: int
    from_entry_id: int
    to_entry_id: int
    entry_count: int
    checkpoint_hash: str
    signing_key_version: int
    object_key: str | None
    created_at: datetime


class OnchainVerifyResponse(BaseModel):
    entry_id: int
    db_entry_hash: str
    onchain_entry_hash: str | None = None
    match: bool | None = None
    status: str
