import enum
import uuid
from datetime import datetime

from pgvector.sqlalchemy import Vector
from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class Role(str, enum.Enum):
    INVESTIGATING_OFFICER = "investigating_officer"
    FORENSICS_OFFICER = "forensics_officer"
    COURT_OFFICIAL = "court_official"
    ADMIN = "admin"


class DocumentStatus(str, enum.Enum):
    PROCESSING = "processing"
    READY = "ready"
    FAILED = "failed"


class CustodyStatus(str, enum.Enum):
    POLICE_CUSTODY = "police_custody"
    FORENSICS_CUSTODY = "forensics_custody"
    COURT_CUSTODY = "court_custody"
    RELEASED = "released"


class EncryptionKeyPurpose(str, enum.Enum):
    PII_DATA = "pii_data"
    OBJECT_STORAGE = "object_storage"
    CHECKPOINT_SIGNING = "checkpoint_signing"


class SigningKeyStatus(str, enum.Enum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class DocumentClassification(str, enum.Enum):
    PUBLIC_REDACTED = "public_redacted"
    CASE_RESTRICTED = "case_restricted"
    COURT_ELEVATED = "court_elevated"
    ADMIN_ONLY = "admin_only"


class AuditAction(str, enum.Enum):
    DOCUMENT_UPLOADED = "document_uploaded"
    DOCUMENT_PROCESSED = "document_processed"
    DOCUMENT_PROCESSING_FAILED = "document_processing_failed"
    DOCUMENT_ACCESSED = "document_accessed"
    ACCESS_GRANTED = "access_granted"
    ACCESS_REVOKED = "access_revoked"
    ASSET_REGISTERED = "asset_registered"
    ASSET_TRANSFERRED = "asset_transferred"
    INTEGRITY_VERIFIED = "integrity_verified"
    CASE_CREATED = "case_created"
    CASE_ASSIGNED = "case_assigned"
    DOCUMENT_PURGED = "document_purged"
    RETENTION_POLICY_UPDATED = "retention_policy_updated"
    LOGIN_LOCKED = "login_locked"
    DOCUMENT_RECLASSIFIED = "document_reclassified"
    SESSION_REUSE_DETECTED = "session_reuse_detected"
    MFA_ENABLED = "mfa_enabled"
    KEY_ROTATED = "key_rotated"
    MALWARE_DETECTED = "malware_detected"
    DOCUMENT_DOWNLOADED = "document_downloaded"
    ASSET_TRANSFER_CONFLICT = "asset_transfer_conflict"
    ACCESS_GRANT_EXPIRED = "access_grant_expired"
    KEY_REVOKED = "key_revoked"
    SIGNING_KEY_REGISTERED = "signing_key_registered"
    SIGNING_KEY_REVOKED = "signing_key_revoked"
    AUDIT_CHECKPOINT_CREATED = "audit_checkpoint_created"
    USER_CREATED = "user_created"
    USER_ROLE_CHANGED = "user_role_changed"
    USER_DEACTIVATED = "user_deactivated"
    FILE_REJECTED = "file_rejected"

def enum_values(enum_class):
    return [member.value for member in enum_class]


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class User(TimestampMixin, Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    badge_number: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(255))
    role: Mapped[Role] = mapped_column(
        Enum(Role, name="user_role", values_callable=enum_values),
        nullable=False,
        index=True,
    )
    password_hash: Mapped[str] = mapped_column(String(255))
    public_key_pem: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Session(TimestampMixin, Base):
    __tablename__ = "sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    access_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    refresh_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    previous_refresh_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    refresh_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mfa_pending: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Case(TimestampMixin, Base):
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    fir_number: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    status: Mapped[str] = mapped_column(String(64), default="open", nullable=False)
    acts_sections: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )


class CaseAssignment(Base):
    __tablename__ = "case_assignments"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_case_assignment"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class Document(TimestampMixin, Base):
    __tablename__ = "documents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    object_key: Mapped[str] = mapped_column(String(1024), unique=True, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    signing_key_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("officer_signing_keys.id", ondelete="RESTRICT"),
        nullable=True,
    )
    processing_status: Mapped[DocumentStatus] = mapped_column(
        Enum(DocumentStatus, name="document_status", values_callable=enum_values),
        default=DocumentStatus.PROCESSING,
        nullable=False,
        index=True,
    )
    extracted_text_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    redacted_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    embedding: Mapped[list[float] | None] = mapped_column(Vector(384), nullable=True)
    processing_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    classification: Mapped[DocumentClassification] = mapped_column(
        Enum(DocumentClassification, name="document_classification", values_callable=enum_values),
        default=DocumentClassification.CASE_RESTRICTED,
        nullable=False,
        index=True,
    )


class PhysicalAsset(TimestampMixin, Base):
    __tablename__ = "physical_assets"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cases.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    registered_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    qr_uuid: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        unique=True,
        default=uuid.uuid4,
        nullable=False,
        index=True,
    )
    item_name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(128), nullable=False)
    custody_status: Mapped[CustodyStatus] = mapped_column(
        Enum(CustodyStatus, name="custody_status", values_callable=enum_values),
        default=CustodyStatus.POLICE_CUSTODY,
        nullable=False,
    )
    current_custodian_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )


class DocumentAccessGrant(TimestampMixin, Base):
    __tablename__ = "document_access_grants"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    document_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    grantee_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    granted_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )


class AuditLedger(Base):
    __tablename__ = "audit_ledger"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_type: Mapped[AuditAction] = mapped_column(
        Enum(AuditAction, name="audit_action", values_callable=enum_values),
        nullable=False,
        index=True,
    )
    entity_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    payload: Mapped[dict] = mapped_column(
        JSONB,
        server_default=text("'{}'::jsonb"),
        nullable=False,
    )
    signature: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_entry_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    chain_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    chain_block_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    chain_anchored_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )


class RetentionPolicy(TimestampMixin, Base):
    __tablename__ = "retention_policies"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    retention_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )


class EncryptionKey(TimestampMixin, Base):
    __tablename__ = "encryption_keys"
    __table_args__ = (
        UniqueConstraint("purpose", "version", name="uq_encryption_key_purpose_version"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    purpose: Mapped[EncryptionKeyPurpose] = mapped_column(
        Enum(EncryptionKeyPurpose, name="encryption_key_purpose", values_callable=enum_values),
        nullable=False,
        index=True,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    wrapped_key: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class OfficerSigningKey(TimestampMixin, Base):
    """A public key an officer generated in their browser.

    The private half never reaches the server, so a signature verified against one
    of these rows is attributable to the officer rather than to the backend. Old
    keys are retired rather than deleted so historical signatures still verify.
    """

    __tablename__ = "officer_signing_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    status: Mapped[SigningKeyStatus] = mapped_column(
        Enum(SigningKeyStatus, name="signing_key_status", values_callable=enum_values),
        default=SigningKeyStatus.ACTIVE,
        nullable=False,
        index=True,
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )


class AssetTransfer(Base):
    """One custody handover, with the officer's client-side signature over it.

    Kept as its own table rather than living only in the audit payload so the
    signed message can be reconstructed and re-verified later.
    """

    __tablename__ = "asset_transfers"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("physical_assets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    performed_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    receiving_officer_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    from_status: Mapped[CustodyStatus] = mapped_column(
        Enum(CustodyStatus, name="custody_status", values_callable=enum_values, create_type=False),
        nullable=False,
    )
    to_status: Mapped[CustodyStatus] = mapped_column(
        Enum(CustodyStatus, name="custody_status", values_callable=enum_values, create_type=False),
        nullable=False,
    )
    signed_payload: Mapped[str] = mapped_column(Text, nullable=False)
    client_signature: Mapped[str] = mapped_column(Text, nullable=False)
    signing_key_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("officer_signing_keys.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )


class AuditCheckpoint(Base):
    """A signed summary of a run of ledger entries, mirrored to write-once storage.

    The in-database hash chain proves internal consistency; the checkpoint proves
    the chain has not been regenerated wholesale, because its signature is made
    with a key the database never sees and its copy lives outside the database.
    """

    __tablename__ = "audit_checkpoints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    from_entry_id: Mapped[int] = mapped_column(Integer, nullable=False)
    to_entry_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    entry_count: Mapped[int] = mapped_column(Integer, nullable=False)
    checkpoint_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signing_key_version: Mapped[int] = mapped_column(Integer, nullable=False)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )


class KnownDevice(Base):
    """A browser and network an officer has already been seen logging in from.

    v4 §5 mandates a second factor for logins from anywhere unfamiliar. For an
    enrolled user that is already true of every login; this is what makes the
    rule bite for someone who has not enrolled yet.
    """

    __tablename__ = "known_devices"
    __table_args__ = (
        UniqueConstraint("user_id", "fingerprint", name="uq_known_device"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
