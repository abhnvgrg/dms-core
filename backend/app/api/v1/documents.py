import hashlib
import io
import re
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.api.deps import get_current_user, require_fresh_mfa
from app.api.v1.cases import _get_case_if_authorized
from app.core.config import get_settings
from app.database import get_db
from app.models.entities import (
    AuditAction,
    Case,
    CaseAssignment,
    Document,
    DocumentAccessGrant,
    DocumentClassification,
    OfficerSigningKey,
    Role,
    User,
)
from app.schemas.documents import (
    AccessGrantRequest,
    AccessGrantResponse,
    DocumentSearchResult,
    DocumentStatusResponse,
    DocumentUploadResponse,
    EvidenceDetail,
    EvidenceSummary,
    ReclassifyRequest,
    VerifyResponse,
)
from app.services import (
    encryption,
    file_inspection,
    malware_scan,
    officer_keys,
    signing,
    storage,
)
from app.services.ai_pipeline import generate_embedding
from app.services.audit import append_entry
from app.tasks.document_processing import process_document

router = APIRouter(prefix="/documents", tags=["documents"])

MAX_UPLOAD_SIZE = 25 * 1024 * 1024
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "application/pdf"}
UPLOADER_ROLES = (Role.INVESTIGATING_OFFICER, Role.FORENSICS_OFFICER, Role.ADMIN)


def _safe_filename(filename: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    return name[-200:]


def _ocr_status(document: Document) -> str:
    if document.processing_status == "processing":
        return "pending"
    if document.processing_status == "failed":
        return "error"
    return "ok" if document.redacted_text else "unsupported"


async def _resolve_case(case_ref: str, current_user: User, session: AsyncSession) -> Case:
    try:
        case_id = UUID(case_ref)
    except ValueError:
        case = await session.scalar(
            select(Case).where(func.lower(Case.fir_number) == case_ref.strip().lower())
        )
        if case is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
        case_id = case.id

    return await _get_case_if_authorized(case_id, current_user, session)


async def _verify_document_signature(
    document: Document, session: AsyncSession
) -> tuple[bool, str | None, str | None]:
    """Re-check the upload signature against the key it was made with.

    Documents predating client-side key custody carry a server signature; those
    are reported as legacy rather than quietly treated as equivalent.
    """
    if not document.signature:
        return False, None, None

    if document.signing_key_id is None:
        return signing.verify_signature(document.sha256_hash, document.signature), None, "legacy_server_key"

    key = await session.get(OfficerSigningKey, document.signing_key_id)
    if key is None:
        return False, None, "missing"

    owner = await session.scalar(select(User).where(User.id == key.user_id))
    valid = officer_keys.verify_signature(key.public_key_pem, document.sha256_hash, document.signature)
    status_label = officer_keys.signature_status(key, document.created_at)

    return valid, owner.badge_number if owner else None, status_label


async def _enforce_classification(document: Document, current_user: User, session: AsyncSession) -> None:
    if current_user.role == Role.ADMIN:
        return

    if document.classification == DocumentClassification.ADMIN_ONLY:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if current_user.role != Role.COURT_OFFICIAL:
        return

    if document.classification == DocumentClassification.CASE_RESTRICTED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This document requires an access grant to view",
        )

    if document.classification == DocumentClassification.COURT_ELEVATED:
        grant = await session.scalar(
            select(DocumentAccessGrant).where(
                DocumentAccessGrant.document_id == document.id,
                DocumentAccessGrant.grantee_id == current_user.id,
                DocumentAccessGrant.revoked_at.is_(None),
                DocumentAccessGrant.expires_at > datetime.now(timezone.utc),
            )
        )
        if grant is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This document requires an active access grant to view",
            )


@router.post("/upload", response_model=DocumentUploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_document(
    case_id: str = Form(...),
    file: UploadFile = File(...),
    classification: str = Form(DocumentClassification.CASE_RESTRICTED.value),
    sha256_hash: str = Form(..., description="SHA-256 the client computed and signed"),
    client_signature: str = Form(..., description="Base64 RSA-PSS signature over that hash"),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DocumentUploadResponse:
    case = await _resolve_case(case_id, current_user, session)

    if current_user.role not in UPLOADER_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to upload documents",
        )

    try:
        classification_value = DocumentClassification(classification)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid classification")

    file_bytes = await file.read()

    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")

    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type")

    signing_key = await officer_keys.get_active_key(session, current_user.id)
    if signing_key is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "No active signing key for this officer. Generate one in the browser "
                "and register it at POST /api/v1/auth/signing-keys before uploading."
            ),
        )

    if get_settings().malware_scanning_enabled:
        try:
            malware_scan.scan_bytes(file_bytes)
        except malware_scan.MalwareDetected as detected:
            await append_entry(
                session,
                action=AuditAction.MALWARE_DETECTED,
                actor_id=current_user.id,
                payload={
                    "case_id": str(case.id),
                    "filename": file.filename or "upload",
                    "signature": detected.signature,
                },
            )
            await session.commit()
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Malware detected: {detected.signature}")
        except malware_scan.ScannerUnavailable:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Malware scanner unavailable, upload rejected")

    # Structural check before anything that parses the file. A PDF carrying
    # JavaScript never reaches OCR, NER or the embedding model.
    try:
        file_inspection.inspect(file_bytes, content_type)
    except file_inspection.FileRejected as rejected:
        await append_entry(
            session,
            action=AuditAction.FILE_REJECTED,
            actor_id=current_user.id,
            payload={
                "case_id": str(case.id),
                "filename": file.filename or "upload",
                "reason": rejected.reason,
            },
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"File rejected: {rejected.reason}",
        )

    computed_hash = hashlib.sha256(file_bytes).hexdigest()
    if computed_hash != sha256_hash.lower().strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded bytes do not match the hash the client signed",
        )

    if not officer_keys.verify_signature(signing_key.public_key_pem, computed_hash, client_signature):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Signature does not verify against your registered signing key",
        )

    sha256_hash = computed_hash
    signature = client_signature
    document_id = uuid4()
    safe_name = _safe_filename(file.filename or "upload")
    object_key = storage.build_object_key(case.id, document_id, safe_name)

    encrypted_bytes = await encryption.encrypt_bytes(session, file_bytes)
    storage.upload_file(object_key, encrypted_bytes, content_type)

    document = Document(
        id=document_id,
        case_id=case.id,
        uploaded_by_id=current_user.id,
        original_filename=file.filename or "upload",
        content_type=content_type,
        object_key=object_key,
        sha256_hash=sha256_hash,
        signature=signature,
        signing_key_id=signing_key.id,
        processing_status="processing",
        classification=classification_value,
    )
    session.add(document)

    await append_entry(
        session,
        action=AuditAction.DOCUMENT_UPLOADED,
        actor_id=current_user.id,
        payload={
            "document_id": str(document_id),
            "case_id": str(case.id),
            "sha256_hash": sha256_hash,
            "signing_key_fingerprint": signing_key.fingerprint,
        },
    )

    await session.commit()

    process_document.delay(str(document_id))

    return DocumentUploadResponse(
        id=document_id,
        case_id=case.fir_number,
        filename=document.original_filename,
        sha256_hash=sha256_hash,
        signature=signature,
        uploaded_by=current_user.full_name,
        uploaded_at=document.created_at,
        ocr_status=_ocr_status(document),
        classification=classification_value.value,
        redacted_text=document.redacted_text,
    )


@router.get("", response_model=list[EvidenceSummary])
async def list_documents(
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[EvidenceSummary]:
    query = (
        select(Document, Case.fir_number, User.full_name)
        .join(Case, Case.id == Document.case_id)
        .join(User, User.id == Document.uploaded_by_id)
    )
    if current_user.role != Role.ADMIN:
        query = query.join(
            CaseAssignment, CaseAssignment.case_id == Document.case_id
        ).where(CaseAssignment.user_id == current_user.id)
        query = query.where(Document.classification != DocumentClassification.ADMIN_ONLY)

    result = await session.execute(query.order_by(Document.created_at.desc()))

    return [
        EvidenceSummary(
            id=document.id,
            case_id=fir_number,
            filename=document.original_filename,
            sha256_hash=document.sha256_hash,
            uploaded_by=full_name,
            uploaded_at=document.created_at,
            ocr_status=_ocr_status(document),
        )
        for document, fir_number, full_name in result.unique().all()
    ]


@router.get("/search", response_model=list[DocumentSearchResult])
async def search_documents(
    q: str = Query(..., min_length=1),
    case_id: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[DocumentSearchResult]:
    query_vector = generate_embedding(q)
    if query_vector is None:
        return []

    query = (
        select(
            Document,
            Case.fir_number,
            User.full_name,
            Document.embedding.cosine_distance(query_vector).label("distance"),
        )
        .join(Case, Case.id == Document.case_id)
        .join(User, User.id == Document.uploaded_by_id)
        .where(Document.embedding.isnot(None))
    )

    if current_user.role != Role.ADMIN:
        query = query.join(
            CaseAssignment, CaseAssignment.case_id == Document.case_id
        ).where(CaseAssignment.user_id == current_user.id)
        query = query.where(Document.classification != DocumentClassification.ADMIN_ONLY)

    if case_id:
        case = await _resolve_case(case_id, current_user, session)
        query = query.where(Document.case_id == case.id)

    query = query.order_by("distance").limit(limit)

    result = await session.execute(query)

    results: list[DocumentSearchResult] = []
    # A Court Official searching sees that a document exists, not what is in it.
    # Content for them is gated behind an explicit, time-bound grant instead.
    metadata_only = current_user.role == Role.COURT_OFFICIAL

    for document, fir_number, full_name, distance in result.unique().all():
        snippet = None
        if not metadata_only:
            redacted = await encryption.decrypt_text(session, document.redacted_text)
            snippet = f"{redacted[:240]}..." if redacted and len(redacted) > 240 else redacted
        results.append(
            DocumentSearchResult(
                id=document.id,
                case_id=fir_number,
                filename=document.original_filename,
                uploaded_by=full_name,
                uploaded_at=document.created_at,
                ocr_status=_ocr_status(document),
                snippet=snippet,
                score=max(0.0, 1.0 - float(distance)),
            )
        )
    return results


@router.get("/{document_id}", response_model=EvidenceDetail)
async def get_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> EvidenceDetail:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    case = await _get_case_if_authorized(document.case_id, current_user, session)
    await _enforce_classification(document, current_user, session)
    uploader = await session.scalar(select(User).where(User.id == document.uploaded_by_id))

    extracted_text = None
    if document.classification != DocumentClassification.PUBLIC_REDACTED:
        extracted_text = await encryption.decrypt_text(session, document.extracted_text_encrypted)

    return EvidenceDetail(
        id=document.id,
        case_id=case.fir_number,
        filename=document.original_filename,
        sha256_hash=document.sha256_hash,
        uploaded_by=uploader.full_name if uploader else "Unknown",
        uploaded_at=document.created_at,
        ocr_status=_ocr_status(document),
        signature=document.signature,
        classification=document.classification.value,
        extracted_text=extracted_text,
        redacted_text=await encryption.decrypt_text(session, document.redacted_text),
    )


@router.get("/{document_id}/download")
async def download_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)
    await _enforce_classification(document, current_user, session)

    try:
        encrypted_bytes = storage.download_file(document.object_key)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Stored file could not be located")

    file_bytes = await encryption.decrypt_bytes(session, encrypted_bytes)

    await append_entry(
        session,
        action=AuditAction.DOCUMENT_DOWNLOADED,
        actor_id=current_user.id,
        payload={"document_id": str(document.id), "case_id": str(document.case_id)},
    )
    await session.commit()

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type=document.content_type,
        headers={"Content-Disposition": f'attachment; filename="{document.original_filename}"'},
    )


@router.patch("/{document_id}/classification", response_model=EvidenceDetail)
async def reclassify_document(
    document_id: UUID,
    payload: ReclassifyRequest,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> EvidenceDetail:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    case = await _get_case_if_authorized(document.case_id, current_user, session)
    if current_user.role not in (Role.INVESTIGATING_OFFICER, Role.ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an investigating officer or admin can reclassify a document")

    try:
        new_classification = DocumentClassification(payload.classification)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid classification")

    previous_classification = document.classification
    document.classification = new_classification

    await append_entry(
        session,
        action=AuditAction.DOCUMENT_RECLASSIFIED,
        actor_id=current_user.id,
        payload={
            "document_id": str(document.id),
            "case_id": str(document.case_id),
            "from": previous_classification.value,
            "to": new_classification.value,
        },
    )
    await session.commit()
    await session.refresh(document)

    uploader = await session.scalar(select(User).where(User.id == document.uploaded_by_id))
    extracted_text = None
    if document.classification != DocumentClassification.PUBLIC_REDACTED:
        extracted_text = await encryption.decrypt_text(session, document.extracted_text_encrypted)

    return EvidenceDetail(
        id=document.id,
        case_id=case.fir_number,
        filename=document.original_filename,
        sha256_hash=document.sha256_hash,
        uploaded_by=uploader.full_name if uploader else "Unknown",
        uploaded_at=document.created_at,
        ocr_status=_ocr_status(document),
        signature=document.signature,
        classification=document.classification.value,
        extracted_text=extracted_text,
        redacted_text=await encryption.decrypt_text(session, document.redacted_text),
    )


@router.post("/{document_id}/access-grants", response_model=AccessGrantResponse, status_code=status.HTTP_201_CREATED)
async def create_access_grant(
    document_id: UUID,
    payload: AccessGrantRequest,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> AccessGrantResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)
    if current_user.role not in (Role.INVESTIGATING_OFFICER, Role.ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an investigating officer or admin can grant document access")

    grantee = await session.scalar(select(User).where(User.badge_number == payload.grantee_badge_number))
    if grantee is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Grantee not found")

    grant = DocumentAccessGrant(
        document_id=document.id,
        grantee_id=grantee.id,
        granted_by_id=current_user.id,
        reason=payload.reason,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=payload.duration_hours),
    )
    session.add(grant)
    await session.flush()

    await append_entry(
        session,
        action=AuditAction.ACCESS_GRANTED,
        actor_id=current_user.id,
        payload={
            "document_id": str(document.id),
            "case_id": str(document.case_id),
            "grantee_id": str(grantee.id),
            "reason": payload.reason,
        },
    )
    await session.commit()

    return AccessGrantResponse(
        id=grant.id,
        document_id=grant.document_id,
        grantee_badge_number=grantee.badge_number,
        granted_by_badge_number=current_user.badge_number,
        reason=grant.reason,
        expires_at=grant.expires_at,
        revoked_at=grant.revoked_at,
    )


@router.get("/{document_id}/access-grants", response_model=list[AccessGrantResponse])
async def list_access_grants(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> list[AccessGrantResponse]:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)

    Grantee = aliased(User)
    Granter = aliased(User)
    result = await session.execute(
        select(DocumentAccessGrant, Grantee.badge_number, Granter.badge_number)
        .join(Grantee, Grantee.id == DocumentAccessGrant.grantee_id)
        .join(Granter, Granter.id == DocumentAccessGrant.granted_by_id)
        .where(DocumentAccessGrant.document_id == document_id)
        .order_by(DocumentAccessGrant.created_at.desc())
    )

    return [
        AccessGrantResponse(
            id=grant.id,
            document_id=grant.document_id,
            grantee_badge_number=grantee_badge_number,
            granted_by_badge_number=granter_badge_number,
            reason=grant.reason,
            expires_at=grant.expires_at,
            revoked_at=grant.revoked_at,
        )
        for grant, grantee_badge_number, granter_badge_number in result.all()
    ]


@router.post("/{document_id}/access-grants/{grant_id}/revoke", response_model=AccessGrantResponse)
async def revoke_access_grant(
    document_id: UUID,
    grant_id: UUID,
    current_user: User = Depends(require_fresh_mfa),
    session: AsyncSession = Depends(get_db),
) -> AccessGrantResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)
    if current_user.role not in (Role.INVESTIGATING_OFFICER, Role.ADMIN):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Only an investigating officer or admin can revoke document access")

    grant = await session.scalar(
        select(DocumentAccessGrant).where(
            DocumentAccessGrant.id == grant_id, DocumentAccessGrant.document_id == document_id
        )
    )
    if grant is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Access grant not found")

    grant.revoked_at = datetime.now(timezone.utc)

    await append_entry(
        session,
        action=AuditAction.ACCESS_REVOKED,
        actor_id=current_user.id,
        payload={
            "document_id": str(document.id),
            "case_id": str(document.case_id),
            "grantee_id": str(grant.grantee_id),
        },
    )
    await session.commit()

    grantee = await session.scalar(select(User).where(User.id == grant.grantee_id))

    return AccessGrantResponse(
        id=grant.id,
        document_id=grant.document_id,
        grantee_badge_number=grantee.badge_number if grantee else "unknown",
        granted_by_badge_number=current_user.badge_number,
        reason=grant.reason,
        expires_at=grant.expires_at,
        revoked_at=grant.revoked_at,
    )


@router.get("/{document_id}/status", response_model=DocumentStatusResponse)
async def get_document_status(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DocumentStatusResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)
    return DocumentStatusResponse.model_validate(document)


@router.post("/{document_id}/verify", response_model=VerifyResponse)
async def verify_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> VerifyResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)

    try:
        encrypted_bytes = storage.download_file(document.object_key)
        file_bytes = await encryption.decrypt_bytes(session, encrypted_bytes)
    except FileNotFoundError:
        return VerifyResponse(
            evidence_id=document.id,
            filename=document.original_filename,
            integrity="FAILED",
            reason="Stored file could not be located in object storage",
        )

    recomputed_hash = hashlib.sha256(file_bytes).hexdigest()
    hash_match = recomputed_hash == document.sha256_hash

    signature_valid, signed_by, key_status = await _verify_document_signature(document, session)
    integrity = "VERIFIED" if hash_match and signature_valid else "TAMPERED"
    if integrity == "VERIFIED" and key_status == "pending_review":
        integrity = "PENDING_REVIEW"

    await append_entry(
        session,
        action=AuditAction.INTEGRITY_VERIFIED,
        actor_id=current_user.id,
        payload={"document_id": str(document.id), "case_id": str(document.case_id), "integrity": integrity},
    )
    await session.commit()

    return VerifyResponse(
        evidence_id=document.id,
        filename=document.original_filename,
        original_hash=document.sha256_hash,
        recomputed_hash=recomputed_hash,
        hash_match=hash_match,
        signature_valid=signature_valid,
        signed_by=signed_by,
        signing_key_status=key_status,
        integrity=integrity,
    )
