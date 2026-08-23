import hashlib
import re
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.api.v1.cases import _get_case_if_authorized
from app.database import get_db
from app.models.entities import AuditAction, Document, Role, User
from app.schemas.documents import DocumentResponse, DocumentStatusResponse, DocumentUploadResponse
from app.services import storage
from app.services.audit import append_entry
from app.tasks.document_processing import process_document

router = APIRouter(prefix="/documents", tags=["documents"])

MAX_UPLOAD_SIZE = 25 * 1024 * 1024
ALLOWED_CONTENT_TYPES = {"image/jpeg", "image/png", "application/pdf"}


def _safe_filename(filename: str) -> str:
    name = re.sub(r"[^A-Za-z0-9._-]", "_", filename)
    return name[-200:]


@router.post("/upload", response_model=DocumentUploadResponse, status_code=status.HTTP_202_ACCEPTED)
async def upload_document(
    case_id: UUID = Form(...),
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DocumentUploadResponse:
    await _get_case_if_authorized(case_id, current_user, session)

    if current_user.role not in (Role.investigating_officer, Role.forensics_officer, Role.admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have permission to upload documents",
        )

    file_bytes = await file.read()

    if len(file_bytes) > MAX_UPLOAD_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large")

    content_type = file.content_type or "application/octet-stream"
    if content_type not in ALLOWED_CONTENT_TYPES:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Unsupported file type")

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    document_id = uuid4()
    safe_name = _safe_filename(file.filename or "upload")
    object_key = storage.build_object_key(case_id, document_id, safe_name)

    storage.upload_file(object_key, file_bytes, content_type)

    document = Document(
        id=document_id,
        case_id=case_id,
        uploaded_by_id=current_user.id,
        original_filename=file.filename or "upload",
        content_type=content_type,
        object_key=object_key,
        sha256_hash=sha256_hash,
        processing_status="processing",
    )
    session.add(document)

    await append_entry(
        session,
        action=AuditAction.document_uploaded,
        actor_id=current_user.id,
        payload={"document_id": str(document_id), "case_id": str(case_id), "sha256_hash": sha256_hash},
    )

    await session.commit()

    process_document.delay(str(document_id))

    return DocumentUploadResponse(id=document_id, case_id=case_id, processing_status="processing")


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: UUID,
    current_user: User = Depends(get_current_user),
    session: AsyncSession = Depends(get_db),
) -> DocumentResponse:
    document = await session.scalar(select(Document).where(Document.id == document_id))
    if document is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    await _get_case_if_authorized(document.case_id, current_user, session)
    return DocumentResponse.model_validate(document)


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