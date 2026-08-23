import asyncio
from uuid import UUID

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.entities import AuditAction, Document
from app.services import storage
from app.services.ai_pipeline import extract_text, redact_pii, generate_embedding
from app.services.audit import append_entry
from app.tasks.celery_app import celery_app


async def _process_document_async(document_id: str) -> None:
    async with AsyncSessionLocal() as session:
        document = await session.scalar(
            select(Document).where(Document.id == UUID(document_id))
        )
        if document is None:
            return

        try:
            file_bytes = storage.download_file(document.object_key)
            ocr_status, extracted_text = extract_text(file_bytes, document.content_type)

            if ocr_status == "ok" and extracted_text:
                redacted = redact_pii(extracted_text)
                embedding = generate_embedding(redacted)

                document.extracted_text_encrypted = extracted_text
                document.redacted_text = redacted
                document.embedding = embedding
                document.processing_status = "ready"
            else:
                document.redacted_text = None
                document.processing_status = "ready"

            await append_entry(
                session,
                action=AuditAction.document_processed,
                actor_id=document.uploaded_by_id,
                payload={"document_id": str(document.id), "ocr_status": ocr_status},
            )

        except Exception as error:
            document.processing_status = "failed"
            document.processing_error = str(error)

            await append_entry(
                session,
                action=AuditAction.document_processing_failed,
                actor_id=document.uploaded_by_id,
                payload={"document_id": str(document.id), "error": str(error)},
            )

        await session.commit()


@celery_app.task(name="process_document")
def process_document(document_id: str) -> None:
    asyncio.run(_process_document_async(document_id))