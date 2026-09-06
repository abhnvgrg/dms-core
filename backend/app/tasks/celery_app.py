from celery import Celery

from app.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "nyayvault",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.tasks.document_processing",
        "app.tasks.blockchain_anchor",
        "app.tasks.retention_purge",
        "app.tasks.audit_checkpoint",
        "app.tasks.grant_expiry",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

celery_app.conf.beat_schedule = {
    "purge-expired-documents": {
        "task": "purge_expired_documents",
        "schedule": 30.0,
    },
    "create-audit-checkpoint": {
        "task": "create_audit_checkpoint",
        "schedule": 60.0,
    },
    "expire-access-grants": {
        "task": "expire_access_grants",
        "schedule": 60.0,
    },
}
