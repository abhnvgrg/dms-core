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
        # Runs every 30s so a short demo retention window (e.g. 2 minutes)
        # actually gets swept automatically within a live demo. A real
        # deployment with day-scale retention could relax this to hourly/daily.
        "schedule": 30.0,
    },
    "create-audit-checkpoint": {
        "task": "create_audit_checkpoint",
        # Checked every minute; the task itself decides whether a checkpoint is
        # due, on entry count or elapsed time (see app/services/checkpoints.py).
        # Those thresholds are the detection window: tampering is caught at the
        # next checkpoint, so lowering them narrows the gap at the cost of more
        # signing work and more objects in the write-once bucket.
        "schedule": 60.0,
    },
    "expire-access-grants": {
        "task": "expire_access_grants",
        "schedule": 60.0,
    },
}
