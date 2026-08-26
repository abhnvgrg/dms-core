import io
from uuid import UUID

from minio import Minio
from minio.error import S3Error

from app.core.config import get_settings

settings = get_settings()

_client = Minio(
    settings.minio_endpoint,
    access_key=settings.minio_access_key,
    secret_key=settings.minio_secret_key,
    secure=settings.minio_secure,
)


def ensure_bucket_exists() -> None:
    if not _client.bucket_exists(settings.minio_bucket):
        _client.make_bucket(settings.minio_bucket)


def build_object_key(case_id: UUID, document_id: UUID, safe_filename: str) -> str:
    return f"cases/{case_id}/documents/{document_id}/{safe_filename}"


def upload_file(object_key: str, data: bytes, content_type: str) -> None:
    ensure_bucket_exists()
    _client.put_object(
        settings.minio_bucket,
        object_key,
        data=io.BytesIO(data),
        length=len(data),
        content_type=content_type,
    )


def delete_file(object_key: str) -> None:
    try:
        _client.remove_object(settings.minio_bucket, object_key)
    except S3Error as error:
        raise FileNotFoundError(f"Object not found: {object_key}") from error


def download_file(object_key: str) -> bytes:
    response = None
    try:
        response = _client.get_object(settings.minio_bucket, object_key)
        return response.read()
    except S3Error as error:
        raise FileNotFoundError(f"Object not found: {object_key}") from error
    finally:
        if response is not None:
            response.close()
            response.release_conn()

def ensure_checkpoint_bucket_exists() -> None:
    """A second bucket, object-locked so checkpoints can be written but not replaced.

    Object lock can only be turned on at creation time, so an existing bucket is
    left as-is rather than silently pretending to be write-once.
    """
    if _client.bucket_exists(settings.minio_checkpoint_bucket):
        return

    try:
        _client.make_bucket(settings.minio_checkpoint_bucket, object_lock=True)
    except (S3Error, ValueError):
        # Object lock needs a MinIO deployment with versioning support; fall
        # back to a plain bucket rather than losing the checkpoint entirely.
        _client.make_bucket(settings.minio_checkpoint_bucket)


def put_checkpoint(checkpoint_id: int, data: bytes) -> str:
    ensure_checkpoint_bucket_exists()
    object_key = f"checkpoints/{checkpoint_id:012d}.json"
    _client.put_object(
        settings.minio_checkpoint_bucket,
        object_key,
        data=io.BytesIO(data),
        length=len(data),
        content_type="application/json",
    )
    return object_key


def get_checkpoint(object_key: str) -> bytes:
    response = None
    try:
        response = _client.get_object(settings.minio_checkpoint_bucket, object_key)
        return response.read()
    except S3Error as error:
        raise FileNotFoundError(f"Checkpoint not found: {object_key}") from error
    finally:
        if response is not None:
            response.close()
            response.release_conn()
