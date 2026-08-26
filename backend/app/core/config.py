from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NyayVault API"
    environment: str = "development"
    cors_origins: str = "http://localhost:3000"

    database_url: str
    redis_url: str = "redis://localhost:6379/0"

    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/0"

    minio_endpoint: str = "localhost:9000"
    minio_access_key: str
    minio_secret_key: str
    minio_bucket: str = "nyayvault-evidence"
    minio_checkpoint_bucket: str = "nyayvault-audit-checkpoints"
    minio_secure: bool = False

    root_encryption_key: str

    blockchain_rpc_url: str = "http://localhost:8545"
    blockchain_chain_id: int = 1337
    blockchain_contract_address: str | None = None
    blockchain_deployer_private_key: str | None = None
    blockchain_anchoring_enabled: bool = True

    clamav_host: str = "localhost"
    clamav_port: int = 3310
    malware_scanning_enabled: bool = True

    mfa_issuer: str = "NyayVault"


@lru_cache
def get_settings() -> Settings:
    return Settings()