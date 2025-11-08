from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "AAA RBAC Service"
    environment: str = "development"
    database_url: str = (
        "postgresql+asyncpg://aaa_user:aaa_password@localhost:5432/aaa_db"
    )
    log_file_path: str = "logs/audit.log"
    log_to_database: bool = True
    log_to_file: bool = True
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost", "http://localhost:8000"])
    access_token_expire_minutes: int = 30
    refresh_token_expire_minutes: int = 60 * 24 * 14
    jwt_secret: str = "replace-me"
    jwt_algorithm: str = "HS256"
    session_secret: str = "replace-me-too"
    brute_force_threshold: int = 5
    brute_force_window_seconds: int = 300
    db_init_max_attempts: int = 10
    db_init_retry_seconds: float = 3.0

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value: Any) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("log_to_database", "log_to_file", mode="before")
    @classmethod
    def parse_bool(cls, value: Any) -> bool:
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @field_validator("log_file_path", mode="after")
    @classmethod
    def ensure_log_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            path = Path.cwd() / path
        path.parent.mkdir(parents=True, exist_ok=True)
        return str(path)


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
