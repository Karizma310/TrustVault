from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from pydantic import (
    AliasChoices,
    EmailStr,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    secret_key: SecretStr = Field(
        validation_alias=AliasChoices("TRUSTVAULT_SECRET_KEY", "SECRET_KEY")
    )
    database_url: str = "sqlite:///./trustvault.db"
    upload_dir: Path = Path("private_uploads")
    max_upload_bytes: int = 25 * 1024 * 1024
    access_token_minutes: int = 30
    password_reset_minutes: int = 30
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: SecretStr | None = None
    smtp_from_email: EmailStr | None = None
    google_client_id: str | None = None
    google_client_secret: SecretStr | None = None
    google_redirect_uri: str | None = None
    frontend_login_url: str = "http://127.0.0.1:8001/app/templates/login.html"
    cors_origins: str = "http://127.0.0.1:8001,http://localhost:8001"

    model_config = SettingsConfigDict(
        env_prefix="TRUSTVAULT_",
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("frontend_login_url")
    @classmethod
    def require_http_frontend_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("TRUSTVAULT_FRONTEND_LOGIN_URL must be an absolute HTTP(S) URL.")
        if parsed.fragment:
            raise ValueError("TRUSTVAULT_FRONTEND_LOGIN_URL must not include a fragment.")
        return value

    @field_validator("google_client_secret", mode="before")
    @classmethod
    def empty_google_client_secret_is_unset(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("google_redirect_uri")
    @classmethod
    def validate_google_redirect_uri(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        parsed = urlparse(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.path != "/api/auth/google/callback"
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError(
                "TRUSTVAULT_GOOGLE_REDIRECT_URI must point to /api/auth/google/callback."
            )
        if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
            raise ValueError("HTTP is allowed only for local Google OAuth development.")
        return value

    @field_validator("secret_key")
    @classmethod
    def require_secret_length(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if len(secret) < 32 or secret.casefold().startswith("replace-"):
            raise ValueError("TRUSTVAULT_SECRET_KEY must contain at least 32 characters.")
        return value

    @field_validator("database_url")
    @classmethod
    def require_supported_database(cls, value: str) -> str:
        if value.startswith("postgresql://"):
            return value.replace("postgresql://", "postgresql+psycopg://", 1)
        if value.startswith("postgres://"):
            return value.replace("postgres://", "postgresql+psycopg://", 1)
        if not value.startswith(("sqlite:///", "postgresql+psycopg://")):
            raise ValueError("The database URL must use SQLite or PostgreSQL with psycopg.")
        return value

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, value: str) -> str:
        normalized_origins = []
        for origin in (item.strip() for item in value.split(",")):
            if not origin:
                continue
            parsed = urlparse(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("TRUSTVAULT_CORS_ORIGINS must be comma-separated HTTP(S) origins.")
            normalized_origins.append(f"{parsed.scheme}://{parsed.netloc}")
        return ",".join(dict.fromkeys(normalized_origins))

    @field_validator("max_upload_bytes", "access_token_minutes")
    @classmethod
    def require_positive_values(cls, value: int) -> int:
        if value < 1:
            raise ValueError("This setting must be greater than zero.")
        return value

    @field_validator("smtp_host", "smtp_username", mode="before")
    @classmethod
    def blank_mail_settings_are_unset(cls, value: str | None) -> str | None:
        return value.strip() or None if isinstance(value, str) else value

    @field_validator("smtp_password", mode="before")
    @classmethod
    def blank_smtp_password_is_unset(cls, value: str | None) -> str | None:
        return value or None

    @field_validator("smtp_port", "password_reset_minutes")
    @classmethod
    def require_positive_mail_values(cls, value: int) -> int:
        if value < 1:
            raise ValueError("This setting must be greater than zero.")
        return value

    @model_validator(mode="after")
    def require_complete_smtp_authentication(self):
        if bool(self.smtp_username) != bool(self.smtp_password):
            raise ValueError(
                "TRUSTVAULT_SMTP_USERNAME and TRUSTVAULT_SMTP_PASSWORD must be set together."
            )
        return self

    @property
    def password_reset_email_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_from_email)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()