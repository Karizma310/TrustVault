from collections.abc import Generator
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from sqlalchemy import Engine, create_engine, event, inspect, text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.orm import DeclarativeBase, Session
from sqlalchemy.types import DateTime, TypeDecorator

from app.config import get_settings

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Base(DeclarativeBase):
    pass


class UTCDateTime(TypeDecorator[datetime]):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None or value.tzinfo is None:
            return value
        utc_value = value.astimezone(timezone.utc)
        if dialect.name == "sqlite":
            return utc_value.replace(tzinfo=None)
        return utc_value

    def process_result_value(self, value: datetime | None, _dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    database_url = _resolve_database_url(get_settings().database_url)
    connect_args = {"check_same_thread": False} if database_url.get_backend_name() == "sqlite" else {}
    engine = create_engine(database_url, connect_args=connect_args)

    if engine.dialect.name == "sqlite":
        @event.listens_for(engine, "connect")
        def enable_sqlite_foreign_keys(connection, _connection_record) -> None:
            cursor = connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    return engine


def _resolve_database_url(database_url: str) -> URL:
    url = make_url(database_url)
    if (
        url.get_backend_name() != "sqlite"
        or not url.database
        or url.database == ":memory:"
        or url.query.get("uri") == "true"
    ):
        return url

    database_path = Path(url.database)
    if not database_path.is_absolute():
        database_path = (PROJECT_ROOT / database_path).resolve()
        return url.set(database=str(database_path))
    return url


def get_db() -> Generator[Session, None, None]:
    with Session(get_engine()) as session:
        yield session


def initialize_database() -> None:
    configured_upload_dir = get_settings().upload_dir
    upload_dir = (
        configured_upload_dir
        if configured_upload_dir.is_absolute()
        else (PROJECT_ROOT / configured_upload_dir).resolve()
    )
    public_static_dir = (Path(__file__).resolve().parent / "static").resolve()
    if upload_dir == public_static_dir or public_static_dir in upload_dir.parents:
        raise ValueError("Uploaded documents must be stored outside the public static directory.")
    upload_dir.mkdir(parents=True, exist_ok=True)
    from app import models  # noqa: F401

    engine = get_engine()
    Base.metadata.create_all(bind=engine)
    _migrate_user_display_name(engine)
    _migrate_user_preferences(engine)
    _migrate_user_role(engine)
    _protect_audit_logs(engine)


def _migrate_user_display_name(engine: Engine) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "display_name" not in columns:
        with engine.begin() as connection:
            connection.execute(text("ALTER TABLE users ADD COLUMN display_name VARCHAR(100)"))


def _migrate_user_preferences(engine: Engine) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    statements = []
    if "notifications_enabled" not in columns:
        statements.append(
            "ALTER TABLE users ADD COLUMN notifications_enabled BOOLEAN NOT NULL DEFAULT TRUE"
        )
    if "theme" not in columns:
        statements.append("ALTER TABLE users ADD COLUMN theme VARCHAR(10) NOT NULL DEFAULT 'light'")
    if statements:
        with engine.begin() as connection:
            for statement in statements:
                connection.execute(text(statement))


def _migrate_user_role(engine: Engine) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns("users")}
    if "role" not in columns:
        with engine.begin() as connection:
            connection.execute(
                text("ALTER TABLE users ADD COLUMN role VARCHAR(16) NOT NULL DEFAULT 'user'")
            )


def _protect_audit_logs(engine: Engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
                BEFORE UPDATE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit records are append-only');
                END
                """
            )
        )
        connection.execute(
            text(
                """
                CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
                BEFORE DELETE ON audit_logs
                BEGIN
                    SELECT RAISE(ABORT, 'audit records are append-only');
                END
                """
            )
        )