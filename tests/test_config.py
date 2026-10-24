import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url

from app.config import Settings


TEST_SECRET_KEY = "test-only-secret-key-for-settings-validation"


@pytest.mark.parametrize(
    ("database_url", "expected_driver"),
    [
        ("sqlite:///./trustvault.db", "sqlite"),
        ("postgresql://user:password@db.example.test:5432/trustvault", "postgresql+psycopg"),
        ("postgres://user:password@db.example.test:5432/trustvault", "postgresql+psycopg"),
        (
            "postgresql+psycopg://user:password@db.example.test:5432/trustvault",
            "postgresql+psycopg",
        ),
    ],
)
def test_database_url_supports_sqlite_and_psycopg(database_url, expected_driver):
    settings = Settings(
        secret_key=TEST_SECRET_KEY,
        database_url=database_url,
        _env_file=None,
    )

    url = make_url(settings.database_url)
    assert url.drivername == expected_driver
    engine = create_engine(settings.database_url)
    try:
        assert engine.dialect.name == url.get_backend_name()
        assert engine.dialect.driver == url.get_driver_name()
    finally:
        engine.dispose()


def test_database_url_rejects_unsupported_driver():
    with pytest.raises(ValidationError, match="must use SQLite or PostgreSQL with psycopg"):
        Settings(
            secret_key=TEST_SECRET_KEY,
            database_url="mysql://user:password@db.example.test/trustvault",
            _env_file=None,
        )
