import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_SECRET_KEY", "test-only-secret-key-that-is-not-used-outside-tests")
    monkeypatch.setenv("TRUSTVAULT_DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    monkeypatch.setenv("TRUSTVAULT_UPLOAD_DIR", str(tmp_path / "private"))
    monkeypatch.setenv("TRUSTVAULT_MAX_UPLOAD_BYTES", "1024")

    from app.config import get_settings
    from app.database import Base, get_engine
    from app.main import app
    from app import models  # noqa: F401

    get_settings.cache_clear()
    get_engine.cache_clear()
    Base.metadata.create_all(bind=get_engine())

    with TestClient(app) as test_client:
        yield test_client

    Base.metadata.drop_all(bind=get_engine())
    get_engine().dispose()
    get_engine.cache_clear()
    get_settings.cache_clear()