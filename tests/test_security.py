import os
from pathlib import Path
import subprocess
import sys

import pytest


def _register_and_login(client, email):
    client.post(
        "/api/auth/register",
        json={"email": email, "password": "secure-test-password-123"},
    )
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "secure-test-password-123"},
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_uploaded_document_is_private_and_requires_access(client, tmp_path):
    owner_headers = _register_and_login(client, "owner@example.com")
    stranger_headers = _register_and_login(client, "stranger@example.com")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("private.txt", b"private contents", "text/plain")},
    )
    assert upload.status_code == 201
    document = upload.json()
    assert document["filename"] == "private.txt"
    assert document["id"]

    denied = client.get(
        f"/api/documents/{document['id']}/download",
        headers=stranger_headers,
    )
    assert denied.status_code == 404
    stored_files = list((tmp_path / "private").iterdir())
    assert len(stored_files) == 1
    assert stored_files[0].read_bytes() == b"private contents"


def test_upload_rejects_unsupported_and_oversized_files(client, tmp_path):
    headers = _register_and_login(client, "owner@example.com")
    unsupported = client.post(
        "/api/documents",
        headers=headers,
        files={"file": ("script.exe", b"no", "application/octet-stream")},
    )
    assert unsupported.status_code == 415

    oversized = client.post(
        "/api/documents",
        headers=headers,
        files={"file": ("too-large.txt", b"x" * 1025, "text/plain")},
    )
    assert oversized.status_code == 413
    assert list((tmp_path / "private").iterdir()) == []


def test_upload_rejects_unsafe_names_and_mismatched_file_contents(client, tmp_path):
    headers = _register_and_login(client, "validation@example.com")
    unsafe_name = client.post(
        "/api/documents",
        headers=headers,
        files={"file": ("../private.txt", b"private", "text/plain")},
    )
    assert unsafe_name.status_code == 422
    mismatched_type = client.post(
        "/api/documents",
        headers=headers,
        files={"file": ("fake.pdf", b"not a PDF", "application/pdf")},
    )
    assert mismatched_type.status_code == 415
    assert list((tmp_path / "private").iterdir()) == []
    audit_actions = {
        event["action"]
        for event in client.get("/api/audit", headers=headers).json()
    }
    assert "document_upload_denied" in audit_actions


def test_document_search_filters_name_owner_category_and_date(client):
    headers = _register_and_login(client, "search-owner@example.com")
    for filename, content in (
        ("quarterly-report.txt", b"quarterly"),
        ("budget.csv", b"month,total\njan,2\n"),
    ):
        response = client.post(
            "/api/documents",
            headers=headers,
            files={"file": (filename, content, "text/plain")},
        )
        assert response.status_code == 201

    by_name = client.get("/api/documents", headers=headers, params={"q": "quarterly"})
    assert [item["filename"] for item in by_name.json()] == ["quarterly-report.txt"]
    by_owner = client.get("/api/documents", headers=headers, params={"owner": "search-owner"})
    assert len(by_owner.json()) == 2
    by_category = client.get("/api/documents", headers=headers, params={"category": "CSV"})
    assert [item["filename"] for item in by_category.json()] == ["budget.csv"]
    outside_date = client.get(
        "/api/documents",
        headers=headers,
        params={"since": "2099-01-01"},
    )
    assert outside_date.json() == []


def test_startup_rejects_public_static_upload_directory(monkeypatch, tmp_path):
    public_static = Path(__file__).resolve().parents[1] / "app" / "static"
    monkeypatch.setenv("TRUSTVAULT_SECRET_KEY", "test-only-secret-key-that-is-not-used-outside-tests")
    monkeypatch.setenv("TRUSTVAULT_DATABASE_URL", f"sqlite:///{tmp_path / 'unsafe.db'}")
    monkeypatch.setenv("TRUSTVAULT_UPLOAD_DIR", str(public_static))

    from app.config import get_settings
    from app.database import get_engine, initialize_database

    get_settings.cache_clear()
    get_engine.cache_clear()
    try:
        with pytest.raises(ValueError, match="outside the public static directory"):
            initialize_database()
    finally:
        get_engine.cache_clear()
        get_settings.cache_clear()


def test_setup_db_script_runs_from_project_root_with_isolated_database(tmp_path):
    project_root = Path(__file__).resolve().parents[1]
    database_path = tmp_path / "standalone-setup.db"
    upload_path = tmp_path / "standalone-private"
    environment = os.environ.copy()
    environment.update(
        {
            "TRUSTVAULT_SECRET_KEY": "test-only-secret-key-that-is-not-used-outside-tests",
            "TRUSTVAULT_DATABASE_URL": f"sqlite:///{database_path}",
            "TRUSTVAULT_UPLOAD_DIR": str(upload_path),
        }
    )

    result = subprocess.run(
        [sys.executable, str(project_root / "scripts" / "setup_db.py")],
        cwd=project_root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == (
        "TrustVault database and private storage directory are ready."
    )
    assert database_path.is_file()
    assert upload_path.is_dir()