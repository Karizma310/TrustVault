import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_engine
from app.models.document import Document
from app.models.user import User


def _create_account(client, email):
    password = "demo-test-password-123"
    registered = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    assert registered.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _run_seed_script(project_root, environment, admin_email, owner_email, viewer_email):
    return subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "seed_data.py"),
            "--admin-email",
            admin_email,
            "--owner-email",
            owner_email,
            "--viewer-email",
            viewer_email,
        ],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_demo_seed_creates_private_samples_and_read_only_access(client):
    admin_email = "demo-admin@example.com"
    owner_email = "demo-owner@example.com"
    viewer_email = "demo-viewer@example.com"
    admin_headers = _create_account(client, admin_email)
    owner_headers = _create_account(client, owner_email)
    viewer_headers = _create_account(client, viewer_email)

    with Session(get_engine()) as db:
        admin = db.scalar(select(User).where(User.email == admin_email))
        owner = db.scalar(select(User).where(User.email == owner_email))
        viewer = db.scalar(select(User).where(User.email == viewer_email))
        assert admin is not None
        assert owner is not None and viewer is not None
        password_hashes_before = {
            admin.id: admin.password_hash,
            owner.id: owner.password_hash,
            viewer.id: viewer.password_hash,
        }
        admin.role = "admin"
        db.commit()

    project_root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    result = _run_seed_script(
        project_root,
        environment,
        admin_email,
        owner_email,
        viewer_email,
    )
    assert result.returncode == 0, result.stderr
    assert "No passwords were created or changed." in result.stdout

    owned = client.get("/api/documents", headers=owner_headers)
    assert owned.status_code == 200
    assert len(owned.json()) == 2
    documents = {item["title"]: item for item in owned.json()}
    private_document = documents["Demo: owner-only document"]
    shared_document = documents["Demo: shared read-only document"]

    assert client.get("/api/documents", headers=viewer_headers).json() == []
    shared = client.get("/api/documents/shared-with-me", headers=viewer_headers)
    assert [item["id"] for item in shared.json()] == [shared_document["id"]]
    assert client.get(
        f"/api/documents/{shared_document['id']}/download",
        headers=viewer_headers,
    ).content.startswith(b"TrustVault demo file")
    assert client.get(
        f"/api/documents/{private_document['id']}/download",
        headers=owner_headers,
    ).status_code == 200
    assert client.get(
        f"/api/documents/{private_document['id']}/download",
        headers=viewer_headers,
    ).status_code == 404
    assert client.get("/api/notifications", headers=viewer_headers).json()["total_count"] == 1

    # Administrator status does not grant access to an owner's private documents.
    assert client.get(
        f"/api/documents/{shared_document['id']}/download",
        headers=admin_headers,
    ).status_code == 404

    audit = client.get("/api/admin/audit?limit=500", headers=admin_headers)
    assert audit.status_code == 200
    actions = [entry["action"] for entry in audit.json()]
    assert actions.count("demo_document_seeded") == 2
    assert "document_access_granted" in actions
    assert "document_access_denied" in actions

    rerun = _run_seed_script(
        project_root,
        environment,
        admin_email,
        owner_email,
        viewer_email,
    )
    assert rerun.returncode == 0, rerun.stderr
    assert len(client.get("/api/documents", headers=owner_headers).json()) == 2
    assert client.get("/api/notifications", headers=viewer_headers).json()["total_count"] == 1
    with Session(get_engine()) as db:
        assert {
            user.id: user.password_hash
            for user in db.scalars(select(User))
            if user.id in password_hashes_before
        } == password_hashes_before


def test_demo_seed_refuses_to_assign_admin_and_leaves_data_untouched(client):
    admin_email = "not-an-admin@example.com"
    owner_email = "seed-owner@example.com"
    viewer_email = "seed-viewer@example.com"
    _create_account(client, admin_email)
    _create_account(client, owner_email)
    _create_account(client, viewer_email)

    project_root = Path(__file__).resolve().parents[1]
    result = _run_seed_script(
        project_root,
        os.environ.copy(),
        admin_email,
        owner_email,
        viewer_email,
    )

    assert result.returncode != 0
    assert "selected Admin account is not an administrator" in result.stderr
    with Session(get_engine()) as db:
        assert db.scalar(select(Document.id)) is None
        admin = db.scalar(select(User).where(User.email == admin_email))
        assert admin is not None and admin.role == "user"
    assert list(get_settings().upload_dir.iterdir()) == []
