import subprocess
import sys
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_engine
from app.models.audit_log import AuditLog
from app.models.user import User


def _register_and_login(client, email):
    assert client.post(
        "/api/auth/register",
        json={"email": email, "password": "secure-test-password-123"},
    ).status_code == 201
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": "secure-test-password-123"},
    )
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def test_role_values_from_requests_are_ignored_and_admin_routes_are_protected(client):
    registration = client.post(
        "/api/auth/register",
        json={
            "email": "roles@example.com",
            "password": "secure-test-password-123",
            "role": "admin",
        },
    )
    assert registration.status_code == 201
    user_login = client.post(
        "/api/auth/login",
        json={"email": "roles@example.com", "password": "secure-test-password-123"},
    )
    user_headers = {"Authorization": f"Bearer {user_login.json()['access_token']}"}
    profile = client.get("/api/auth/me", headers=user_headers)
    assert profile.status_code == 200
    assert profile.json()["role"] == "user"

    forged_profile = client.patch(
        "/api/auth/me",
        headers=user_headers,
        json={"role": "admin", "display_name": "Regular user"},
    )
    assert forged_profile.status_code == 200
    assert forged_profile.json()["role"] == "user"
    assert client.get("/api/admin/audit", headers=user_headers).status_code == 403

    with Session(get_engine()) as db:
        user = db.scalar(select(User).where(User.email == "roles@example.com"))
        assert user is not None
        user.role = "admin"
        db.commit()

    admin_profile = client.get("/api/auth/me", headers=user_headers)
    assert admin_profile.json()["role"] == "admin"
    admin_events = client.get("/api/admin/audit", headers=user_headers)
    assert admin_events.status_code == 200
    assert {event["action"] for event in admin_events.json()} >= {
        "user_registered",
        "user_logged_in",
    }

    client.post(
        "/api/auth/register",
        json={"email": "private-owner@example.com", "password": "secure-test-password-123"},
    )
    owner_login = client.post(
        "/api/auth/login",
        json={"email": "private-owner@example.com", "password": "secure-test-password-123"},
    )
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}
    uploaded = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("admin-private.txt", b"not admin content", "text/plain")},
    )
    document_id = uploaded.json()["id"]
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=user_headers,
    ).status_code == 404


def test_role_assignment_script_promotes_only_target_and_admin_routes_work(client):
    target_email = "promoted-by-script@example.com"
    normal_email = "remains-user@example.com"
    target_headers = _register_and_login(client, target_email)
    normal_headers = _register_and_login(client, normal_email)

    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "set_admin_role.py"),
            target_email,
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    assert client.get("/api/auth/me", headers=target_headers).json()["role"] == "admin"
    assert client.get("/api/admin/login-activity", headers=target_headers).status_code == 200
    assert client.get("/api/admin/users", headers=target_headers).status_code == 200
    assert client.get("/api/admin/login-activity", headers=normal_headers).status_code == 403
    assert client.get("/api/admin/users", headers=normal_headers).status_code == 403

    with Session(get_engine()) as db:
        promoted = db.scalar(select(User).where(User.email == target_email))
        normal = db.scalar(select(User).where(User.email == normal_email))
        assert promoted is not None and promoted.role == "admin"
        assert normal is not None and normal.role == "user"


def test_only_admin_assignment_demotes_existing_admins(client):
    target_email = "sole-admin@example.com"
    previous_admin_email = "previous-admin@example.com"
    target_headers = _register_and_login(client, target_email)
    previous_admin_headers = _register_and_login(client, previous_admin_email)
    with Session(get_engine()) as db:
        previous_admin = db.scalar(
            select(User).where(User.email == previous_admin_email)
        )
        assert previous_admin is not None
        previous_admin.role = "admin"
        db.commit()

    project_root = Path(__file__).resolve().parents[1]
    subprocess.run(
        [
            sys.executable,
            str(project_root / "scripts" / "set_admin_role.py"),
            target_email,
            "--only-admin",
        ],
        cwd=project_root,
        check=True,
        capture_output=True,
        text=True,
    )

    with Session(get_engine()) as db:
        users = db.scalars(select(User)).all()
        admins = [user.email for user in users if user.role == "admin"]
        assert admins == [target_email]
        demoted = db.scalar(select(User).where(User.email == previous_admin_email))
        assert demoted is not None and demoted.role == "user"

    assert client.get(
        "/api/admin/users", headers=target_headers
    ).status_code == 200
    assert client.get(
        "/api/admin/login-activity", headers=previous_admin_headers
    ).status_code == 403


def test_admin_user_list_and_login_activity_are_private_and_persistent(client):
    admin_headers = _register_and_login(client, "monitor@example.com")
    admin_login = client.post(
        "/api/auth/login",
        json={"email": "monitor@example.com", "password": "secure-test-password-123"},
    )
    admin_headers = {"Authorization": f"Bearer {admin_login.json()['access_token']}"}
    with Session(get_engine()) as db:
        admin = db.scalar(select(User).where(User.email == "monitor@example.com"))
        assert admin is not None
        admin.role = "admin"
        db.commit()

    user_registration = client.post(
        "/api/auth/register",
        json={
            "email": "public-user@example.com",
            "display_name": "Public User",
            "password": "secure-test-password-456",
        },
    )
    assert user_registration.status_code == 201
    failed_login = client.post(
        "/api/auth/login",
        json={"email": "public-user@example.com", "password": "incorrect-password"},
    )
    assert failed_login.status_code == 401
    valid_login = client.post(
        "/api/auth/login",
        json={"email": "public-user@example.com", "password": "secure-test-password-456"},
    )
    user_headers = {"Authorization": f"Bearer {valid_login.json()['access_token']}"}
    assert client.post("/api/auth/logout", headers=user_headers).status_code == 204

    registrations = client.get("/api/admin/users", headers=admin_headers)
    assert registrations.status_code == 200
    user_entry = next(
        item for item in registrations.json() if item["email"] == "public-user@example.com"
    )
    assert user_entry["display_name"] == "Public User"
    assert user_entry["created_at"]
    assert "password_hash" not in user_entry

    activity = client.get("/api/admin/login-activity", headers=admin_headers)
    assert activity.status_code == 200
    assert activity.headers["cache-control"] == "private, no-store"
    user_events = [
        event for event in activity.json()
        if event["identifier"] == "public-user@example.com"
    ]
    assert {event["outcome"] for event in user_events} == {"success", "failure", "logout"}
    assert all(event["created_at"] for event in user_events)
    assert all("password" not in event and "token" not in event for event in user_events)
    with Session(get_engine()) as db:
        failed_entry = db.scalar(
            select(AuditLog).where(
                AuditLog.action == "user_login_failed",
                AuditLog.details_json.contains("public-user@example.com"),
            )
        )
        assert failed_entry is not None
        assert "incorrect-password" not in (failed_entry.details_json or "")
        assert "access_token" not in (failed_entry.details_json or "")

    for path in (
        "/api/admin/audit",
        "/api/admin/audit/export.csv",
        "/api/admin/users",
        "/api/admin/login-activity",
    ):
        assert client.get(path, headers=user_headers).status_code == 403
        assert client.get(path).status_code == 401


def test_frontend_pages_are_served_by_api_origin(client):
    root = client.get("/")
    assert root.status_code == 200
    assert root.url.path == "/app/templates/landing.html"
    landing = client.get("/app/templates/landing.html").text
    assert 'href="dashboard.html" data-authenticated-only hidden' in landing
    assert 'href="admin.html" data-authenticated-only data-admin-only hidden' in landing
    assert 'href="login.html" data-public-only' in landing
    login = client.get("/app/templates/login.html").text
    registration = client.get("/app/templates/register.html").text
    assert 'aria-label="Public navigation"' in login
    assert 'aria-label="Public navigation"' in registration
    assert 'href="dashboard.html"' not in login
    assert 'href="dashboard.html"' not in registration
    assert "Create account" in registration
    assert client.get("/app/static/js/trustvault.js").status_code == 200
    for page in ("dashboard", "documents", "shared", "permissions", "audit", "settings"):
        page_response = client.get(f"/app/templates/{page}.html")
        assert page_response.status_code == 200
        assert 'data-authenticated-page hidden' in page_response.text
    admin_page = client.get("/app/templates/admin.html")
    assert admin_page.status_code == 200
    assert 'data-authenticated-page data-admin-page hidden' in admin_page.text
    assert "Registered users" in admin_page.text
    assert "Login activity" in admin_page.text
