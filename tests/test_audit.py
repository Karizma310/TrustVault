from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_engine
from app.models.audit_log import AuditLog


def test_authenticated_actions_are_audited_and_exportable(client):
    registration = client.post(
        "/api/auth/register",
        json={"email": "auditor@example.com", "password": "secure-test-password-123"},
    )
    assert registration.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"email": "auditor@example.com", "password": "secure-test-password-123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    upload = client.post(
        "/api/documents",
        headers=headers,
        files={"file": ("audit.txt", b"audited document", "text/plain")},
    )
    assert upload.status_code == 201

    logs = client.get("/api/audit", headers=headers)
    assert logs.status_code == 200
    actions = {entry["action"] for entry in logs.json()}
    assert {"user_registered", "user_logged_in", "document_uploaded"} <= actions

    export = client.get("/api/audit/export.csv", headers=headers)
    assert export.status_code == 200
    assert export.headers["content-type"].startswith("text/csv")
    assert "document_uploaded" in export.text


def test_health_and_openapi_are_available(client):
    assert client.get("/health").json() == {"status": "ok"}
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


def test_frontend_origin_is_allowed_to_make_authenticated_api_requests(client):
    response = client.options(
        "/api/documents",
        headers={
            "Origin": "http://127.0.0.1:8001",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:8001"
    assert "authorization" in response.headers["access-control-allow-headers"].lower()


def test_file_origin_is_not_allowed_to_access_the_api(client):
    response = client.options(
        "/api/documents",
        headers={
            "Origin": "null",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )
    assert "access-control-allow-origin" not in response.headers


def test_audit_date_filters_validate_ranges_and_return_utc(client):
    client.post(
        "/api/auth/register",
        json={"email": "date-filter@example.com", "password": "secure-test-password-123"},
    )
    login = client.post(
        "/api/auth/login",
        json={"email": "date-filter@example.com", "password": "secure-test-password-123"},
    )
    headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
    logs = client.get("/api/audit", headers=headers)
    assert logs.status_code == 200
    assert logs.json()
    timestamp = datetime.fromisoformat(logs.json()[0]["created_at"].replace("Z", "+00:00"))
    assert timestamp.utcoffset() == timezone.utc.utcoffset(timestamp)

    reversed_range = client.get(
        "/api/audit",
        headers=headers,
        params={"since": "2099-01-02T00:00:00Z", "until": "2099-01-01T00:00:00Z"},
    )
    assert reversed_range.status_code == 422


def test_denied_document_attempts_are_audited_and_records_are_append_only(client):
    client.post(
        "/api/auth/register",
        json={"email": "audit-owner@example.com", "password": "secure-test-password-123"},
    )
    owner_login = client.post(
        "/api/auth/login",
        json={"email": "audit-owner@example.com", "password": "secure-test-password-123"},
    )
    owner_headers = {"Authorization": f"Bearer {owner_login.json()['access_token']}"}
    client.post(
        "/api/auth/register",
        json={"email": "audit-outsider@example.com", "password": "secure-test-password-123"},
    )
    outsider_login = client.post(
        "/api/auth/login",
        json={"email": "audit-outsider@example.com", "password": "secure-test-password-123"},
    )
    outsider_headers = {"Authorization": f"Bearer {outsider_login.json()['access_token']}"}
    uploaded = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("audit-private.txt", b"private", "text/plain")},
    )
    document_id = uploaded.json()["id"]
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=outsider_headers,
    ).status_code == 404
    assert client.patch(
        f"/api/documents/{document_id}",
        headers=outsider_headers,
        json={"title": "unauthorized edit"},
    ).status_code == 404

    events = client.get("/api/audit", headers=outsider_headers).json()
    denied = {event["action"] for event in events}
    assert {"document_access_denied", "document_edit_denied"} <= denied

    with Session(get_engine()) as db:
        event_id = db.scalar(select(AuditLog.id).where(AuditLog.action == "document_access_denied"))
        assert event_id is not None
        with pytest.raises(IntegrityError):
            db.execute(
                update(AuditLog)
                .where(AuditLog.id == event_id)
                .values(action="tampered")
            )
            db.commit()
        db.rollback()
        with pytest.raises(IntegrityError):
            db.execute(delete(AuditLog).where(AuditLog.id == event_id))
            db.commit()
        db.rollback()


def test_document_actions_and_denied_permission_changes_are_audited(client):
    def register(email):
        assert client.post(
            "/api/auth/register",
            json={"email": email, "password": "secure-test-password-123"},
        ).status_code == 201
        login = client.post(
            "/api/auth/login",
            json={"email": email, "password": "secure-test-password-123"},
        )
        return {"Authorization": f"Bearer {login.json()['access_token']}"}

    owner = register("complete-audit-owner@example.com")
    viewer = register("complete-audit-viewer@example.com")
    outsider = register("complete-audit-outsider@example.com")
    upload = client.post(
        "/api/documents",
        headers=owner,
        files={"file": ("audited.txt", b"audit all actions", "text/plain")},
    )
    document_id = upload.json()["id"]
    grant = client.post(
        f"/api/documents/{document_id}/permissions",
        headers=owner,
        json={"user_email": "complete-audit-viewer@example.com"},
    )
    permission_id = grant.json()["id"]
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer,
    ).status_code == 200
    assert client.patch(
        f"/api/documents/{document_id}",
        headers=owner,
        json={"title": "Updated audit title"},
    ).status_code == 200
    assert client.get(
        f"/api/documents/{document_id}/permissions",
        headers=owner,
    ).status_code == 200

    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=outsider,
    ).status_code == 404
    assert client.patch(
        f"/api/documents/{document_id}",
        headers=outsider,
        json={"title": "Unauthorized"},
    ).status_code == 404
    assert client.delete(
        f"/api/documents/{document_id}",
        headers=outsider,
    ).status_code == 404
    assert client.get(
        f"/api/documents/{document_id}/permissions",
        headers=outsider,
    ).status_code == 404
    assert client.post(
        f"/api/documents/{document_id}/permissions",
        headers=outsider,
        json={"user_email": "complete-audit-viewer@example.com"},
    ).status_code == 404
    assert client.delete(
        f"/api/documents/{document_id}/permissions/{permission_id}",
        headers=outsider,
    ).status_code == 404
    assert client.delete(
        f"/api/documents/{document_id}/permissions/{permission_id}",
        headers=owner,
    ).status_code == 204
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=viewer,
    ).status_code == 404
    assert client.delete(
        f"/api/documents/{document_id}",
        headers=owner,
    ).status_code == 204

    owner_actions = {
        event["action"] for event in client.get("/api/audit", headers=owner).json()
    }
    assert {
        "document_uploaded",
        "document_edited",
        "document_access_granted",
        "document_permissions_listed",
        "document_access_revoked",
        "document_deleted",
    } <= owner_actions
    viewer_actions = {
        event["action"] for event in client.get("/api/audit", headers=viewer).json()
    }
    assert {"document_downloaded", "document_access_denied"} <= viewer_actions
    denied_actions = {
        event["action"] for event in client.get("/api/audit", headers=outsider).json()
    }
    assert {
        "document_access_denied",
        "document_edit_denied",
        "document_delete_denied",
        "document_permissions_read_denied",
        "document_access_grant_denied",
        "document_access_revoke_denied",
    } <= denied_actions