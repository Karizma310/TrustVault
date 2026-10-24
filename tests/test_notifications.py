def _register_and_login(client, email, display_name):
    registered = client.post(
        "/api/auth/register",
        json={
            "email": email,
            "display_name": display_name,
            "password": "secure-test-password-123",
        },
    )
    assert registered.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": "secure-test-password-123"},
    )
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def test_share_notification_is_private_persistent_and_readable(client):
    assert client.get("/api/notifications").status_code == 401
    owner_headers = _register_and_login(client, "owner@example.com", "Vault Owner")
    viewer_headers = _register_and_login(client, "viewer@example.com", "File Viewer")
    stranger_headers = _register_and_login(client, "stranger@example.com", "Stranger")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("quarterly-report.pdf", b"%PDF-1.7\nprivate report", "application/pdf")},
    )
    assert upload.status_code == 201
    document_id = upload.json()["id"]

    empty_before_share = client.get("/api/notifications", headers=viewer_headers)
    assert empty_before_share.status_code == 200
    assert empty_before_share.json() == {
        "items": [],
        "total_count": 0,
        "unread_count": 0,
        "notifications_enabled": True,
    }
    assert empty_before_share.headers["cache-control"] == "no-store"

    grant = client.post(
        f"/api/documents/{document_id}/permissions",
        headers=owner_headers,
        json={"user_email": "viewer@example.com"},
    )
    assert grant.status_code == 201

    owner_profile = client.get("/api/auth/me", headers=owner_headers).json()
    viewer_profile = client.get("/api/auth/me", headers=viewer_headers).json()
    owner_documents = client.get("/api/documents", headers=owner_headers).json()
    assert owner_documents[0]["owner_id"] == owner_profile["id"]
    assert client.get("/api/documents", headers=viewer_headers).json() == []
    shared_documents = client.get(
        "/api/documents/shared-with-me",
        headers=viewer_headers,
    ).json()
    assert [item["id"] for item in shared_documents] == [document_id]
    assert shared_documents[0]["owner_id"] == owner_profile["id"]
    assert viewer_profile["id"] != owner_profile["id"]

    owner_notifications = client.get("/api/notifications", headers=owner_headers).json()
    viewer_notifications_response = client.get(
        "/api/notifications",
        headers=viewer_headers,
    )
    assert viewer_notifications_response.headers["cache-control"] == "no-store"
    assert owner_notifications == {
        "items": [],
        "total_count": 0,
        "unread_count": 0,
        "notifications_enabled": True,
    }
    assert viewer_notifications_response.status_code == 200
    viewer_notifications = viewer_notifications_response.json()
    assert viewer_notifications["unread_count"] == 1
    assert viewer_notifications["total_count"] == 1
    assert viewer_notifications["notifications_enabled"] is True
    assert len(viewer_notifications["items"]) == 1
    notification = viewer_notifications["items"][0]
    assert notification["document_id"] == document_id
    assert notification["owner_name"] == "Vault Owner"
    assert notification["document_name"] == "quarterly-report.pdf"
    assert notification["access_level"] == "read"
    assert notification["read_at"] is None
    notification_id = notification["id"]

    assert client.get("/api/notifications", headers=stranger_headers).json() == {
        "items": [],
        "total_count": 0,
        "unread_count": 0,
        "notifications_enabled": True,
    }
    assert client.post(
        f"/api/notifications/{notification_id}/read",
        headers=stranger_headers,
    ).status_code == 404
    assert client.delete(
        f"/api/notifications/{notification_id}",
        headers=owner_headers,
    ).status_code == 404

    viewer_login_again = client.post(
        "/api/auth/login",
        json={"email": "viewer@example.com", "password": "secure-test-password-123"},
    )
    relogin_headers = {"Authorization": f"Bearer {viewer_login_again.json()['access_token']}"}
    from app.database import get_engine

    get_engine().dispose()
    get_engine.cache_clear()
    assert client.get("/api/auth/me", headers=relogin_headers).json()["id"] == viewer_profile["id"]
    persisted = client.get("/api/notifications", headers=relogin_headers).json()
    assert persisted["unread_count"] == 1
    assert persisted["items"][0]["id"] == notification_id

    marked_read = client.post(
        f"/api/notifications/{notification_id}/read",
        headers=relogin_headers,
    )
    assert marked_read.status_code == 200
    assert marked_read.json()["read_at"] is not None
    after_read = client.get("/api/notifications", headers=relogin_headers).json()
    assert after_read["total_count"] == 1
    assert after_read["unread_count"] == 0
    assert after_read["items"][0]["read_at"] is not None

    dismissed = client.delete(
        f"/api/notifications/{notification_id}",
        headers=relogin_headers,
    )
    assert dismissed.status_code == 204
    assert client.get("/api/notifications", headers=relogin_headers).json() == {
        "items": [],
        "total_count": 0,
        "unread_count": 0,
        "notifications_enabled": True,
    }


def test_relative_sqlite_path_is_anchored_to_project_root(monkeypatch, tmp_path):
    from app.database import PROJECT_ROOT, _resolve_database_url

    monkeypatch.chdir(tmp_path)

    database_url = _resolve_database_url("sqlite:///./trustvault.db")

    assert database_url.database == str(PROJECT_ROOT / "trustvault.db")


def test_failed_or_duplicate_permission_grant_creates_no_extra_notification(client):
    owner_headers = _register_and_login(client, "grant-owner@example.com", "Grant Owner")
    viewer_headers = _register_and_login(client, "grant-viewer@example.com", "Grant Viewer")
    stranger_headers = _register_and_login(client, "grant-stranger@example.com", "Grant Stranger")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("shared.txt", b"shared content", "text/plain")},
    )
    document_id = upload.json()["id"]
    permission_path = f"/api/documents/{document_id}/permissions"

    assert client.post(
        permission_path,
        headers=stranger_headers,
        json={"user_email": "grant-viewer@example.com"},
    ).status_code == 404
    assert client.post(
        permission_path,
        headers=owner_headers,
        json={"user_email": "unregistered@example.com"},
    ).status_code == 404
    assert client.get("/api/notifications", headers=viewer_headers).json() == {
        "items": [],
        "total_count": 0,
        "unread_count": 0,
        "notifications_enabled": True,
    }

    assert client.post(
        permission_path,
        headers=owner_headers,
        json={"user_email": "grant-viewer@example.com"},
    ).status_code == 201
    assert client.post(
        permission_path,
        headers=owner_headers,
        json={"user_email": "grant-viewer@example.com"},
    ).status_code == 409
    assert len(client.get("/api/notifications", headers=viewer_headers).json()["items"]) == 1


def test_disabling_notification_alerts_preserves_saved_notifications(client):
    owner_headers = _register_and_login(client, "alerts-owner@example.com", "Alerts Owner")
    viewer_headers = _register_and_login(client, "alerts-viewer@example.com", "Alerts Viewer")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("alert.txt", b"alert contents", "text/plain")},
    )
    document_id = upload.json()["id"]
    assert client.post(
        f"/api/documents/{document_id}/permissions",
        headers=owner_headers,
        json={"user_email": "alerts-viewer@example.com"},
    ).status_code == 201

    updated = client.patch(
        "/api/auth/preferences",
        headers=viewer_headers,
        json={"notifications_enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["notifications_enabled"] is False
    notifications = client.get("/api/notifications", headers=viewer_headers).json()
    assert notifications["total_count"] == 1
    assert notifications["unread_count"] == 1
    assert notifications["notifications_enabled"] is False
    restored = client.patch(
        "/api/auth/preferences",
        headers=viewer_headers,
        json={"notifications_enabled": True},
    )
    assert restored.status_code == 200
    restored_notifications = client.get("/api/notifications", headers=viewer_headers).json()
    assert restored_notifications["notifications_enabled"] is True
    assert restored_notifications["unread_count"] == 1
