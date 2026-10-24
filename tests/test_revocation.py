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


def test_owner_grants_and_revokes_read_access(client):
    owner_headers = _register_and_login(client, "owner@example.com")
    recipient_headers = _register_and_login(client, "recipient@example.com")
    stranger_headers = _register_and_login(client, "stranger@example.com")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("shared.pdf", b"%PDF-1.7\nonly owner and recipient", "application/pdf")},
    )
    document_id = upload.json()["id"]

    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=stranger_headers,
    ).status_code == 404
    assert client.get(
        "/api/documents/shared-with-me",
        headers=stranger_headers,
    ).json() == []

    grant = client.post(
        f"/api/documents/{document_id}/permissions",
        headers=owner_headers,
        json={"user_email": "recipient@example.com"},
    )
    assert grant.status_code == 201
    permission_id = grant.json()["id"]
    assert grant.json()["access_level"] == "read"
    shared_documents = client.get(
        "/api/documents/shared-with-me",
        headers=recipient_headers,
    ).json()
    assert shared_documents[0]["id"] == document_id
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=recipient_headers,
    ).content == b"%PDF-1.7\nonly owner and recipient"

    non_owner_grant = client.post(
        f"/api/documents/{document_id}/permissions",
        headers=stranger_headers,
        json={"user_email": "recipient@example.com"},
    )
    assert non_owner_grant.status_code == 404
    non_owner_list = client.get(
        f"/api/documents/{document_id}/permissions",
        headers=stranger_headers,
    )
    assert non_owner_list.status_code == 404
    non_owner_revoke = client.delete(
        f"/api/documents/{document_id}/permissions/{permission_id}",
        headers=stranger_headers,
    )
    assert non_owner_revoke.status_code == 404

    revoke = client.delete(
        f"/api/documents/{document_id}/permissions/{permission_id}",
        headers=owner_headers,
    )
    assert revoke.status_code == 204
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=recipient_headers,
    ).status_code == 404
    assert client.get("/api/documents/shared-with-me", headers=recipient_headers).json() == []


def test_owner_can_grant_by_user_id_and_recipient_sees_document(client):
    owner_headers = _register_and_login(client, "owner-id@example.com")
    recipient_headers = _register_and_login(client, "recipient-id@example.com")
    recipient_id = client.get(
        "/api/auth/me",
        headers=recipient_headers,
    ).json()["id"]
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("shared-by-id.txt", b"shared by user ID", "text/plain")},
    )
    document_id = upload.json()["id"]

    grant = client.post(
        f"/api/documents/{document_id}/permissions",
        headers=owner_headers,
        json={"user_id": recipient_id},
    )
    assert grant.status_code == 201
    assert grant.json()["user_id"] == recipient_id
    assert grant.json()["access_level"] == "read"

    shared = client.get(
        "/api/documents/shared-with-me",
        headers=recipient_headers,
    )
    assert shared.status_code == 200
    assert [item["id"] for item in shared.json()] == [document_id]


def test_only_owner_can_edit_or_delete_document(client, tmp_path):
    owner_headers = _register_and_login(client, "edit-owner@example.com")
    viewer_headers = _register_and_login(client, "edit-viewer@example.com")
    upload = client.post(
        "/api/documents",
        headers=owner_headers,
        files={"file": ("owned.txt", b"owner contents", "text/plain")},
    )
    document_id = upload.json()["id"]

    denied_edit = client.patch(
        f"/api/documents/{document_id}",
        headers=viewer_headers,
        json={"title": "Viewer changed title"},
    )
    assert denied_edit.status_code == 404
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=owner_headers,
    ).status_code == 200
    update = client.patch(
        f"/api/documents/{document_id}",
        headers=owner_headers,
        json={"title": "Renamed safely"},
    )
    assert update.status_code == 200
    assert update.json()["title"] == "Renamed safely"

    denied_delete = client.delete(
        f"/api/documents/{document_id}",
        headers=viewer_headers,
    )
    assert denied_delete.status_code == 404
    deleted = client.delete(f"/api/documents/{document_id}", headers=owner_headers)
    assert deleted.status_code == 204
    assert client.get(
        f"/api/documents/{document_id}/download",
        headers=owner_headers,
    ).status_code == 404
    assert list((tmp_path / "private").iterdir()) == []