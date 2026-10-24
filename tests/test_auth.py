from sqlalchemy import create_engine, inspect, select
from sqlalchemy.orm import Session

from app.database import (
    _migrate_user_display_name,
    _migrate_user_preferences,
    _migrate_user_role,
    get_engine,
)
from app.models.user import User
from app.services.security import verify_password


def test_registration_login_and_authenticated_profile(client):
    assert client.get("/api/auth/me").status_code == 401
    assert client.get("/api/auth/preferences").status_code == 401
    assert client.patch(
        "/api/auth/preferences",
        json={"theme": "dark"},
    ).status_code == 401
    response = client.post(
        "/api/auth/register",
        json={"email": "Jamie@example.com", "password": "a-secure-passphrase-123"},
    )
    assert response.status_code == 201
    assert response.json()["email"] == "jamie@example.com"
    assert "password" not in response.json()

    login = client.post(
        "/api/auth/login",
        json={"email": "JAMIE@example.com", "password": "a-secure-passphrase-123"},
    )
    assert login.status_code == 200
    token = login.json()["access_token"]
    profile = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert profile.status_code == 200
    assert profile.json()["email"] == "jamie@example.com"
    assert profile.headers["cache-control"] == "no-store"


def test_profiles_are_specific_to_the_authenticated_account(client):
    owner = client.post(
        "/api/auth/register",
        json={
            "display_name": "Vault Owner",
            "email": "owner-profile@example.com",
            "password": "a-secure-passphrase-123",
        },
    )
    viewer = client.post(
        "/api/auth/register",
        json={
            "display_name": "Document Viewer",
            "email": "viewer-profile@example.com",
            "password": "a-secure-passphrase-456",
        },
    )
    assert owner.status_code == 201
    assert viewer.status_code == 201

    owner_token = client.post(
        "/api/auth/login",
        json={"email": "owner-profile@example.com", "password": "a-secure-passphrase-123"},
    ).json()["access_token"]
    viewer_token = client.post(
        "/api/auth/login",
        json={"email": "viewer-profile@example.com", "password": "a-secure-passphrase-456"},
    ).json()["access_token"]

    owner_profile = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {owner_token}"},
    ).json()
    viewer_profile = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {viewer_token}"},
    ).json()

    assert owner_profile["id"] == owner.json()["id"]
    assert owner_profile["email"] == "owner-profile@example.com"
    assert owner_profile["display_name"] == "Vault Owner"
    assert viewer_profile["id"] == viewer.json()["id"]
    assert viewer_profile["email"] == "viewer-profile@example.com"
    assert viewer_profile["display_name"] == "Document Viewer"
    assert owner_profile["id"] != viewer_profile["id"]


def test_profile_edit_and_preferences_are_scoped_to_authenticated_user(client):
    first = client.post(
        "/api/auth/register",
        json={
            "display_name": "First User",
            "email": "first-settings@example.com",
            "password": "a-secure-passphrase-123",
        },
    )
    second = client.post(
        "/api/auth/register",
        json={
            "display_name": "Second User",
            "email": "second-settings@example.com",
            "password": "a-secure-passphrase-456",
        },
    )
    assert first.status_code == 201
    assert second.status_code == 201

    def login(email, password):
        access_token = client.post(
            "/api/auth/login",
            json={"email": email, "password": password},
        ).json()["access_token"]
        return {"Authorization": f"Bearer {access_token}"}

    first_headers = login("first-settings@example.com", "a-secure-passphrase-123")
    second_headers = login("second-settings@example.com", "a-secure-passphrase-456")
    preferences_response = client.get("/api/auth/preferences", headers=first_headers)
    assert preferences_response.headers["cache-control"] == "no-store"
    assert preferences_response.json() == {
        "user_id": first.json()["id"],
        "notifications_enabled": True,
        "theme": "light",
    }

    updated_profile = client.patch(
        "/api/auth/me",
        headers=first_headers,
        json={"display_name": "Updated First"},
    )
    assert updated_profile.status_code == 200
    assert updated_profile.json()["display_name"] == "Updated First"
    assert updated_profile.json()["email"] == "first-settings@example.com"
    assert client.get("/api/auth/me", headers=first_headers).json()["email"] == (
        "first-settings@example.com"
    )
    assert client.get("/api/auth/me", headers=second_headers).json()["display_name"] == "Second User"

    updated_preferences = client.patch(
        "/api/auth/preferences",
        headers=first_headers,
        json={"notifications_enabled": False, "theme": "dark"},
    )
    assert updated_preferences.status_code == 200
    assert updated_preferences.json() == {
        "user_id": first.json()["id"],
        "notifications_enabled": False,
        "theme": "dark",
    }
    assert client.get("/api/auth/preferences", headers=second_headers).json() == {
        "user_id": second.json()["id"],
        "notifications_enabled": True,
        "theme": "light",
    }

    relogin_headers = login("first-settings@example.com", "a-secure-passphrase-123")
    assert client.get("/api/auth/preferences", headers=relogin_headers).json() == {
        "user_id": first.json()["id"],
        "notifications_enabled": False,
        "theme": "dark",
    }
    assert client.patch(
        "/api/auth/preferences",
        headers=second_headers,
        json={"theme": "invalid"},
    ).status_code == 422
    assert client.patch(
        "/api/auth/preferences",
        headers=second_headers,
        json={"notifications_enabled": None},
    ).status_code == 422


def test_registration_rejects_short_password_and_duplicate_email(client):
    short_password = client.post(
        "/api/auth/register",
        json={"email": "user@example.com", "password": "short"},
    )
    assert short_password.status_code == 422

    payload = {"email": "user@example.com", "password": "long-enough-password"}
    assert client.post("/api/auth/register", json=payload).status_code == 201
    assert client.post("/api/auth/register", json=payload).status_code == 409


def test_registration_rejects_invalid_email(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "not-an-email", "password": "secure-test-password"},
    )
    assert response.status_code == 422


def test_registration_accepts_an_empty_optional_display_name(client):
    for email, display_name in (
        ("empty-name@example.com", ""),
        ("whitespace-name@example.com", "   "),
        ("null-name@example.com", None),
    ):
        response = client.post(
            "/api/auth/register",
            json={
                "email": email,
                "password": "secure-test-password-123",
                "display_name": display_name,
            },
        )
        assert response.status_code == 201
        assert response.json()["display_name"] is None


def test_registration_stores_a_password_hash_not_the_password(client):
    password = "secure-test-password-123"
    response = client.post(
        "/api/auth/register",
        json={"email": "hashed@example.com", "password": password},
    )
    assert response.status_code == 201
    assert "password" not in response.json()

    with Session(get_engine()) as db:
        user = db.scalar(select(User).where(User.email == "hashed@example.com"))
        assert user is not None
        assert user.password_hash != password
        assert verify_password(password, user.password_hash)


def test_existing_database_gets_optional_profile_name_column(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(254), password_hash VARCHAR(255))"
            )
            connection.exec_driver_sql(
                "INSERT INTO users (id, email, password_hash) VALUES (1, 'legacy@example.com', 'hash')"
            )
        _migrate_user_display_name(engine)
        _migrate_user_preferences(engine)
        _migrate_user_role(engine)
        columns = {column["name"] for column in inspect(engine).get_columns("users")}
        assert "display_name" in columns
        assert "notifications_enabled" in columns
        assert "theme" in columns
        assert "role" in columns
        with engine.connect() as connection:
            user_preferences = connection.exec_driver_sql(
                "SELECT notifications_enabled, theme FROM users WHERE id = 1"
            ).one()
            migrated_role = connection.exec_driver_sql(
                "SELECT role FROM users WHERE id = 1"
            ).scalar_one()
        assert user_preferences == (1, "light")
        assert migrated_role == "user"
    finally:
        engine.dispose()


def test_login_and_protected_route_reject_invalid_credentials(client):
    registration = client.post(
        "/api/auth/register",
        json={
            "email": "login-error@example.com",
            "password": "secure-login-password-123",
        },
    )
    assert registration.status_code == 201

    wrong_password = client.post(
        "/api/auth/login",
        json={
            "email": "login-error@example.com",
            "password": "wrong-login-password-456",
        },
    )
    unknown_email = client.post(
        "/api/auth/login",
        json={"email": "missing@example.com", "password": "no-such-password"},
    )
    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json()["detail"] == "Invalid email or password."
    assert unknown_email.json()["detail"] == wrong_password.json()["detail"]
    assert client.get("/api/auth/me").status_code == 401


def test_login_page_maps_unauthorized_api_responses_to_visible_generic_message(client):
    login_page = client.get("/app/templates/login.html")
    javascript = client.get("/app/static/js/trustvault.js")
    stylesheet = client.get("/app/static/css/trustvault.css")

    assert login_page.status_code == javascript.status_code == stylesheet.status_code == 200
    assert 'role="status" aria-live="polite" data-login-status' in login_page.text
    assert "error instanceof AuthenticationError" in javascript.text
    assert ' ? "Invalid email or password."' in javascript.text
    assert '.preview-notice[data-state="error"]' in stylesheet.text