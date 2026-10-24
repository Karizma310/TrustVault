from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api import google_auth
from app.api.google_auth import STATE_COOKIE
from app.config import ENV_FILE, Settings, get_settings
from app.database import get_engine
from app.models.google_identity import GoogleIdentity


def test_settings_env_file_is_anchored_to_project_root():
    assert ENV_FILE.is_absolute()
    assert Settings.model_config["env_file"] == ENV_FILE
    assert ENV_FILE == Path(__file__).resolve().parents[1] / ".env"


def _configure_google(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_GOOGLE_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("TRUSTVAULT_GOOGLE_CLIENT_SECRET", "test-client-secret")
    monkeypatch.setenv(
        "TRUSTVAULT_GOOGLE_REDIRECT_URI",
        "http://127.0.0.1:8000/api/auth/google/callback",
    )
    get_settings.cache_clear()


def _start_google_login(client, monkeypatch):
    _configure_google(monkeypatch)
    response = client.get("/api/auth/google/start", follow_redirects=False)
    assert response.status_code == 302
    return response


def test_google_start_redirects_with_scopes_state_and_csrf_cookie(client, monkeypatch):
    response = _start_google_login(client, monkeypatch)
    location = urlparse(response.headers["location"])
    query = parse_qs(location.query)

    assert location.scheme == "https"
    assert location.netloc == "accounts.google.com"
    assert query["client_id"] == ["test-client-id"]
    assert query["redirect_uri"] == [
        "http://127.0.0.1:8000/api/auth/google/callback"
    ]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid email profile"]
    assert response.cookies.get(STATE_COOKIE) == query["state"][0]
    assert response.headers["set-cookie"].lower().find("httponly") >= 0
    assert "samesite=lax" in response.headers["set-cookie"].lower()


def test_google_start_reports_missing_configuration(client, monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_GOOGLE_CLIENT_ID", "")
    monkeypatch.setenv("TRUSTVAULT_GOOGLE_CLIENT_SECRET", "")
    monkeypatch.setenv("TRUSTVAULT_GOOGLE_REDIRECT_URI", "")
    get_settings.cache_clear()

    response = client.get("/api/auth/google/start", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"].endswith("#google_error=not_configured")


def test_google_callback_rejects_invalid_state(client, monkeypatch):
    _configure_google(monkeypatch)
    response = client.get(
        "/api/auth/google/callback?state=attacker-state&code=fake-code",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("#google_error=invalid_state")


def test_google_callback_provider_error_is_reported(client, monkeypatch):
    start = _start_google_login(client, monkeypatch)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    client.cookies.set(STATE_COOKIE, state, path="/api/auth/google/callback")

    response = client.get(
        f"/api/auth/google/callback?state={state}&error=access_denied",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith("#google_error=cancelled")


def test_google_callback_rejects_invalid_identity_token(client, monkeypatch):
    start = _start_google_login(client, monkeypatch)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    client.cookies.set(STATE_COOKIE, state, path="/api/auth/google/callback")
    monkeypatch.setattr(google_auth, "_exchange_google_code", lambda *_: "untrusted-token")

    def reject_token(*_args):
        raise ValueError("invalid signature")

    monkeypatch.setattr(google_auth.id_token, "verify_oauth2_token", reject_token)
    response = client.get(
        f"/api/auth/google/callback?state={state}&code=mocked-code",
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert response.headers["location"].endswith(
        "#google_error=verification_failed"
    )


def test_google_callback_rejects_unverified_email(client, monkeypatch):
    _configure_google(monkeypatch)
    monkeypatch.setattr(
        google_auth.id_token,
        "verify_oauth2_token",
        lambda *_args: {
            "iss": "https://accounts.google.com",
            "sub": "google-subject-1",
            "email": "person@example.com",
            "email_verified": False,
            "name": "Verified Person",
        },
    )
    with pytest.raises(ValueError, match="not verified"):
        google_auth._verify_google_identity("verified-by-mock", get_settings())


def test_google_callback_creates_user_and_exchanges_one_time_code(
    client,
    monkeypatch,
):
    start = _start_google_login(client, monkeypatch)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    client.cookies.set(STATE_COOKIE, state, path="/api/auth/google/callback")

    class MockGoogleTokenResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {"id_token": "mock-id-token"}

    exchange_requests = []

    def mock_google_token_exchange(url, *, data, timeout):
        exchange_requests.append({"url": url, "data": data, "timeout": timeout})
        return MockGoogleTokenResponse()

    monkeypatch.setattr(google_auth.requests, "post", mock_google_token_exchange)
    monkeypatch.setattr(
        google_auth.id_token,
        "verify_oauth2_token",
        lambda *_args: {
            "iss": "https://accounts.google.com",
            "sub": "stable-google-subject",
            "email": "person@example.com",
            "email_verified": True,
            "aud": "test-client-id",
            "name": "Google Person",
        },
    )

    callback = client.get(
        f"/api/auth/google/callback?state={state}&code=mocked-code",
        follow_redirects=False,
    )
    assert exchange_requests[0]["url"] == google_auth.GOOGLE_TOKEN_URL
    assert exchange_requests[0]["data"]["grant_type"] == "authorization_code"
    assert exchange_requests[0]["data"]["code"] == "mocked-code"
    assert exchange_requests[0]["data"]["redirect_uri"] == (
        "http://127.0.0.1:8000/api/auth/google/callback"
    )
    assert callback.status_code == 303
    fragment = urlparse(callback.headers["location"]).fragment
    code = parse_qs(fragment)["google_code"][0]

    exchange = client.post("/api/auth/google/exchange", json={"code": code})
    assert exchange.status_code == 200
    token = exchange.json()["access_token"]
    profile = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert profile.status_code == 200
    assert profile.json()["email"] == "person@example.com"
    assert profile.json()["display_name"] == "Google Person"
    with Session(get_engine()) as db:
        identity = db.scalar(
            select(GoogleIdentity).where(
                GoogleIdentity.subject == "stable-google-subject"
            )
        )
        assert identity is not None
    assert client.post("/api/auth/google/exchange", json={"code": code}).status_code == 400


def test_google_login_does_not_silently_link_existing_password_account(
    client,
    monkeypatch,
):
    client.post(
        "/api/auth/register",
        json={
            "email": "person@example.com",
            "password": "a-secure-password-123",
        },
    )
    start = _start_google_login(client, monkeypatch)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    client.cookies.set(STATE_COOKIE, state, path="/api/auth/google/callback")
    monkeypatch.setattr(google_auth, "_exchange_google_code", lambda *_: "mock-id-token")
    monkeypatch.setattr(
        google_auth,
        "_verify_google_identity",
        lambda *_: {"subject": "another-google-subject", "email": "person@example.com"},
    )

    response = client.get(
        f"/api/auth/google/callback?state={state}&code=mocked-code",
        follow_redirects=False,
    )
    assert response.headers["location"].endswith("#google_error=account_exists")
