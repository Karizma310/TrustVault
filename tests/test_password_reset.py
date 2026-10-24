from datetime import datetime, timedelta, timezone
import smtplib
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_engine
from app.models.password_reset_token import PasswordResetToken
from app.models.user import User
from app.services.password_reset import (
    build_reset_url,
    hash_reset_token,
    send_password_reset_email,
)
from app.services.security import verify_password


def _set_email_configuration(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_SMTP_HOST", "mail.example.test")
    monkeypatch.setenv("TRUSTVAULT_SMTP_PORT", "587")
    monkeypatch.setenv("TRUSTVAULT_SMTP_FROM_EMAIL", "no-reply@example.com")
    monkeypatch.setenv(
        "TRUSTVAULT_FRONTEND_LOGIN_URL",
        "http://127.0.0.1:8001/app/templates/login.html",
    )
    get_settings.cache_clear()


def _clear_email_configuration(monkeypatch):
    monkeypatch.setenv("TRUSTVAULT_SMTP_HOST", "")
    monkeypatch.setenv("TRUSTVAULT_SMTP_USERNAME", "")
    monkeypatch.setenv("TRUSTVAULT_SMTP_PASSWORD", "")
    monkeypatch.setenv("TRUSTVAULT_SMTP_FROM_EMAIL", "no-reply@example.com")
    get_settings.cache_clear()


def _request_reset(client, monkeypatch):
    links = []

    def capture_email(_email, reset_url, _settings):
        links.append(reset_url)

    monkeypatch.setattr("app.api.auth.send_password_reset_email", capture_email)
    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": "reset@example.com"},
    )
    assert response.status_code == 202
    assert response.json() == {
        "message": (
            "If an account exists and email delivery is configured, reset instructions "
            "will be sent if delivery succeeds."
        )
    }
    assert len(links) == 1
    parsed_link = urlsplit(links[0])
    assert (parsed_link.scheme, parsed_link.netloc, parsed_link.path) == (
        "http",
        "127.0.0.1:8001",
        "/app/templates/reset-password.html",
    )
    return parse_qs(parsed_link.fragment)["token"][0]


def _register_user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "reset@example.com", "password": "old-password-123"},
    )
    assert response.status_code == 201


def _confirm_reset(client, token, new_password="new-password-456"):
    return client.post(
        "/api/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": new_password,
            "confirm_password": new_password,
        },
    )


def test_password_reset_changes_password_and_stores_only_token_hash(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)
    token = _request_reset(client, monkeypatch)

    with Session(get_engine()) as db:
        reset = db.scalar(select(PasswordResetToken))
        user = db.scalar(select(User).where(User.email == "reset@example.com"))
        assert reset is not None
        assert user is not None
        assert reset.token_hash == hash_reset_token(token)
        assert token not in reset.token_hash
        assert reset.expires_at > datetime.now(timezone.utc)

    response = _confirm_reset(client, token)
    assert response.status_code == 200
    login = client.post(
        "/api/auth/login",
        json={"email": "reset@example.com", "password": "new-password-456"},
    )
    assert login.status_code == 200
    assert client.post(
        "/api/auth/login",
        json={"email": "reset@example.com", "password": "old-password-123"},
    ).status_code == 401
    with Session(get_engine()) as db:
        user = db.scalar(select(User).where(User.email == "reset@example.com"))
        reset = db.scalar(select(PasswordResetToken))
        assert user is not None and verify_password("new-password-456", user.password_hash)
        assert reset is not None and reset.used_at is not None


def test_password_reset_rejects_invalid_and_reused_tokens(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)
    token = _request_reset(client, monkeypatch)

    assert _confirm_reset(client, "x" * 43).status_code == 400
    assert _confirm_reset(client, token).status_code == 200
    assert _confirm_reset(client, token).status_code == 400


def test_password_reset_rejects_expired_token(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)
    token = _request_reset(client, monkeypatch)
    with Session(get_engine()) as db:
        reset = db.scalar(select(PasswordResetToken))
        assert reset is not None
        reset.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

    assert _confirm_reset(client, token).status_code == 400


def test_unknown_email_returns_same_generic_response_without_sending(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    sent = []
    monkeypatch.setattr(
        "app.api.auth.send_password_reset_email",
        lambda *args: sent.append(args),
    )
    unknown = client.post(
        "/api/auth/password-reset/request",
        json={"email": "unknown@example.com"},
    )
    with Session(get_engine()) as db:
        assert db.scalar(select(PasswordResetToken)) is None

    _register_user(client)
    registered = client.post(
        "/api/auth/password-reset/request",
        json={"email": "reset@example.com"},
    )

    assert unknown.status_code == registered.status_code == 202
    assert unknown.json() == registered.json()
    assert len(sent) == 1
    assert sent[0][0] == "reset@example.com"


def test_reset_page_is_linked_and_missing_mail_configuration_creates_no_token(
    client, monkeypatch
):
    _clear_email_configuration(monkeypatch)
    login_page = client.get("/app/templates/login.html")
    reset_page = client.get("/app/templates/reset-password.html")
    assert 'href="reset-password.html"' in login_page.text
    assert reset_page.status_code == 200
    assert "data-password-reset-request" in reset_page.text
    assert "data-password-reset-confirm" in reset_page.text

    _register_user(client)
    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": "reset@example.com"},
    )
    assert response.status_code == 202
    assert response.json()["message"] == (
        "If an account exists and email delivery is configured, reset instructions "
        "will be sent if delivery succeeds."
    )
    with Session(get_engine()) as db:
        assert db.scalar(select(PasswordResetToken)) is None


def test_cached_settings_require_restart_or_cache_clear_after_env_changes(monkeypatch):
    _clear_email_configuration(monkeypatch)
    assert get_settings().password_reset_email_configured is False

    monkeypatch.setenv("TRUSTVAULT_SMTP_HOST", "mail.example.test")
    monkeypatch.setenv("TRUSTVAULT_SMTP_FROM_EMAIL", "no-reply@example.com")
    assert get_settings().password_reset_email_configured is False

    get_settings.cache_clear()
    assert get_settings().password_reset_email_configured is True
    get_settings.cache_clear()


def test_email_delivery_failure_invalidates_the_unusable_token(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)

    def fail_delivery(*_args):
        raise smtplib.SMTPException("mail delivery unavailable")

    monkeypatch.setattr("app.api.auth.send_password_reset_email", fail_delivery)
    response = client.post(
        "/api/auth/password-reset/request",
        json={"email": "reset@example.com"},
    )
    assert response.status_code == 202
    with Session(get_engine()) as db:
        reset = db.scalar(select(PasswordResetToken))
        assert reset is not None and reset.used_at is not None


def test_smtp_sender_uses_starttls_auth_and_correct_reset_link(monkeypatch):
    _set_email_configuration(monkeypatch)
    monkeypatch.setenv("TRUSTVAULT_SMTP_USERNAME", "smtp-user@example.com")
    monkeypatch.setenv("TRUSTVAULT_SMTP_PASSWORD", "test-mail-password")
    get_settings.cache_clear()
    settings = get_settings()
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls["connection"] = (host, port, timeout)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self, context):
            calls["starttls"] = context

        def login(self, username, password):
            calls["login"] = (username, password)

        def send_message(self, message):
            calls["message"] = message

    monkeypatch.setattr("app.services.password_reset.smtplib.SMTP", FakeSMTP)
    reset_url = build_reset_url(
        "test-only-reset-token",
        "https://vault.example.test/app/templates/login.html",
    )
    send_password_reset_email("recipient@example.com", reset_url, settings)

    assert calls["connection"] == ("mail.example.test", 587, 10)
    assert calls["starttls"] is not None
    assert calls["login"] == ("smtp-user@example.com", "test-mail-password")
    message = calls["message"]
    assert message["To"] == "recipient@example.com"
    assert message["From"] == "no-reply@example.com"
    assert "https://vault.example.test/app/templates/reset-password.html#token=test-only-reset-token" in message.get_content()
    assert "test-only-reset-token" not in message["Subject"]


def test_default_reset_link_uses_fastapi_served_frontend(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)
    token = _request_reset(client, monkeypatch)
    with Session(get_engine()) as db:
        reset = db.scalar(select(PasswordResetToken))
        assert reset is not None
        assert reset.token_hash == hash_reset_token(token)
    assert get_settings().frontend_login_url == (
        "http://127.0.0.1:8001/app/templates/login.html"
    )


def test_password_reset_rejects_mismatched_confirmation(client, monkeypatch):
    _set_email_configuration(monkeypatch)
    _register_user(client)
    token = _request_reset(client, monkeypatch)
    response = client.post(
        "/api/auth/password-reset/confirm",
        json={
            "token": token,
            "new_password": "new-password-456",
            "confirm_password": "different-password-789",
        },
    )
    assert response.status_code == 422
