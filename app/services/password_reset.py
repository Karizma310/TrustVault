import secrets
import smtplib
import ssl
from email.message import EmailMessage
from hashlib import sha256
from urllib.parse import quote, urlsplit, urlunsplit

from app.config import Settings


def create_reset_token() -> str:
    return secrets.token_urlsafe(32)


def hash_reset_token(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def build_reset_url(token: str, login_url: str) -> str:
    parsed = urlsplit(login_url)
    path = parsed.path.rsplit("/", 1)[0] + "/reset-password.html"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", f"token={quote(token)}"))


def send_password_reset_email(email: str, reset_url: str, settings: Settings) -> None:
    if not settings.password_reset_email_configured or settings.smtp_from_email is None:
        raise ValueError("Password reset email delivery is not configured.")

    message = EmailMessage()
    message["Subject"] = "Reset your TrustVault password"
    message["From"] = str(settings.smtp_from_email)
    message["To"] = email
    message.set_content(
        "We received a request to reset your TrustVault password.\n\n"
        f"Use this one-time link within {settings.password_reset_minutes} minutes:\n"
        f"{reset_url}\n\n"
        "If you did not request this, you can ignore this message."
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls(context=ssl.create_default_context())
        if settings.smtp_username and settings.smtp_password:
            server.login(
                settings.smtp_username,
                settings.smtp_password.get_secret_value(),
            )
        server.send_message(message)
