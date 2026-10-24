import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import TypedDict
from urllib.parse import urlencode

import google.auth.exceptions
import requests
from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Response, status
from fastapi.responses import RedirectResponse
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token
from pydantic import BaseModel, EmailStr, Field, TypeAdapter, ValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.api.deps import DatabaseSession
from app.config import Settings, get_settings
from app.models.google_identity import GoogleIdentity
from app.models.google_oauth_grant import GoogleOAuthGrant
from app.models.user import User
from app.schemas.user import TokenResponse
from app.services.audit import record_event
from app.services.security import create_access_token, hash_password

router = APIRouter(prefix="/api/auth/google", tags=["Google authentication"])

STATE_COOKIE = "trustvault_google_oauth_state"
STATE_MAX_AGE_SECONDS = 600
LOGIN_CODE_TTL_SECONDS = 120
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"


class GoogleCodeExchange(BaseModel):
    code: str = Field(min_length=32, max_length=128)


class VerifiedGoogleIdentity(TypedDict):
    subject: str
    email: str
    display_name: str | None


def _google_credentials(settings: Settings) -> tuple[str, str, str] | None:
    client_id = settings.google_client_id
    client_secret = settings.google_client_secret
    redirect_uri = settings.google_redirect_uri
    if not client_id or client_secret is None or not redirect_uri:
        return None
    secret = client_secret.get_secret_value()
    if not secret:
        return None
    return client_id, secret, redirect_uri


def _configured(settings: Settings) -> bool:
    return _google_credentials(settings) is not None


def _login_redirect(settings: Settings, result: str) -> RedirectResponse:
    return RedirectResponse(
        f"{settings.frontend_login_url}#{result}",
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _record_google_login_failure(
    db: DatabaseSession,
    reason: str,
    identifier: str | None = None,
) -> None:
    details = {"provider": "google", "reason": reason}
    if identifier:
        details["identifier"] = identifier
    record_event(
        db,
        actor_user_id=None,
        action="user_login_failed",
        resource_type="user",
        details=details,
    )
    db.commit()


def _state_cookie_secure(settings: Settings) -> bool:
    return bool(
        settings.google_redirect_uri
        and settings.google_redirect_uri.startswith("https://")
    )


def _clear_state_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        STATE_COOKIE,
        path="/api/auth/google/callback",
        secure=_state_cookie_secure(settings),
        httponly=True,
        samesite="lax",
    )


def _exchange_google_code(code: str, settings: Settings) -> str:
    credentials = _google_credentials(settings)
    if credentials is None:
        raise ValueError("Google OAuth is not configured.")
    client_id, client_secret, redirect_uri = credentials
    response = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    response.raise_for_status()
    payload = response.json()
    token = payload.get("id_token")
    if not isinstance(token, str) or not token:
        raise ValueError("Google did not return an identity token.")
    return token


def _verify_google_identity(
    token: str,
    settings: Settings,
) -> VerifiedGoogleIdentity:
    credentials = _google_credentials(settings)
    if credentials is None:
        raise ValueError("Google OAuth is not configured.")
    claims = id_token.verify_oauth2_token(
        token,
        GoogleRequest(),
        credentials[0],
    )
    if claims.get("iss") not in {"accounts.google.com", "https://accounts.google.com"}:
        raise ValueError("Google identity token has an invalid issuer.")
    if claims.get("email_verified") is not True:
        raise ValueError("Google email address is not verified.")
    subject = claims.get("sub")
    email = claims.get("email")
    if not isinstance(subject, str) or not subject or not isinstance(email, str):
        raise ValueError("Google identity token is missing required claims.")
    display_name = claims.get("name")
    if not isinstance(display_name, str):
        display_name = None
    else:
        display_name = display_name.strip()[:100] or None
    try:
        normalized_email = str(TypeAdapter(EmailStr).validate_python(email))
    except ValidationError as error:
        raise ValueError("Google identity token contains an invalid email.") from error
    return {
        "subject": subject,
        "email": normalized_email.casefold(),
        "display_name": display_name,
    }


def _validate_google_state(
    state: str | None,
    state_cookie: str | None,
) -> bool:
    return bool(
        state
        and state_cookie
        and hmac.compare_digest(state, state_cookie)
    )


@router.get("/start")
def google_authorization_start(
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    credentials = _google_credentials(settings)
    if credentials is None:
        redirect = _login_redirect(settings, "google_error=not_configured")
        _clear_state_cookie(redirect, settings)
        return redirect
    client_id, _client_secret, redirect_uri = credentials

    state = secrets.token_urlsafe(32)
    query = urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "prompt": "select_account",
        }
    )
    redirect = RedirectResponse(
        f"{GOOGLE_AUTHORIZATION_URL}?{query}",
        status_code=status.HTTP_302_FOUND,
    )
    redirect.set_cookie(
        STATE_COOKIE,
        state,
        max_age=STATE_MAX_AGE_SECONDS,
        path="/api/auth/google/callback",
        secure=_state_cookie_secure(settings),
        httponly=True,
        samesite="lax",
    )
    return redirect


@router.get("/callback")
def google_authorization_callback(
    db: DatabaseSession,
    state: str | None = Query(default=None, max_length=256),
    code: str | None = Query(default=None, max_length=2048),
    provider_error: str | None = Query(default=None, alias="error", max_length=128),
    state_cookie: str | None = Cookie(default=None, alias=STATE_COOKIE),
    settings: Settings = Depends(get_settings),
) -> RedirectResponse:
    if not _configured(settings):
        redirect = _login_redirect(settings, "google_error=not_configured")
        _clear_state_cookie(redirect, settings)
        return redirect
    if not _validate_google_state(state, state_cookie):
        _record_google_login_failure(db, "invalid_oauth_state")
        redirect = _login_redirect(settings, "google_error=invalid_state")
        _clear_state_cookie(redirect, settings)
        return redirect
    if provider_error:
        _record_google_login_failure(db, "provider_denied")
        redirect = _login_redirect(settings, "google_error=cancelled")
        _clear_state_cookie(redirect, settings)
        return redirect
    if not code:
        _record_google_login_failure(db, "missing_authorization_code")
        redirect = _login_redirect(settings, "google_error=callback_failed")
        _clear_state_cookie(redirect, settings)
        return redirect

    try:
        identity_token = _exchange_google_code(code, settings)
        identity = _verify_google_identity(identity_token, settings)
    except (requests.RequestException, google.auth.exceptions.GoogleAuthError, ValueError):
        _record_google_login_failure(db, "identity_verification_failed")
        redirect = _login_redirect(settings, "google_error=verification_failed")
        _clear_state_cookie(redirect, settings)
        return redirect

    try:
        google_identity = db.scalar(
            select(GoogleIdentity).where(GoogleIdentity.subject == identity["subject"])
        )
        if google_identity is not None:
            user = db.get(User, google_identity.user_id)
            if user is None or user.email != identity["email"]:
                _record_google_login_failure(
                    db, "account_mismatch", identity["email"]
                )
                redirect = _login_redirect(settings, "google_error=account_mismatch")
                _clear_state_cookie(redirect, settings)
                return redirect
            if user.display_name is None and identity.get("display_name"):
                user.display_name = identity["display_name"]
        else:
            existing_user = db.scalar(select(User).where(User.email == identity["email"]))
            if existing_user is not None:
                _record_google_login_failure(
                    db, "email_already_registered", identity["email"]
                )
                redirect = _login_redirect(settings, "google_error=account_exists")
                _clear_state_cookie(redirect, settings)
                return redirect
            user = User(
                email=identity["email"],
                display_name=identity.get("display_name"),
                password_hash=hash_password(secrets.token_urlsafe(48)),
            )
            db.add(user)
            db.flush()
            db.add(GoogleIdentity(subject=identity["subject"], user_id=user.id))

        exchange_code = secrets.token_urlsafe(32)
        now = datetime.now(timezone.utc)
        db.add(
            GoogleOAuthGrant(
                code_hash=hashlib.sha256(exchange_code.encode("utf-8")).hexdigest(),
                user_id=user.id,
                expires_at=now + timedelta(seconds=LOGIN_CODE_TTL_SECONDS),
            )
        )
        db.commit()
    except IntegrityError:
        db.rollback()
        _record_google_login_failure(db, "account_conflict", identity["email"])
        redirect = _login_redirect(settings, "google_error=account_conflict")
        _clear_state_cookie(redirect, settings)
        return redirect

    redirect = _login_redirect(settings, f"google_code={exchange_code}")
    _clear_state_cookie(redirect, settings)
    return redirect


@router.post("/exchange", response_model=TokenResponse)
def exchange_google_login_code(
    payload: GoogleCodeExchange,
    db: DatabaseSession,
) -> TokenResponse:
    now = datetime.now(timezone.utc)
    code_hash = hashlib.sha256(payload.code.encode("utf-8")).hexdigest()
    grant = db.scalar(select(GoogleOAuthGrant).where(GoogleOAuthGrant.code_hash == code_hash))
    if grant is None:
        _record_google_login_failure(db, "invalid_or_expired_exchange_code")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google sign-in code is invalid or expired.",
        )

    result = db.execute(
        update(GoogleOAuthGrant)
        .where(
            GoogleOAuthGrant.id == grant.id,
            GoogleOAuthGrant.consumed_at.is_(None),
            GoogleOAuthGrant.expires_at > now,
        )
        .values(consumed_at=now)
    )
    if result.rowcount != 1:
        db.rollback()
        _record_google_login_failure(db, "invalid_or_expired_exchange_code")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google sign-in code is invalid or expired.",
        )

    user_id = grant.user_id
    user = db.get(User, user_id)
    if user is None:
        db.rollback()
        _record_google_login_failure(db, "account_unavailable")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google sign-in code is invalid or expired.",
        )
    record_event(
        db,
        actor_user_id=user_id,
        action="user_logged_in",
        resource_type="user",
        resource_id=str(user_id),
        details={"identifier": user.email, "provider": "google"},
    )
    db.commit()
    token, expires_in = create_access_token(user_id)
    return TokenResponse(access_token=token, expires_in=expires_in)
