import logging
import smtplib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, DatabaseSession
from app.config import Settings, get_settings
from app.database import get_engine
from app.models.user import User
from app.models.password_reset_token import PasswordResetToken
from app.schemas.password_reset import (
    PasswordResetConfirm,
    PasswordResetMessage,
    PasswordResetRequest,
)
from app.schemas.user import (
    LoginRequest,
    ProfileUpdate,
    TokenResponse,
    UserCreate,
    UserPreferencesRead,
    UserPreferencesUpdate,
    UserRead,
)
from app.services.audit import record_event
from app.services.password_reset import (
    build_reset_url,
    create_reset_token,
    hash_reset_token,
    send_password_reset_email,
)
from app.services.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/auth", tags=["authentication"])
logger = logging.getLogger(__name__)


def _deliver_password_reset_email(
    email: str,
    reset_url: str,
    token_hash: str,
    user_id: int,
    settings: Settings,
) -> None:
    try:
        send_password_reset_email(email, reset_url, settings)
    except (OSError, smtplib.SMTPException, ValueError) as error:
        logger.error(
            "Password reset email delivery failed (%s).",
            type(error).__name__,
        )
        with Session(get_engine()) as db:
            db.execute(
                update(PasswordResetToken)
                .where(
                    PasswordResetToken.user_id == user_id,
                    PasswordResetToken.token_hash == token_hash,
                    PasswordResetToken.used_at.is_(None),
                )
                .values(used_at=datetime.now(timezone.utc))
            )
            db.commit()


@router.post(
    "/password-reset/request",
    response_model=PasswordResetMessage,
    status_code=status.HTTP_202_ACCEPTED,
)
def request_password_reset(
    payload: PasswordResetRequest,
    db: DatabaseSession,
    background_tasks: BackgroundTasks,
    settings: Settings = Depends(get_settings),
) -> PasswordResetMessage:
    message = PasswordResetMessage(
        message=(
            "If an account exists and email delivery is configured, reset instructions "
            "will be sent if delivery succeeds."
        )
    )
    if not settings.password_reset_email_configured:
        logger.warning("Password reset requested while email delivery is not configured.")
        return message

    email = str(payload.email).casefold()
    user = db.scalar(select(User).where(User.email == email))
    if user is None:
        return message

    now = datetime.now(timezone.utc)
    token = create_reset_token()
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    db.add(
        PasswordResetToken(
            user_id=user.id,
            token_hash=hash_reset_token(token),
            expires_at=now + timedelta(minutes=settings.password_reset_minutes),
        )
    )
    db.commit()

    reset_url = build_reset_url(token, settings.frontend_login_url)
    background_tasks.add_task(
        _deliver_password_reset_email,
        user.email,
        reset_url,
        hash_reset_token(token),
        user.id,
        settings,
    )
    return message


@router.post(
    "/password-reset/confirm",
    response_model=PasswordResetMessage,
)
def confirm_password_reset(
    payload: PasswordResetConfirm,
    db: DatabaseSession,
) -> PasswordResetMessage:
    now = datetime.now(timezone.utc)
    token_hash = hash_reset_token(payload.token)
    reset = db.scalar(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )
    if reset is None or reset.used_at is not None or reset.expires_at <= now:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password reset link is invalid or has expired.",
        )

    result = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.id == reset.id,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
    )
    if result.rowcount != 1:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password reset link is invalid or has expired.",
        )

    user = db.get(User, reset.user_id)
    if user is None:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This password reset link is invalid or has expired.",
        )
    user.password_hash = hash_password(payload.new_password)
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.id != reset.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=now)
    )
    db.commit()
    return PasswordResetMessage(message="Your password has been reset. You can now sign in.")


@router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: UserCreate, db: DatabaseSession) -> User:
    email = str(payload.email).casefold()
    if db.scalar(select(User).where(User.email == email)) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email is already registered.")

    display_name = payload.display_name.strip() if payload.display_name else None
    user = User(
        email=email,
        display_name=display_name or None,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    try:
        db.flush()
        record_event(
            db,
            actor_user_id=user.id,
            action="user_registered",
            resource_type="user",
            resource_id=str(user.id),
        )
        db.commit()
    except IntegrityError as error:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered.",
        ) from error
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: DatabaseSession) -> TokenResponse:
    email = str(payload.email).casefold()
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(payload.password, user.password_hash):
        record_event(
            db,
            actor_user_id=None,
            action="user_login_failed",
            resource_type="user",
            details={"identifier": email, "provider": "password"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_access_token(user.id)
    record_event(
        db,
        actor_user_id=user.id,
        action="user_logged_in",
        resource_type="user",
        resource_id=str(user.id),
        details={"identifier": user.email, "provider": "password"},
    )
    db.commit()
    return TokenResponse(access_token=token, expires_in=expires_in)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(current_user: CurrentUser, db: DatabaseSession) -> Response:
    record_event(
        db,
        actor_user_id=current_user.id,
        action="user_logged_out",
        resource_type="user",
        resource_id=str(current_user.id),
        details={"identifier": current_user.email},
    )
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserRead)
def read_current_user(current_user: CurrentUser, response: Response) -> User:
    response.headers["Cache-Control"] = "no-store"
    return current_user


@router.patch("/me", response_model=UserRead)
def update_current_user(
    payload: ProfileUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> User:
    if "display_name" in payload.model_fields_set:
        display_name = payload.display_name.strip() if payload.display_name else ""
        current_user.display_name = display_name or None
        db.commit()
        db.refresh(current_user)
    return current_user


@router.get("/preferences", response_model=UserPreferencesRead)
def read_user_preferences(current_user: CurrentUser, response: Response) -> User:
    response.headers["Cache-Control"] = "no-store"
    return UserPreferencesRead(
        user_id=current_user.id,
        notifications_enabled=current_user.notifications_enabled,
        theme=current_user.theme,
    )


@router.patch("/preferences", response_model=UserPreferencesRead)
def update_user_preferences(
    payload: UserPreferencesUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> UserPreferencesRead:
    if not payload.model_fields_set:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="At least one preference must be provided.",
        )
    if (
        "notifications_enabled" in payload.model_fields_set
        and payload.notifications_enabled is None
    ):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="notifications_enabled must be a boolean.",
        )
    if payload.notifications_enabled is not None:
        current_user.notifications_enabled = payload.notifications_enabled
    if payload.theme is not None:
        current_user.theme = payload.theme
    db.commit()
    db.refresh(current_user)
    return UserPreferencesRead(
        user_id=current_user.id,
        notifications_enabled=current_user.notifications_enabled,
        theme=current_user.theme,
    )