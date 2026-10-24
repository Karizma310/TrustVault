from datetime import datetime, timezone
from typing import NoReturn

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.api.deps import CurrentUser, DatabaseSession
from app.models.document import Document
from app.models.notification import Notification
from app.models.permission import Permission
from app.models.user import User
from app.schemas.permission import PermissionCreate, PermissionRead
from app.services.audit import record_event

router = APIRouter(tags=["permissions"])


def _deny_permission_change(
    db: DatabaseSession,
    *,
    actor_id: int,
    document_id: str,
    action: str,
    reason: str,
    message: str,
    status_code: int = status.HTTP_404_NOT_FOUND,
) -> NoReturn:
    record_event(
        db,
        actor_user_id=actor_id,
        action=action,
        resource_type="document",
        resource_id=document_id,
        details={"reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail=message)


def _owned_document(
    db: DatabaseSession,
    document_id: str,
    user_id: int,
    action: str,
) -> Document:
    document = db.get(Document, document_id)
    if document is None or document.owner_id != user_id:
        _deny_permission_change(
            db,
            actor_id=user_id,
            document_id=document_id,
            action=action,
            reason="not_owner_or_not_found",
            message="Document not found.",
        )
    return document


def _permission_result(permission: Permission, user_email: str) -> PermissionRead:
    return PermissionRead(
        id=permission.id,
        document_id=permission.document_id,
        user_id=permission.user_id,
        user_email=user_email,
        access_level=permission.access_level,
        created_at=permission.created_at,
        revoked_at=permission.revoked_at,
    )


@router.get(
    "/api/documents/{document_id}/permissions",
    response_model=list[PermissionRead],
)
def list_permissions(
    document_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> list[PermissionRead]:
    _owned_document(db, document_id, current_user.id, "document_permissions_read_denied")
    rows = db.execute(
        select(Permission, User.email)
        .join(User, User.id == Permission.user_id)
        .where(Permission.document_id == document_id, Permission.revoked_at.is_(None))
        .order_by(Permission.created_at.desc())
    )
    permissions = [_permission_result(permission, email) for permission, email in rows]
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_permissions_listed",
        resource_type="document",
        resource_id=document_id,
        details={"result_count": str(len(permissions))},
    )
    db.commit()
    return permissions


@router.post(
    "/api/documents/{document_id}/permissions",
    response_model=PermissionRead,
    status_code=status.HTTP_201_CREATED,
)
def grant_permission(
    document_id: str,
    payload: PermissionCreate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> PermissionRead:
    document = _owned_document(
        db, document_id, current_user.id, "document_access_grant_denied"
    )
    if payload.user_id is not None:
        recipient = db.get(User, payload.user_id)
    else:
        target_email = str(payload.user_email).casefold()
        recipient = db.scalar(select(User).where(User.email == target_email))
    if recipient is None:
        _deny_permission_change(
            db,
            actor_id=current_user.id,
            document_id=document_id,
            action="document_access_grant_denied",
            reason="recipient_not_found",
            message="User not found.",
        )
    if recipient.id == current_user.id:
        _deny_permission_change(
            db,
            actor_id=current_user.id,
            document_id=document_id,
            action="document_access_grant_denied",
            reason="recipient_is_owner",
            message="You already own this document.",
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    permission = db.scalar(
        select(Permission).where(
            Permission.document_id == document_id,
            Permission.user_id == recipient.id,
        )
    )
    if permission is not None and permission.revoked_at is None:
        record_event(
            db,
            actor_user_id=current_user.id,
            action="document_access_grant_denied",
            resource_type="document",
            resource_id=document_id,
            details={"reason": "access_already_granted"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Access is already granted.",
        )
    if permission is None:
        permission = Permission(
            document_id=document_id,
            user_id=recipient.id,
            granted_by_id=current_user.id,
            access_level="read",
        )
        db.add(permission)
    else:
        permission.access_level = "read"
        permission.granted_by_id = current_user.id
        permission.created_at = datetime.now(timezone.utc)
        permission.revoked_at = None

    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_access_granted",
        resource_type="document",
        resource_id=document_id,
        details={"recipient_user_id": str(recipient.id), "access_level": "read"},
    )
    db.add(
        Notification(
            recipient_user_id=recipient.id,
            document_id=document_id,
            owner_name=current_user.display_name or current_user.email or "User",
            document_name=document.title,
            access_level="read",
        )
    )
    try:
        db.commit()
    except IntegrityError as error:
        db.rollback()
        record_event(
            db,
            actor_user_id=current_user.id,
            action="document_access_grant_denied",
            resource_type="document",
            resource_id=document_id,
            details={"reason": "access_already_granted"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Access is already granted.",
        ) from error
    db.refresh(permission)
    return _permission_result(permission, recipient.email)


@router.delete(
    "/api/documents/{document_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def revoke_permission(
    document_id: str,
    permission_id: int,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> None:
    _owned_document(
        db, document_id, current_user.id, "document_access_revoke_denied"
    )
    permission = db.scalar(
        select(Permission).where(
            Permission.id == permission_id,
            Permission.document_id == document_id,
            Permission.revoked_at.is_(None),
        )
    )
    if permission is None:
        _deny_permission_change(
            db,
            actor_id=current_user.id,
            document_id=document_id,
            action="document_access_revoke_denied",
            reason="active_permission_not_found",
            message="Active permission not found.",
        )

    permission.revoked_at = datetime.now(timezone.utc)
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_access_revoked",
        resource_type="document",
        resource_id=document_id,
        details={"recipient_user_id": str(permission.user_id)},
    )
    db.commit()