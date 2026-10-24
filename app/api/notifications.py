from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Response, status
from sqlalchemy import select

from app.api.deps import CurrentUser, DatabaseSession
from app.models.notification import Notification
from app.schemas.notification import NotificationList, NotificationRead

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("", response_model=NotificationList)
def list_notifications(
    current_user: CurrentUser,
    db: DatabaseSession,
    response: Response,
) -> NotificationList:
    response.headers["Cache-Control"] = "no-store"
    notifications = list(
        db.scalars(
            select(Notification)
            .where(Notification.recipient_user_id == current_user.id)
            .order_by(Notification.created_at.desc(), Notification.id.desc())
        )
    )
    return NotificationList(
        items=[NotificationRead.model_validate(item) for item in notifications],
        total_count=len(notifications),
        unread_count=sum(item.read_at is None for item in notifications),
        notifications_enabled=current_user.notifications_enabled,
    )


@router.post("/{notification_id}/read", response_model=NotificationRead)
def mark_notification_read(
    notification_id: int,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Notification:
    notification = db.scalar(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.recipient_user_id == current_user.id,
        )
    )
    if notification is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found.")
    if notification.read_at is None:
        notification.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(notification)
    return notification


@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
def dismiss_notification(
    notification_id: int,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> None:
    notification = db.scalar(
        select(Notification).where(
            Notification.id == notification_id,
            Notification.recipient_user_id == current_user.id,
        )
    )
    if notification is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found.")
    db.delete(notification)
    db.commit()
