from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    document_id: str
    owner_name: str
    document_name: str
    access_level: str
    created_at: datetime
    read_at: datetime | None


class NotificationList(BaseModel):
    items: list[NotificationRead]
    total_count: int
    unread_count: int
    notifications_enabled: bool
