from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr


class AdminUserRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: EmailStr
    display_name: str | None
    role: Literal["user", "admin"]
    created_at: datetime


class AdminLoginActivityRead(BaseModel):
    id: int
    user_id: int | None
    identifier: str | None
    outcome: Literal["success", "failure", "logout"]
    provider: Literal["password", "google"] | None
    created_at: datetime
