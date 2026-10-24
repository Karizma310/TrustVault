from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, model_validator


class PermissionCreate(BaseModel):
    user_email: EmailStr | None = None
    user_id: int | None = Field(default=None, gt=0)

    @model_validator(mode="after")
    def require_one_recipient(self) -> "PermissionCreate":
        if (self.user_email is None) == (self.user_id is None):
            raise ValueError("Provide exactly one recipient email or user ID.")
        return self


class PermissionRead(BaseModel):
    id: int
    document_id: str
    user_id: int
    user_email: EmailStr
    access_level: str
    created_at: datetime
    revoked_at: datetime | None