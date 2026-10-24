import csv
import json
from datetime import datetime, timezone
from io import StringIO
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy import or_, select

from app.api.deps import AdminUser, DatabaseSession
from app.models.audit_log import AuditLog
from app.models.user import User
from app.schemas.admin import AdminLoginActivityRead, AdminUserRead
from app.schemas.audit_log import AuditLogRead

router = APIRouter(prefix="/api/admin", tags=["administration"])


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _admin_audit_query(
    action: str | None,
    since: datetime | None,
    until: datetime | None,
    limit: int,
):
    since_utc = _as_utc(since) if since is not None else None
    until_utc = _as_utc(until) if until is not None else None
    if since_utc is not None and until_utc is not None and since_utc > until_utc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="'since' must be earlier than or equal to 'until'.",
        )
    statement = select(AuditLog)
    if action:
        statement = statement.where(AuditLog.action == action)
    if since_utc:
        statement = statement.where(AuditLog.created_at >= since_utc)
    if until_utc:
        statement = statement.where(AuditLog.created_at <= until_utc)
    return statement.order_by(AuditLog.created_at.desc()).limit(limit)


@router.get("/audit", response_model=list[AuditLogRead])
def list_admin_audit_logs(
    _admin: AdminUser,
    db: DatabaseSession,
    response: Response,
    action: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditLog]:
    response.headers["Cache-Control"] = "private, no-store"
    return list(db.scalars(_admin_audit_query(action, since, until, limit)))


@router.get("/users", response_model=list[AdminUserRead])
def list_registered_users(
    _admin: AdminUser,
    db: DatabaseSession,
    response: Response,
    q: Annotated[str | None, Query(max_length=254)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[User]:
    response.headers["Cache-Control"] = "private, no-store"
    statement = select(User)
    if q:
        statement = statement.where(
            or_(User.email.ilike(f"%{q.strip()}%"), User.display_name.ilike(f"%{q.strip()}%"))
        )
    return list(
        db.scalars(
            statement.order_by(User.created_at.desc(), User.id.desc())
            .limit(limit)
            .offset(offset)
        )
    )


@router.get("/login-activity", response_model=list[AdminLoginActivityRead])
def list_login_activity(
    _admin: AdminUser,
    db: DatabaseSession,
    response: Response,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AdminLoginActivityRead]:
    response.headers["Cache-Control"] = "private, no-store"
    entries = db.scalars(
        select(AuditLog)
        .where(
            AuditLog.action.in_(
                ("user_logged_in", "user_login_failed", "user_logged_out")
            )
        )
        .order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
        .limit(limit)
        .offset(offset)
    )
    activity = []
    for entry in entries:
        details = json.loads(entry.details_json) if entry.details_json else {}
        user = db.get(User, entry.actor_user_id) if entry.actor_user_id else None
        activity.append(
            AdminLoginActivityRead(
                id=entry.id,
                user_id=entry.actor_user_id,
                identifier=details.get("identifier") or (user.email if user else None),
                outcome={
                    "user_logged_in": "success",
                    "user_login_failed": "failure",
                    "user_logged_out": "logout",
                }[entry.action],
                provider=details.get("provider"),
                created_at=entry.created_at,
            )
        )
    return activity


@router.get("/audit/export.csv")
def export_admin_audit_logs(
    _admin: AdminUser,
    db: DatabaseSession,
    action: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 500,
) -> StreamingResponse:
    rows = db.scalars(_admin_audit_query(action, since, until, limit))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["id", "timestamp", "actor_user_id", "action", "resource_type", "resource_id", "details"]
    )
    for entry in rows:
        writer.writerow(
            [
                entry.id,
                entry.created_at.isoformat(),
                entry.actor_user_id or "",
                entry.action,
                entry.resource_type,
                entry.resource_id or "",
                entry.details_json or "",
            ]
        )
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="trustvault-admin-audit.csv"',
            "Cache-Control": "private, no-store",
        },
    )
