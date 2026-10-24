import csv
from datetime import datetime, timezone
from io import StringIO
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from app.api.deps import CurrentUser, DatabaseSession
from app.models.audit_log import AuditLog
from app.schemas.audit_log import AuditLogRead

router = APIRouter(prefix="/api/audit", tags=["audit"])


def _user_audit_query(
    user_id: int,
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
    statement = select(AuditLog).where(AuditLog.actor_user_id == user_id)
    if action:
        statement = statement.where(AuditLog.action == action)
    if since_utc:
        statement = statement.where(AuditLog.created_at >= since_utc)
    if until_utc:
        statement = statement.where(AuditLog.created_at <= until_utc)
    return statement.order_by(AuditLog.created_at.desc()).limit(limit)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@router.get("", response_model=list[AuditLogRead])
def list_audit_logs(
    current_user: CurrentUser,
    db: DatabaseSession,
    action: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> list[AuditLog]:
    statement = _user_audit_query(current_user.id, action, since, until, limit)
    return list(db.scalars(statement))


@router.get("/export.csv")
def export_audit_logs(
    current_user: CurrentUser,
    db: DatabaseSession,
    action: Annotated[str | None, Query(max_length=64)] = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 500,
) -> StreamingResponse:
    rows = db.scalars(_user_audit_query(current_user.id, action, since, until, limit))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(
        ["id", "timestamp", "action", "resource_type", "resource_id", "details"]
    )
    for entry in rows:
        writer.writerow(
            [
                entry.id,
                entry.created_at.isoformat(),
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
        headers={"Content-Disposition": 'attachment; filename="trustvault-audit.csv"'},
    )
