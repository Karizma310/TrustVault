import mimetypes
from pathlib import Path
from uuid import uuid4
from datetime import date, datetime, time, timedelta, timezone
from typing import NoReturn

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import and_, or_, select
from sqlalchemy.exc import SQLAlchemyError

from app.api.deps import CurrentUser, DatabaseSession
from app.config import get_settings
from app.models.document import Document
from app.models.permission import Permission
from app.models.user import User
from app.schemas.document import DocumentRead, DocumentUpdate
from app.services.audit import record_event
from app.services.storage import (
    EmptyUploadError,
    InvalidUploadContentError,
    StorageError,
    UploadTooLargeError,
    remove_upload,
    save_upload,
    validate_upload_content,
)

router = APIRouter(prefix="/api/documents", tags=["documents"])
ALLOWED_EXTENSIONS = {
    ".csv",
    ".doc",
    ".docx",
    ".jpg",
    ".jpeg",
    ".pdf",
    ".png",
    ".txt",
    ".xls",
    ".xlsx",
}
WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _deny_request(
    db: DatabaseSession,
    *,
    actor_id: int,
    action: str,
    resource_id: str | None,
    reason: str,
    status_code: int,
    message: str,
) -> NoReturn:
    record_event(
        db,
        actor_user_id=actor_id,
        action=action,
        resource_type="document",
        resource_id=resource_id,
        details={"reason": reason},
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail=message)


def _validated_filename(file: UploadFile, db: DatabaseSession, actor_id: int) -> str:
    filename = file.filename or ""
    invalid = (
        not filename
        or len(filename) > 255
        or filename in {".", ".."}
        or filename.endswith((" ", "."))
        or any(ord(character) < 32 or character in '<>:"/\\|?*' for character in filename)
        or Path(filename).stem.rstrip(" .").upper() in WINDOWS_RESERVED_NAMES
    )
    if invalid:
        _deny_request(
            db,
            actor_id=actor_id,
            action="document_upload_denied",
            resource_id=None,
            reason="unsafe_filename",
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            message="The filename is invalid.",
        )
    return filename


@router.post("", response_model=DocumentRead, status_code=status.HTTP_201_CREATED)
async def upload_document(
    current_user: CurrentUser,
    db: DatabaseSession,
    file: UploadFile = File(...),
    title: str | None = Form(default=None, max_length=200),
    description: str | None = Form(default=None, max_length=5000),
) -> Document:
    filename = _validated_filename(file, db, current_user.id)
    suffix = Path(filename).suffix.casefold()
    if suffix not in ALLOWED_EXTENSIONS:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="unsupported_file_type",
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            message="This file type is not allowed.",
        )
    try:
        await validate_upload_content(
            file,
            filename,
            get_settings().max_upload_bytes,
        )
    except UploadTooLargeError:
        await file.close()
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="file_exceeds_size_limit",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            message="The uploaded file exceeds the configured size limit.",
        )
    except InvalidUploadContentError:
        await file.close()
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="file_content_does_not_match_extension",
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            message="The file contents do not match the selected file type.",
        )

    document_title = (title or filename).strip()
    if not document_title or len(document_title) > 200:
        await file.close()
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="invalid_title",
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            message="The document title must contain between 1 and 200 characters.",
        )
    settings = get_settings()
    try:
        storage_key, size_bytes = await save_upload(
            file,
            settings.upload_dir,
            settings.max_upload_bytes,
        )
    except UploadTooLargeError:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="file_exceeds_size_limit",
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            message="The uploaded file exceeds the configured size limit.",
        )
    except EmptyUploadError:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_upload_denied",
            resource_id=None,
            reason="empty_file",
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            message="Empty files cannot be uploaded.",
        )
    except StorageError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The private document could not be stored.",
        ) from error

    document = Document(
        id=str(uuid4()),
        owner_id=current_user.id,
        filename=filename,
        title=document_title,
        description=description,
        storage_key=storage_key,
        content_type=mimetypes.guess_type(filename)[0] or "application/octet-stream",
        size_bytes=size_bytes,
    )
    db.add(document)
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_uploaded",
        resource_type="document",
        resource_id=document.id,
    )
    try:
        db.commit()
    except SQLAlchemyError as error:
        db.rollback()
        remove_upload(settings.upload_dir, storage_key)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document metadata could not be saved.",
        ) from error
    db.refresh(document)
    return document


@router.get("", response_model=list[DocumentRead])
def list_documents(
    current_user: CurrentUser,
    db: DatabaseSession,
    q: str | None = Query(default=None, max_length=200),
    owner: str | None = Query(default=None, max_length=254),
    category: str | None = Query(default=None, max_length=10),
    since: date | None = None,
    until: date | None = None,
) -> list[Document]:
    if since is not None and until is not None and since > until:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="'since' must be earlier than or equal to 'until'.",
        )
    statement = (
        select(Document)
        .join(User, User.id == Document.owner_id)
        .where(Document.owner_id == current_user.id)
    )
    if q:
        conditions = []
        for word in q.split():
            search = f"%{word}%"
            conditions.append(
                or_(
                    Document.title.ilike(search),
                    Document.filename.ilike(search),
                    User.email.ilike(search),
                    User.display_name.ilike(search),
                )
            )
        if conditions:
            statement = statement.where(and_(*conditions))
    if owner:
        owner_search = f"%{owner.strip()}%"
        statement = statement.where(
            or_(User.email.ilike(owner_search), User.display_name.ilike(owner_search))
        )
    if category and category.casefold() != "all":
        extension = category.casefold().lstrip(".")
        if f".{extension}" not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="The requested document category is not supported.",
            )
        statement = statement.where(Document.filename.ilike(f"%.{extension}"))
    if since:
        statement = statement.where(
            Document.created_at >= datetime.combine(since, time.min, timezone.utc)
        )
    if until:
        statement = statement.where(
            Document.created_at < datetime.combine(until + timedelta(days=1), time.min, timezone.utc)
        )
    documents = list(db.scalars(statement.order_by(Document.created_at.desc())))
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_listed",
        resource_type="document",
        details={"result_count": str(len(documents))},
    )
    db.commit()
    return documents


@router.get("/shared-with-me", response_model=list[DocumentRead])
def list_shared_documents(current_user: CurrentUser, db: DatabaseSession) -> list[Document]:
    statement = (
        select(Document)
        .join(Permission, Permission.document_id == Document.id)
        .where(
            Permission.user_id == current_user.id,
            Permission.access_level == "read",
            Permission.revoked_at.is_(None),
        )
        .order_by(Document.created_at.desc())
    )
    documents = list(db.scalars(statement))
    record_event(
        db,
        actor_user_id=current_user.id,
        action="shared_documents_listed",
        resource_type="document",
        details={"result_count": str(len(documents))},
    )
    db.commit()
    return documents


@router.get("/{document_id}/download")
def download_document(
    document_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> FileResponse:
    document = db.get(Document, document_id)
    if document is None:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_access_denied",
            resource_id=document_id,
            reason="document_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
            message="Document not found.",
        )
    if document.owner_id != current_user.id:
        permission = db.scalar(
            select(Permission).where(
                Permission.document_id == document_id,
                Permission.user_id == current_user.id,
                Permission.access_level == "read",
                Permission.revoked_at.is_(None),
            )
        )
        if permission is None:
            _deny_request(
                db,
                actor_id=current_user.id,
                action="document_access_denied",
                resource_id=document_id,
                reason="permission_missing_or_revoked",
                status_code=status.HTTP_404_NOT_FOUND,
                message="Document not found.",
            )

    storage_path = get_settings().upload_dir / document.storage_key
    if not storage_path.is_file():
        record_event(
            db,
            actor_user_id=current_user.id,
            action="document_download_failed",
            resource_type="document",
            resource_id=document.id,
            details={"reason": "private_file_unavailable"},
        )
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The private document file is unavailable.",
        )
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_downloaded",
        resource_type="document",
        resource_id=document.id,
    )
    db.commit()
    return FileResponse(
        storage_path,
        media_type=document.content_type,
        filename=document.filename,
        headers={
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.patch("/{document_id}", response_model=DocumentRead)
def update_document(
    document_id: str,
    payload: DocumentUpdate,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Document:
    document = db.get(Document, document_id)
    if document is None or document.owner_id != current_user.id:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_edit_denied",
            resource_id=document_id,
            reason="not_owner_or_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
            message="Document not found.",
        )
    if not payload.model_fields_set:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="At least one document field must be provided.",
        )
    if "title" in payload.model_fields_set:
        title = (payload.title or "").strip()
        if not title:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="The document title cannot be empty.",
            )
        document.title = title
    if "description" in payload.model_fields_set:
        document.description = payload.description
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_edited",
        resource_type="document",
        resource_id=document.id,
        details={"fields": ",".join(sorted(payload.model_fields_set))},
    )
    db.commit()
    db.refresh(document)
    return document


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_document(
    document_id: str,
    current_user: CurrentUser,
    db: DatabaseSession,
) -> Response:
    document = db.get(Document, document_id)
    if document is None or document.owner_id != current_user.id:
        _deny_request(
            db,
            actor_id=current_user.id,
            action="document_delete_denied",
            resource_id=document_id,
            reason="not_owner_or_not_found",
            status_code=status.HTTP_404_NOT_FOUND,
            message="Document not found.",
        )
    settings = get_settings()
    storage_key = document.storage_key
    record_event(
        db,
        actor_user_id=current_user.id,
        action="document_deleted",
        resource_type="document",
        resource_id=document.id,
    )
    db.delete(document)
    db.commit()
    try:
        remove_upload(settings.upload_dir, storage_key)
    except StorageError as error:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Document metadata was deleted, but its private file could not be removed.",
        ) from error
    return Response(status_code=status.HTTP_204_NO_CONTENT)