import argparse
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import get_settings
from app.database import get_engine, initialize_database
from app.models.document import Document
from app.models.notification import Notification
from app.models.permission import Permission
from app.models.user import User
from app.services.audit import record_event


@dataclass(frozen=True)
class DemoDocument:
    slug: str
    filename: str
    title: str
    description: str
    contents: bytes
    share_with_viewer: bool = False


DEMO_DOCUMENTS = (
    DemoDocument(
        slug="owner-only",
        filename="trustvault-demo-private.txt",
        title="Demo: owner-only document",
        description="Synthetic TrustVault demo content; no private information.",
        contents=(
            b"TrustVault demo file - synthetic sample data only.\n"
            b"This document is private to its owner unless access is granted.\n"
        ),
    ),
    DemoDocument(
        slug="shared-read-only",
        filename="trustvault-demo-shared.txt",
        title="Demo: shared read-only document",
        description="Synthetic TrustVault demo content shared with Viewer as read-only.",
        contents=(
            b"TrustVault demo file - synthetic sample data only.\n"
            b"The demo Viewer can download this file while access is active.\n"
        ),
        share_with_viewer=True,
    ),
)


def _fixture_uuid(owner_id: int, slug: str) -> str:
    return str(uuid5(NAMESPACE_URL, f"trustvault-demo:{owner_id}:{slug}"))


def _fixture_storage_key(owner_id: int, slug: str) -> str:
    return uuid5(NAMESPACE_URL, f"trustvault-demo:{owner_id}:{slug}:storage").hex


def _upload_directory() -> Path:
    configured_directory = get_settings().upload_dir
    if configured_directory.is_absolute():
        return configured_directory
    return (PROJECT_ROOT / configured_directory).resolve()


def _write_fixture_file(
    path: Path,
    contents: bytes,
    created_files: list[tuple[Path, bool]],
    document_is_new: bool,
) -> None:
    with path.open("xb") as destination:
        created_files.append((path, document_is_new))
        destination.write(contents)


def _clean_up_files(files: list[tuple[Path, bool]], *, new_documents_only: bool) -> None:
    first_error: OSError | None = None
    for path, document_is_new in files:
        if new_documents_only and not document_is_new:
            continue
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise OSError("A partially created demo file could not be removed.") from first_error


def seed_demo_data(admin_email: str, owner_email: str, viewer_email: str) -> tuple[int, int]:
    initialize_database()
    emails = [email.strip().casefold() for email in (admin_email, owner_email, viewer_email)]
    if len(set(emails)) != len(emails):
        raise ValueError("Admin, Owner, and Viewer must be three different accounts.")

    with Session(get_engine()) as db:
        users = {
            email: db.scalar(select(User).where(User.email == email))
            for email in emails
        }
        missing = [email for email, user in users.items() if user is None]
        if missing:
            raise ValueError(
                "Register the demo accounts before seeding data: " + ", ".join(missing)
            )

        admin = users[emails[0]]
        owner = users[emails[1]]
        viewer = users[emails[2]]
        if admin is None or owner is None or viewer is None:
            raise RuntimeError("Demo-account lookup returned an unexpected empty result.")
        if admin.role != "admin":
            raise ValueError(
                "The selected Admin account is not an administrator. "
                "Register it, then assign its role with scripts/set_admin_role.py."
            )
        if owner.role != "user" or viewer.role != "user":
            raise ValueError("The demo Owner and Viewer accounts must have the regular User role.")

        upload_directory = _upload_directory()
        planned_documents: list[tuple[DemoDocument, Document, bool, Path]] = []
        for sample in DEMO_DOCUMENTS:
            document_id = _fixture_uuid(owner.id, sample.slug)
            storage_key = _fixture_storage_key(owner.id, sample.slug)
            document = db.get(Document, document_id)
            document_is_new = document is None
            expected = {
                "owner_id": owner.id,
                "filename": sample.filename,
                "title": sample.title,
                "description": sample.description,
                "storage_key": storage_key,
                "content_type": "text/plain",
                "size_bytes": len(sample.contents),
            }
            if document is not None and any(
                getattr(document, field) != value for field, value in expected.items()
            ):
                raise ValueError(
                    "A document conflicts with the TrustVault demo fixture; "
                    "no existing document was changed."
                )
            planned_documents.append(
                (
                    sample,
                    document
                    or Document(
                        id=document_id,
                        **expected,
                    ),
                    document_is_new,
                    upload_directory / storage_key,
                )
            )

        shared_document = next(
            document
            for sample, document, _is_new, _path in planned_documents
            if sample.share_with_viewer
        )
        existing_permission = db.scalar(
            select(Permission).where(
                Permission.document_id == shared_document.id,
                Permission.user_id == viewer.id,
            )
        )
        if (
            existing_permission is not None
            and existing_permission.revoked_at is None
            and existing_permission.access_level != "read"
        ):
            raise ValueError(
                "The seeded Viewer permission is not read-only; "
                "no existing permission was changed."
            )

        created_files: list[tuple[Path, bool]] = []
        try:
            for sample, document, document_is_new, storage_path in planned_documents:
                if document_is_new:
                    _write_fixture_file(
                        storage_path,
                        sample.contents,
                        created_files,
                        document_is_new=True,
                    )
                elif not storage_path.is_file():
                    _write_fixture_file(
                        storage_path,
                        sample.contents,
                        created_files,
                        document_is_new=False,
                    )

            permission_changes = 0
            for sample, document, document_is_new, _storage_path in planned_documents:
                if document_is_new:
                    db.add(document)
                    record_event(
                        db,
                        actor_user_id=owner.id,
                        action="demo_document_seeded",
                        resource_type="document",
                        resource_id=document.id,
                        details={"source": "demo_seed"},
                    )
                if not sample.share_with_viewer:
                    continue

                permission = db.scalar(
                    select(Permission).where(
                        Permission.document_id == document.id,
                        Permission.user_id == viewer.id,
                    )
                )
                if permission is not None and permission.revoked_at is None:
                    if permission.access_level != "read":
                        raise ValueError(
                            "The seeded Viewer permission is not read-only; "
                            "no existing permission was changed."
                        )
                    continue

                if permission is None:
                    permission = Permission(
                        document_id=document.id,
                        user_id=viewer.id,
                        granted_by_id=owner.id,
                        access_level="read",
                    )
                    db.add(permission)
                else:
                    permission.granted_by_id = owner.id
                    permission.access_level = "read"
                    permission.created_at = datetime.now(timezone.utc)
                    permission.revoked_at = None
                record_event(
                    db,
                    actor_user_id=owner.id,
                    action="document_access_granted",
                    resource_type="document",
                    resource_id=document.id,
                    details={
                        "recipient_user_id": str(viewer.id),
                        "access_level": "read",
                        "source": "demo_seed",
                    },
                )
                db.add(
                    Notification(
                        recipient_user_id=viewer.id,
                        document_id=document.id,
                        owner_name=owner.display_name or owner.email,
                        document_name=document.title,
                        access_level="read",
                    )
                )
                permission_changes += 1

            try:
                db.commit()
            except SQLAlchemyError:
                db.rollback()
                _clean_up_files(created_files, new_documents_only=True)
                raise
            return len(DEMO_DOCUMENTS), permission_changes
        except (OSError, ValueError):
            _clean_up_files(created_files, new_documents_only=False)
            raise


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Create private synthetic demo documents for already-registered "
            "TrustVault Admin, Owner, and Viewer accounts."
        )
    )
    parser.add_argument("--admin-email", required=True, help="Registered account with Admin role")
    parser.add_argument("--owner-email", required=True, help="Registered regular account to own samples")
    parser.add_argument("--viewer-email", required=True, help="Registered regular account to receive read access")
    args = parser.parse_args()

    try:
        document_count, permission_count = seed_demo_data(
            args.admin_email,
            args.owner_email,
            args.viewer_email,
        )
    except ValueError as error:
        parser.error(str(error))
    except SQLAlchemyError:
        parser.error(
            "The database operation failed. Check the configured database and retry; "
            "no account passwords are read or changed."
        )
    print(
        "Demo data is ready: "
        f"{document_count} synthetic private documents; "
        f"{permission_count} read-only permission(s) added or restored. "
        "No passwords were created or changed."
    )


if __name__ == "__main__":
    main()
