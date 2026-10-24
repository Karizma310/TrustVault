import codecs
from pathlib import Path
from uuid import uuid4
import zipfile

from fastapi import UploadFile


class UploadTooLargeError(Exception):
    pass


class EmptyUploadError(Exception):
    pass


class StorageError(Exception):
    pass


class InvalidUploadContentError(Exception):
    pass


async def validate_upload_content(
    upload: UploadFile,
    filename: str,
    max_bytes: int,
) -> None:
    if upload.size is not None and upload.size > max_bytes:
        raise UploadTooLargeError
    prefix = await upload.read(8192)
    await upload.seek(0)
    extension = Path(filename).suffix.casefold()

    signatures = {
        ".pdf": prefix.startswith(b"%PDF-"),
        ".png": prefix.startswith(b"\x89PNG\r\n\x1a\n"),
        ".jpg": prefix.startswith(b"\xff\xd8\xff"),
        ".jpeg": prefix.startswith(b"\xff\xd8\xff"),
        ".doc": prefix.startswith(bytes.fromhex("D0CF11E0A1B11AE1")),
        ".xls": prefix.startswith(bytes.fromhex("D0CF11E0A1B11AE1")),
        ".docx": prefix.startswith(b"PK\x03\x04"),
        ".xlsx": prefix.startswith(b"PK\x03\x04"),
    }
    if extension in signatures:
        if not signatures[extension]:
            raise InvalidUploadContentError
        if extension in {".docx", ".xlsx"}:
            try:
                with zipfile.ZipFile(upload.file) as archive:
                    expected_entry = (
                        "word/document.xml" if extension == ".docx" else "xl/workbook.xml"
                    )
                    if expected_entry not in archive.namelist():
                        raise InvalidUploadContentError
            except (OSError, zipfile.BadZipFile) as error:
                raise InvalidUploadContentError from error
            finally:
                await upload.seek(0)
        return

    if extension in {".txt", ".csv"}:
        decoder = codecs.getincrementaldecoder("utf-8-sig")()
        size_bytes = 0
        try:
            while chunk := await upload.read(64 * 1024):
                size_bytes += len(chunk)
                if size_bytes > max_bytes:
                    raise UploadTooLargeError
                if b"\x00" in chunk:
                    raise InvalidUploadContentError
                decoder.decode(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError as error:
            raise InvalidUploadContentError from error
        finally:
            await upload.seek(0)
        return

    raise InvalidUploadContentError


async def save_upload(
    upload: UploadFile,
    directory: Path,
    max_bytes: int,
) -> tuple[str, int]:
    storage_key = uuid4().hex
    temporary_path = directory / f".{storage_key}.part"
    final_path = directory / storage_key
    size_bytes = 0

    try:
        with temporary_path.open("xb") as destination:
            while chunk := await upload.read(64 * 1024):
                size_bytes += len(chunk)
                if size_bytes > max_bytes:
                    raise UploadTooLargeError
                destination.write(chunk)
        if size_bytes == 0:
            raise EmptyUploadError
        temporary_path.replace(final_path)
    except (OSError, UploadTooLargeError, EmptyUploadError) as error:
        temporary_path.unlink(missing_ok=True)
        if isinstance(error, OSError):
            raise StorageError("The private document could not be stored.") from error
        raise
    finally:
        await upload.close()

    return storage_key, size_bytes


def remove_upload(directory: Path, storage_key: str) -> None:
    path = directory / storage_key
    if path.parent != directory or not storage_key.isalnum():
        raise ValueError("Invalid private storage key.")
    try:
        path.unlink(missing_ok=True)
    except OSError as error:
        raise StorageError("The private document could not be removed.") from error