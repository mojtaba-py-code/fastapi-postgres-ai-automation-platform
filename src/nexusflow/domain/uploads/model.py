"""Uploaded data files and their content inspection.

Uploads are treated as hostile input:

* the declared extension / MIME type is never trusted - the content is sniffed;
* stored names are generated server-side (``<uuid>.<ext>``) under a tenant
  directory, so user-supplied names can never influence filesystem paths;
* XLSX containers are inspected *before* parsing: entry count, path traversal
  names, encrypted entries, macro payloads and zip-bomb compression ratios;
* CSV must be valid UTF-8 text without NUL bytes;
* files are never executed, and parsing happens in the isolated sandbox worker.
"""

from __future__ import annotations

import codecs
import zipfile
import zlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import UUID

from nexusflow.core.errors import InvalidInputError
from nexusflow.core.text import clean_text

MAX_XLSX_ENTRIES = 5_000
MAX_XLSX_UNCOMPRESSED = 200 * 1024 * 1024
MAX_COMPRESSION_RATIO = 150
_BINARY_SIGNATURES = (b"PK\x03\x04", b"%PDF", b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe", b"\x1f\x8b")
_MACRO_MARKERS = ("vbaproject.bin", "macroenabled", "activex")
# Excel finds a VBA project or ActiveX control through the package's content
# types and relationships, not by file name, so those are checked too.
_MACRO_DECLARATIONS = (b"macroenabled", b"vbaproject", b"activex")
_MANIFESTS = ("[content_types].xml", "xl/_rels/workbook.xml.rels")
_MAX_MANIFEST_BYTES = 1_000_000


class UploadStatus(StrEnum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"


type UploadFormat = Literal["csv", "xlsx"]

CONTENT_TYPES: dict[str, str] = {
    "csv": "text/csv",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


@dataclass(eq=False, kw_only=True)
class Upload:
    id: UUID
    org_id: UUID
    source_id: UUID
    original_filename: str
    storage_key: str
    content_type: str
    size_bytes: int
    sha256: str
    status: UploadStatus = UploadStatus.ACCEPTED
    rejection_reason: str | None = None
    row_count: int | None = None
    uploaded_by: UUID | None = None
    run_id: UUID | None = None
    created_at: datetime
    processed_at: datetime | None = None

    def fail(self, now: datetime, *, reason: str) -> None:
        """The run for this file ended without storing it. Failed uploads leave
        ``uq_uploads_live_sha256``, so the same file can be uploaded again."""
        if self.status in (UploadStatus.FAILED, UploadStatus.REJECTED):
            return
        self.status = UploadStatus.FAILED
        self.rejection_reason = reason[:64]
        self.processed_at = self.processed_at or now


def display_filename(name: str | None) -> str:
    """Last path component only, normalized - for display, never for storage."""
    base = PurePosixPath((name or "upload").replace("\\", "/")).name
    return clean_text(base, max_length=200) or "upload"


def storage_key(org_id: UUID, upload_id: UUID, fmt: UploadFormat) -> str:
    return f"uploads/{org_id}/{upload_id}.{fmt}"


def _reject(reason: str, message: str) -> InvalidInputError:
    return InvalidInputError(message, code=f"upload_{reason}")


def inspect_file(path: Path, *, expected: UploadFormat) -> None:
    """Content-based validation; raises ``InvalidInputError`` on rejection."""
    with path.open("rb") as handle:
        head = handle.read(8)
    if expected == "xlsx":
        if not head.startswith(b"PK\x03\x04"):
            raise _reject("type_mismatch", "The file is not a valid XLSX workbook.")
        _inspect_xlsx(path)
    else:
        if head.startswith(_BINARY_SIGNATURES):
            raise _reject("type_mismatch", "The file is not a CSV text file.")
        _inspect_csv(path)


def _inspect_xlsx(path: Path) -> None:
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_XLSX_ENTRIES:
                raise _reject("too_many_entries", "The workbook contains too many parts.")
            names = set()
            total = 0
            for entry in entries:
                name = entry.filename
                lowered = name.lower()
                if (
                    name.startswith(("/", "\\"))
                    or ".." in PurePosixPath(name.replace("\\", "/")).parts
                ):
                    raise _reject("path_traversal", "The workbook contains unsafe paths.")
                if entry.flag_bits & 0x1:
                    raise _reject("encrypted", "Encrypted workbooks are not supported.")
                if any(marker in lowered for marker in _MACRO_MARKERS):
                    raise _reject("macro", "Macro-enabled workbooks are not accepted.")
                if lowered in names:
                    # Two parts with one name: which one a reader takes is up to the reader.
                    raise _reject("duplicate_entries", "The workbook contains duplicate parts.")
                total += entry.file_size
                ratio = entry.file_size / max(entry.compress_size, 1)
                if total > MAX_XLSX_UNCOMPRESSED or (
                    entry.file_size > 1_000_000 and ratio > MAX_COMPRESSION_RATIO
                ):
                    raise _reject("zip_bomb", "The workbook expands to an unsafe size.")
                names.add(lowered)
            if "[content_types].xml" not in names or "xl/workbook.xml" not in names:
                raise _reject("type_mismatch", "The file is not a valid XLSX workbook.")
            by_name = {entry.filename.lower(): entry for entry in entries}
            for manifest in _MANIFESTS:
                if manifest in by_name and _declares_macros(archive, by_name[manifest]):
                    raise _reject("macro", "Macro-enabled workbooks are not accepted.")
    except (zipfile.BadZipFile, NotImplementedError, zlib.error, EOFError) as exc:
        raise _reject("corrupt", "The workbook is corrupt.") from exc


def _declares_macros(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> bool:
    """Whether a package manifest declares a VBA project, macros or ActiveX.

    A plain byte search - no XML parsing of untrusted input here - over at most
    ``_MAX_MANIFEST_BYTES`` of output, whatever size the archive claims.
    """
    with archive.open(entry) as member:
        data = member.read(_MAX_MANIFEST_BYTES + 1)
    if len(data) > _MAX_MANIFEST_BYTES:
        raise _reject("zip_bomb", "The workbook expands to an unsafe size.")
    lowered = data.lower()
    return any(marker in lowered for marker in _MACRO_DECLARATIONS)


def _inspect_csv(path: Path) -> None:
    if path.stat().st_size == 0:
        raise _reject("empty", "The file is empty.")
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                if b"\x00" in chunk:
                    raise _reject("binary", "The CSV file contains binary data.")
                decoder.decode(chunk)
            decoder.decode(b"", final=True)
    except UnicodeDecodeError as exc:
        raise _reject("encoding", "CSV files must be UTF-8 encoded.") from exc
