"""Workbooks parse however the sandbox names its input (review finding C-1).

The sandbox stores every download as ``input`` - no extension - and openpyxl
refuses a *path* without an Excel extension, so every XLSX upload failed in
production while the unit tests, which named their files ``*.xlsx``, passed.
"""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import openpyxl
import pytest

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.sources.model import FileUploadConfig
from nexusflow.infrastructure.files.parsers import parse_upload

CONFIG = FileUploadConfig.model_validate(
    {"kind": "file_upload", "format": "xlsx", "column_mapping": {"sku": "SKU", "price": "Price"}}
)


def _workbook(*rows: tuple[object, ...]) -> bytes:
    book = openpyxl.Workbook()
    sheet = book.active
    assert sheet is not None
    sheet.append(["SKU", "Price"])
    for row in rows:
        sheet.append(list(row))
    buffer = io.BytesIO()
    book.save(buffer)
    return buffer.getvalue()


def test_a_workbook_stored_without_an_extension_is_parsed(tmp_path: Path) -> None:
    path = tmp_path / "input"  # exactly how the sandbox stores the download
    path.write_bytes(_workbook(("A-1", 1.5), ("A-2", 2)))

    parsed = parse_upload(path, CONFIG, max_rows=100, max_columns=10)

    assert parsed.items == [{"sku": "A-1", "price": 1.5}, {"sku": "A-2", "price": 2}]
    assert parsed.rows == 2 and not parsed.truncated


def _with_cell_xml(workbook: bytes, old: bytes, new: bytes) -> bytes:
    """The workbook with one cell's stored value rewritten, as another program might."""
    source = zipfile.ZipFile(io.BytesIO(workbook))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                assert old in data
                data = data.replace(old, new)
            target.writestr(info, data)
    return out.getvalue()


def test_a_number_that_is_not_finite_is_a_malformed_upload(tmp_path: Path) -> None:
    # 1E999 reads as infinity; serialised as JSON "Infinity" the gateway would
    # refuse the whole result instead of reporting a malformed file.
    path = tmp_path / "input"
    path.write_bytes(_with_cell_xml(_workbook(("A-1", 1.5)), b"<v>1.5</v>", b"<v>1E999</v>"))

    with pytest.raises(InvalidInputError) as refused:
        parse_upload(path, CONFIG, max_rows=100, max_columns=10)
    assert refused.value.code == "upload_malformed"


def test_something_that_is_not_a_workbook_is_malformed_not_a_crash(tmp_path: Path) -> None:
    path = tmp_path / "input"
    path.write_bytes(b"PK\x03\x04 not really a zip archive")

    with pytest.raises(InvalidInputError) as refused:
        parse_upload(path, CONFIG, max_rows=100, max_columns=10)
    assert refused.value.code == "upload_malformed"
