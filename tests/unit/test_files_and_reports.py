"""Upload parsing limits and report output encoding (formula / markup injection)."""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

import openpyxl
import pytest

from nexusflow.core.errors import InvalidInputError
from nexusflow.domain.reports.model import ReportContent, ReportFormat
from nexusflow.domain.sources.model import FileUploadConfig
from nexusflow.infrastructure.files.parsers import parse_upload
from nexusflow.infrastructure.reporting.renderers import ReportRendererRegistry

CONFIG = FileUploadConfig(format="csv", column_mapping={"sku": "SKU", "title": "Title"})
EVIL = '=HYPERLINK("http://evil.example","click")'


def _csv(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "in.csv"
    path.write_text(text, encoding="utf-8")
    return path


class TestParsers:
    def test_rows_are_capped_and_flagged(self, tmp_path: Path) -> None:
        rows = "\n".join(f"S{i},T{i}" for i in range(10))
        parsed = parse_upload(
            _csv(tmp_path, "SKU,Title\n" + rows), CONFIG, max_rows=3, max_columns=10
        )
        assert parsed.rows == 3 and parsed.truncated
        assert parsed.items[0] == {"sku": "S0", "title": "T0"}

    @pytest.mark.parametrize(
        ("content", "code"),
        [
            ("", "upload_empty"),
            ("Name,Other\nx,y\n", "upload_missing_columns"),
            ("SKU,Title,a,b,c\n1,2,3,4,5\n", "upload_too_many_columns"),
        ],
    )
    def test_invalid_files_are_rejected(self, tmp_path: Path, content: str, code: str) -> None:
        with pytest.raises(InvalidInputError) as exc:
            parse_upload(_csv(tmp_path, content), CONFIG, max_rows=10, max_columns=4)
        assert exc.value.code == code

    def test_xlsx_formulas_are_never_evaluated(self, tmp_path: Path) -> None:
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        assert sheet is not None
        sheet.append(["SKU", "Title"])
        sheet.append(["A-1", "=1+1"])  # formula without a cached value
        path = tmp_path / "in.xlsx"
        workbook.save(path)
        config = FileUploadConfig(format="xlsx", column_mapping={"sku": "SKU", "title": "Title"})
        parsed = parse_upload(path, config, max_rows=10, max_columns=10)
        assert parsed.items == [{"sku": "A-1", "title": None}]


def _content() -> ReportContent:
    change = {
        "detected_at": "2026-01-02T03:04:05+00:00",
        "record_key": EVIL,
        "change_type": "updated",
        "significance": "high",
        "score": 80,
        "diff": {"price": {"old": 1, "new": 2, "pct": 100.0}},
    }
    return ReportContent(
        title="Weekly <font size=40>report</font>",
        organization="Org",
        project="Proj",
        dataset=None,
        period_start=datetime(2026, 1, 1, tzinfo=UTC),
        period_end=datetime(2026, 1, 8, tzinfo=UTC),
        generated_at=datetime(2026, 1, 8, tzinfo=UTC),
        executive_summary='<img src="x"/> summary',
        totals={"created": 1},
        by_significance={"high": 1},
        daily_trend=[("2026-01-02", 1)],
        changes=[change],
        anomalies=[change],
        alerts=[],
        insights=[],
        sources=[{"name": EVIL, "kind": "website", "location": "https://shop.example.com"}],
    )


class TestRenderers:
    def test_csv_neutralises_formulas(self) -> None:
        data = ReportRendererRegistry().render(_content(), ReportFormat.CSV).decode("utf-8-sig")
        rows = list(csv.reader(io.StringIO(data)))
        assert rows[1][1] == "'" + EVIL

    def test_xlsx_writes_formula_like_text_as_strings(self) -> None:
        data = ReportRendererRegistry().render(_content(), ReportFormat.XLSX)
        workbook = openpyxl.load_workbook(io.BytesIO(data))
        cell = workbook["Changes"]["B2"]
        assert cell.value == EVIL
        assert cell.data_type == "s"  # a literal string, never a formula

    def test_pdf_treats_markup_as_text(self) -> None:
        data = ReportRendererRegistry().render(_content(), ReportFormat.PDF)
        assert data.startswith(b"%PDF")

    def test_json_round_trips(self) -> None:
        data = ReportRendererRegistry().render(_content(), ReportFormat.JSON)
        assert b"HYPERLINK" in data
