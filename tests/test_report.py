"""Tests for the text, JSON, and Markdown report renderers."""
from __future__ import annotations

import json

from iacscanner import __version__
from iacscanner.report import render_json, render_markdown, render_text


def test_json_report_is_valid_and_complete(vulnerable_result) -> None:
    payload = json.loads(render_json(vulnerable_result, vulnerable_result.findings))
    assert payload["tool"] == "iacscanner"
    assert payload["version"] == __version__
    assert payload["files_scanned"] == 4
    assert payload["summary"]["grade"] in "ABCDF"
    assert 0 <= payload["summary"]["risk_score"] <= 100
    assert payload["findings"], "expected findings for the vulnerable fixtures"
    first = payload["findings"][0]
    assert set(first) == {
        "rule_id", "severity", "confidence", "path", "location", "line", "message",
        "title", "cwe_ids", "cis_controls", "remediation",
    }
    assert first["confidence"] in {"low", "medium", "high"}
    assert first["cwe_ids"] and first["cis_controls"]


def test_json_findings_carry_resolved_lines(vulnerable_result) -> None:
    payload = json.loads(render_json(vulnerable_result, vulnerable_result.findings))
    lines = {(f["rule_id"], f["location"]): f["line"] for f in payload["findings"]}
    assert lines[("TL001", "aws_s3_bucket.example_data")] == 12
    assert lines[("TL016", "jobs.build.steps[0]")] == 11
    assert all(line is None or line >= 1 for line in lines.values())


def test_json_report_counts_match(vulnerable_result) -> None:
    payload = json.loads(render_json(vulnerable_result, vulnerable_result.findings))
    by_sev = payload["summary"]["by_severity"]
    assert sum(by_sev.values()) == len(payload["findings"]) == payload["summary"]["findings"]


def test_text_report_mentions_safety_and_rules(vulnerable_result) -> None:
    text = render_text(vulnerable_result, vulnerable_result.findings)
    assert "Read-only" in text
    assert "TL001" in text
    assert "Risk score" in text


def test_text_report_has_line_column(vulnerable_result) -> None:
    text = render_text(vulnerable_result, vulnerable_result.findings)
    header = next(line for line in text.splitlines() if line.startswith("SEVERITY"))
    assert header.split() == ["SEVERITY", "CONF", "RULE", "FILE", "LINE", "LOCATION", "MESSAGE"]


def test_text_report_clean_run(secure_result) -> None:
    text = render_text(secure_result, secure_result.findings)
    assert "No findings" in text
    assert "grade A" in text


def test_markdown_report_structure(vulnerable_result) -> None:
    md = render_markdown(vulnerable_result, vulnerable_result.findings)
    assert md.startswith("# IaCScanner scan report")
    assert "## Findings" in md
    assert "## Remediation guidance" in md
    assert "| critical |" in md


def test_markdown_findings_table_has_line_column(vulnerable_result) -> None:
    md = render_markdown(vulnerable_result, vulnerable_result.findings)
    assert "| Severity | Confidence | Rule | File | Line | Location | Message |" in md


def test_renderers_are_deterministic(vulnerable_result) -> None:
    args = (vulnerable_result, vulnerable_result.findings)
    assert render_json(*args) == render_json(*args)
    assert render_markdown(*args) == render_markdown(*args)
    assert render_text(*args) == render_text(*args)
