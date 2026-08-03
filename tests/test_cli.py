"""CLI behavior: exit codes, filtering, output files, and an end-to-end run."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from conftest import SECURE, VULNERABLE
from iacscanner.cli import main


def test_scan_secure_exits_zero(capsys) -> None:
    assert main(["scan", str(SECURE)]) == 0
    assert "No findings" in capsys.readouterr().out


def test_scan_vulnerable_exits_one(capsys) -> None:
    assert main(["scan", str(VULNERABLE)]) == 1
    assert "TL001" in capsys.readouterr().out


def test_fail_on_critical_still_fails_with_criticals(capsys) -> None:
    assert main(["scan", str(VULNERABLE), "--fail-on", "critical"]) == 1
    capsys.readouterr()


def test_min_severity_filters_findings(capsys) -> None:
    main(["scan", str(VULNERABLE), "--format", "json", "--min-severity", "critical"])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert severities == {"critical"}


def test_min_confidence_filters_findings(capsys) -> None:
    main(["scan", str(VULNERABLE), "--format", "json", "--min-confidence", "high"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["findings"], "expected some high-confidence findings"
    assert {f["confidence"] for f in payload["findings"]} == {"high"}


def test_min_severity_affects_exit_code(capsys) -> None:
    # Hide everything below critical and only fail on critical-or-above:
    # vulnerable fixtures contain criticals, so exit is still 1.
    assert main(["scan", str(VULNERABLE), "--min-severity", "critical", "--fail-on", "critical"]) == 1
    capsys.readouterr()


def test_missing_path_exits_two(capsys) -> None:
    assert main(["scan", "does-not-exist-anywhere"]) == 2
    assert "error" in capsys.readouterr().err.lower()


def test_parse_error_exits_two(tmp_path: Path, capsys) -> None:
    (tmp_path / "ok.json").write_text("{}", encoding="utf-8")
    (tmp_path / "bad.tf").write_text('resource "x" {\n', encoding="utf-8")
    assert main(["scan", str(tmp_path)]) == 2
    assert "TL000" in capsys.readouterr().out


def test_out_writes_report_file(tmp_path: Path, capsys) -> None:
    out = tmp_path / "report.md"
    code = main(["scan", str(SECURE), "--format", "markdown", "--out", str(out)])
    capsys.readouterr()
    assert code == 0
    assert out.read_text(encoding="utf-8").startswith("# IaCScanner scan report")


def test_rules_command_lists_all_rules(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule_id in [f"TL{n:03d}" for n in range(19)]:  # TL000 through TL018
        assert rule_id in out


def test_cli_end_to_end_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "iacscanner", "scan", str(VULNERABLE), "--format", "json"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 1
    payload = json.loads(proc.stdout)
    assert payload["tool"] == "iacscanner"
    assert payload["summary"]["findings"] > 0


def test_cli_help_subprocess() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "iacscanner", "--help"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0
    assert "scan" in proc.stdout and "rules" in proc.stdout
