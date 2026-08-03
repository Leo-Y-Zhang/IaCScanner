"""Reproducibility harness: every report format must be byte-identical run to run, and
paths must stay relative + POSIX so reports are portable and diffable across machines.

This is the determinism floor the whole "to the max" build stands on; every later feature
(graph, SARIF, policy) must keep it green.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from conftest import PROJECT_ROOT, SECURE, VULNERABLE
from iacscanner.report import render_json, render_markdown, render_text
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan

_RENDERERS = (render_text, render_json, render_markdown, render_sarif)


def _reports(target: Path) -> list[str]:
    result = scan(target)
    return [render(result, result.findings) for render in _RENDERERS]


def test_reports_are_byte_identical_across_three_runs() -> None:
    runs = [_reports(VULNERABLE) for _ in range(3)]
    for i, render in enumerate(_RENDERERS):
        digests = {hashlib.sha256(runs[k][i].encode()).hexdigest() for k in range(3)}
        assert len(digests) == 1, f"{render.__name__} is not reproducible"


def test_finding_paths_are_relative_posix() -> None:
    result = scan(VULNERABLE)
    assert result.findings, "expected the vulnerable fixture to produce findings"
    for finding in result.findings:
        assert "\\" not in finding.path, f"non-POSIX path: {finding.path!r}"
        assert ":" not in finding.path, f"drive letter in path: {finding.path!r}"
        assert not finding.path.startswith("/"), f"absolute path: {finding.path!r}"


def test_relative_target_leaks_no_absolute_path(monkeypatch) -> None:
    # scanned relative to the project root, no report may embed the absolute root path
    monkeypatch.chdir(PROJECT_ROOT)
    abs_root = str(PROJECT_ROOT)
    posix_root = PROJECT_ROOT.as_posix()
    for report in _reports(Path("examples/vulnerable")):
        assert abs_root not in report
        assert posix_root not in report


def test_secure_tree_has_no_findings() -> None:
    assert scan(SECURE).findings == []
