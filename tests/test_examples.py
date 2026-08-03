"""Committed example artifacts must equal a fresh render (drift guard).

`examples/sample-report.md` and `examples/sample.sarif` are checked into the repo as
showcase output. Because every renderer is deterministic and timestamp-free, a fresh scan of
`examples/vulnerable` must reproduce them byte-for-byte. If a rule, message, or renderer
changes without regenerating the samples, this test fails and names the file to refresh:

    iacscanner scan examples/vulnerable --format markdown --out examples/sample-report.md
    iacscanner scan examples/vulnerable --format sarif   --out examples/sample.sarif
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import PROJECT_ROOT
from iacscanner.report import render_markdown
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan


@pytest.fixture()
def scanned_from_root(monkeypatch: pytest.MonkeyPatch):
    """Scan examples/vulnerable with the same relative target the samples were built from."""
    monkeypatch.chdir(PROJECT_ROOT)
    return scan(Path("examples/vulnerable"))


def test_sample_markdown_is_current(scanned_from_root) -> None:
    committed = (PROJECT_ROOT / "examples" / "sample-report.md").read_text(encoding="utf-8")
    fresh = render_markdown(scanned_from_root, scanned_from_root.findings)
    assert fresh == committed, "examples/sample-report.md is stale; regenerate it (see this file's docstring)"


def test_sample_sarif_is_current(scanned_from_root) -> None:
    committed = (PROJECT_ROOT / "examples" / "sample.sarif").read_text(encoding="utf-8")
    fresh = render_sarif(scanned_from_root, scanned_from_root.findings)
    assert fresh == committed, "examples/sample.sarif is stale; regenerate it (see this file's docstring)"
