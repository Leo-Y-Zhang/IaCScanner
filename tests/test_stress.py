"""Determinism-under-load + performance guard, and the --stats summary.

Proves the enlarged engine (graph + 28 rules + SARIF) stays byte-identical and fast on a
large tree, so scale never silently reorders output or blows up quadratically.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path

from iacscanner.cli import main
from iacscanner.report import render_json, render_stats
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan

_TF = 'resource "aws_s3_bucket" "b{i}" {{ bucket = "bucket-{i}"; acl = "public-read" }}\n'
_YAML = (
    "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p{i}\n"
    "spec:\n  hostNetwork: true\n  containers:\n    - name: c\n      image: nginx:latest\n"
)


def _big_tree(root: Path, n: int = 200) -> Path:
    for i in range(n):
        if i % 2:
            (root / f"f{i}.tf").write_text(_TF.format(i=i), encoding="utf-8")
        else:
            (root / f"f{i}.yaml").write_text(_YAML.format(i=i), encoding="utf-8")
    return root


def test_large_tree_scans_reproducibly(tmp_path: Path) -> None:
    _big_tree(tmp_path)
    digests = set()
    for _ in range(10):
        result = scan(tmp_path)
        blob = render_json(result, result.findings) + render_sarif(result, result.findings)
        digests.add(hashlib.sha256(blob.encode()).hexdigest())
    assert len(digests) == 1, "output was not byte-identical across 10 runs"


def test_large_tree_scans_quickly(tmp_path: Path) -> None:
    _big_tree(tmp_path, n=300)
    start = time.perf_counter()
    result = scan(tmp_path)
    elapsed = time.perf_counter() - start
    assert result.findings, "expected findings from the vulnerable tree"
    assert elapsed < 5.0, f"scan of a 300-file tree took {elapsed:.2f}s"


class TestStats:
    def test_stats_render_is_deterministic(self, tmp_path: Path) -> None:
        _big_tree(tmp_path, n=40)
        result = scan(tmp_path)
        assert render_stats(result, result.findings) == render_stats(result, result.findings)

    def test_stats_has_expected_sections(self, tmp_path: Path) -> None:
        _big_tree(tmp_path, n=20)
        result = scan(tmp_path)
        text = render_stats(result, result.findings)
        assert "STATS" in text
        assert "files:" in text and "findings:" in text
        assert "confidence:" in text and "by rule:" in text

    def test_by_rule_lines_are_sorted(self, tmp_path: Path) -> None:
        _big_tree(tmp_path, n=20)
        result = scan(tmp_path)
        rule_lines = [
            ln.strip().split()[0]
            for ln in render_stats(result, result.findings).splitlines()
            if ln.startswith("    TL")
        ]
        assert rule_lines == sorted(rule_lines)

    def test_cli_stats_flag_prints_to_stderr(self, tmp_path: Path, capsys) -> None:
        _big_tree(tmp_path, n=10)
        main(["scan", str(tmp_path), "--format", "json", "--stats"])
        captured = capsys.readouterr()
        assert "STATS" in captured.err
        assert captured.out.startswith("{")  # the report still goes to stdout
