"""Tests for file discovery, parsing, and graceful parse-error handling."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from conftest import parse_snippet
from iacscanner.parsers import discover, parse_file
from iacscanner.scanner import scan


def _make_symlink(src: Path, dst: Path, target_is_directory: bool) -> None:
    """Create a symlink or skip the test when the OS forbids it.

    Windows refuses symlink creation without a special privilege and some
    filesystems do not support links at all; treat that as "not applicable".
    """
    try:
        os.symlink(src, dst, target_is_directory=target_is_directory)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - env dependent
        pytest.skip(f"symlinks unavailable on this platform: {exc}")


def test_terraform_file_parses(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "main.tf", 'resource "aws_s3_bucket" "b" {\n  bucket = "example-data-bucket"\n}\n')
    assert sf.kind == "terraform"
    assert sf.error is None
    assert "resource" in sf.data


def test_kubernetes_yaml_detected(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "pod.yaml", "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  containers: []\n")
    assert sf.kind == "kubernetes"
    assert sf.error is None


def test_github_actions_yaml_detected(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "wf.yml", "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n")
    assert sf.kind == "github-actions"


def test_plain_yaml_detected(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "cfg.yaml", "retries: 3\nhost: db.example.com\n")
    assert sf.kind == "yaml"


def test_json_detected(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "cfg.json", '{"retries": 3}\n')
    assert sf.kind == "json"
    assert sf.data == {"retries": 3}


def test_multi_document_yaml(tmp_path: Path) -> None:
    text = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: b\n"
    sf = parse_snippet(tmp_path, "multi.yaml", text)
    assert sf.kind == "kubernetes"
    assert len(sf.data) == 2


def test_broken_terraform_sets_error(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "bad.tf", 'resource "x" {\n')
    assert sf.error is not None


def test_broken_yaml_sets_error(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "bad.yaml", "a: [unclosed\nb: }{\n")
    assert sf.error is not None


def test_broken_json_sets_error(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "bad.json", "{not json}")
    assert sf.error is not None


def test_discover_skips_noise_dirs_and_sorts(tmp_path: Path) -> None:
    (tmp_path / "b.tf").write_text("", encoding="utf-8")
    (tmp_path / "a.yaml").write_text("", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("", encoding="utf-8")
    hidden = tmp_path / ".git"
    hidden.mkdir()
    (hidden / "c.json").write_text("{}", encoding="utf-8")
    found = discover(tmp_path)
    assert [p.name for p in found] == ["a.yaml", "b.tf"]


def test_discover_single_file(tmp_path: Path) -> None:
    path = tmp_path / "one.tf"
    path.write_text("", encoding="utf-8")
    assert discover(path) == [path]


def test_discover_does_not_follow_symlinked_directory(tmp_path: Path) -> None:
    # A hostile repo cannot make IaCScanner read files outside the scan target
    # by planting a symlinked directory that points elsewhere.
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text(
        'variable "db_password" { default = "SUPERSECRET" }\n', encoding="utf-8"
    )
    target = tmp_path / "repo"
    target.mkdir()
    (target / "real.tf").write_text("", encoding="utf-8")
    _make_symlink(outside, target / "link", target_is_directory=True)

    names = {p.name for p in discover(target)}
    assert names == {"real.tf"}
    assert "secret.tf" not in names


def test_discover_survives_symlink_loop(tmp_path: Path) -> None:
    # A self-referential directory symlink must not send discovery into an
    # infinite recursion / OSError denial-of-service.
    target = tmp_path / "repo"
    target.mkdir()
    (target / "real.tf").write_text("", encoding="utf-8")
    _make_symlink(target, target / "loop", target_is_directory=True)

    names = {p.name for p in discover(target)}
    assert names == {"real.tf"}


def test_discover_walks_without_following_symlinks(tmp_path: Path, monkeypatch) -> None:
    # Platform-independent guard: discover must never let os.walk follow
    # symlinked directories (followlinks stays False).
    (tmp_path / "a.tf").write_text("", encoding="utf-8")
    real_walk = os.walk
    seen: dict[str, object] = {}

    def spy_walk(top, *args, **kwargs):
        seen["followlinks"] = kwargs.get("followlinks", "unset")
        return real_walk(top, *args, **kwargs)

    monkeypatch.setattr("iacscanner.parsers.os.walk", spy_walk)
    discover(tmp_path)
    assert seen["followlinks"] is False


def test_discover_skips_symlinked_file(tmp_path: Path, monkeypatch) -> None:
    # A symlinked scannable file is skipped even when the OS lets it exist,
    # so a link to an out-of-tree secret is never read. Simulated via a
    # patched is_symlink so the guard is verified on every platform.
    (tmp_path / "real.tf").write_text("", encoding="utf-8")
    (tmp_path / "linked.tf").write_text("", encoding="utf-8")

    real_is_symlink = Path.is_symlink

    def fake_is_symlink(self: Path) -> bool:
        if self.name == "linked.tf":
            return True
        return real_is_symlink(self)

    monkeypatch.setattr(Path, "is_symlink", fake_is_symlink)
    names = {p.name for p in discover(tmp_path)}
    assert names == {"real.tf"}


def test_discover_prunes_subdir_whose_realpath_escapes_root(
    tmp_path: Path, monkeypatch
) -> None:
    # Containment guard, link-type-independent: any subdirectory whose real
    # path resolves OUTSIDE the scan root is pruned - this covers an NTFS
    # directory junction (mklink /J, no admin) that os.walk and is_symlink
    # never flag as a link. Simulated by redirecting realpath so the guard
    # is exercised on every platform.
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.tf").write_text("", encoding="utf-8")
    escape = root / "junction"
    escape.mkdir()
    (escape / "secret.tf").write_text(
        'variable "db_password" { default = "SUPERSECRET" }\n', encoding="utf-8"
    )
    outside = str(tmp_path / "somewhere-else")

    real_realpath = os.path.realpath

    def fake_realpath(p, *args, **kwargs):
        # The "junction" directory (and anything under it) resolves out of
        # tree; everything else resolves normally.
        if os.path.basename(str(p)) == "junction":
            return outside
        return real_realpath(p, *args, **kwargs)

    monkeypatch.setattr("iacscanner.parsers.os.path.realpath", fake_realpath)
    names = {p.name for p in discover(root)}
    assert names == {"real.tf"}
    assert "secret.tf" not in names


def test_discover_prunes_subdir_whose_realpath_was_already_seen(
    tmp_path: Path, monkeypatch
) -> None:
    # Loop guard, link-type-independent: a subdirectory whose real path was
    # already visited is not re-descended, so a self-referential junction or
    # symlink cannot drive os.walk into runaway recursion. Simulated by
    # collapsing a nested subdir's realpath onto the root's realpath.
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.tf").write_text("", encoding="utf-8")
    loop = root / "loop"
    loop.mkdir()
    # A canary file the loop guard must prevent from ever being re-collected
    # under a second (aliased) path.
    (loop / "inner.tf").write_text("", encoding="utf-8")

    root_real = os.path.realpath(root)
    real_realpath = os.path.realpath
    descended: list[str] = []

    def fake_realpath(p, *args, **kwargs):
        if os.path.basename(str(p)) == "loop":
            # The junction points back at the already-seen root.
            return root_real
        return real_realpath(p, *args, **kwargs)

    real_walk = os.walk

    def spy_walk(top, *args, **kwargs):
        for dirpath, dirnames, filenames in real_walk(top, *args, **kwargs):
            descended.append(dirpath)
            yield dirpath, dirnames, filenames

    monkeypatch.setattr("iacscanner.parsers.os.path.realpath", fake_realpath)
    monkeypatch.setattr("iacscanner.parsers.os.walk", spy_walk)
    discover(root)
    # The "loop" directory resolves to the already-seen root, so it must be
    # pruned from dirnames and never descended into.
    assert not any(os.path.basename(d) == "loop" for d in descended)


def test_discover_real_junction_does_not_escape_root(tmp_path: Path) -> None:
    # Real NTFS junction end-to-end (Windows only; skipped elsewhere or when
    # junction creation is unavailable), mirroring the real-symlink tests.
    if os.name != "nt":
        pytest.skip("directory junctions are Windows/NTFS only")
    import subprocess

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.tf").write_text(
        'variable "db_password" { default = "SUPERSECRET" }\n', encoding="utf-8"
    )
    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.tf").write_text("", encoding="utf-8")
    junction = root / "link"
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:  # pragma: no cover - env dependent
        pytest.skip(f"mklink /J unavailable: {proc.stderr.strip()}")

    names = {p.name for p in discover(root)}
    assert names == {"real.tf"}
    assert "secret.tf" not in names


def test_discover_real_self_junction_does_not_loop(tmp_path: Path) -> None:
    # Real self-referential NTFS junction must not cause runaway recursion
    # (Windows only; skipped otherwise or when unavailable).
    if os.name != "nt":
        pytest.skip("directory junctions are Windows/NTFS only")
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()
    (root / "real.tf").write_text("", encoding="utf-8")
    junction = root / "loop"
    proc = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(root)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:  # pragma: no cover - env dependent
        pytest.skip(f"mklink /J unavailable: {proc.stderr.strip()}")

    names = {p.name for p in discover(root)}
    assert names == {"real.tf"}


def test_scan_turns_parse_error_into_ig000_finding(tmp_path: Path) -> None:
    (tmp_path / "bad.tf").write_text('resource "x" {\n', encoding="utf-8")
    result = scan(tmp_path)
    assert result.parse_error_count == 1
    assert [f.rule_id for f in result.findings] == ["TL000"]
    assert result.findings[0].severity.value == "low"


def test_parse_file_display_path_is_relative(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "x.json"
    path.parent.mkdir()
    path.write_text("{}", encoding="utf-8")
    sf = parse_file(path, "sub/x.json")
    assert sf.path == "sub/x.json"
