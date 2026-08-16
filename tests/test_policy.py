"""The declarative .themis.yaml policy engine (iacscanner/policy.py + CLI integration)."""
from __future__ import annotations

import json
from pathlib import Path

from conftest import VULNERABLE
from iacscanner.cli import main
from iacscanner.models import Finding, Severity
from iacscanner.policy import apply_policy, discover_policy, load_policy


def _write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


class TestLoad:
    def test_disable_and_severity_and_exclude(self, tmp_path: Path) -> None:
        p = _write(tmp_path / ".themis.yaml", "disable: [TL006]\nseverity:\n  TL001: high\nexclude: ['x/**']")
        policy, warnings = load_policy(p)
        assert policy.disabled == frozenset({"TL006"})
        assert policy.severity_overrides == {"TL001": Severity.HIGH}
        assert policy.exclude_paths == ("x/**",)
        assert warnings == []

    def test_unknown_rule_warns_not_silent(self, tmp_path: Path) -> None:
        _, warnings = load_policy(_write(tmp_path / "p.yaml", "disable: [TL999]"))
        assert any("TL999" in w for w in warnings)

    def test_invalid_severity_warns(self, tmp_path: Path) -> None:
        _, warnings = load_policy(_write(tmp_path / "p.yaml", "severity:\n  TL001: catastrophic"))
        assert any("catastrophic" in w for w in warnings)

    def test_unknown_key_warns(self, tmp_path: Path) -> None:
        _, warnings = load_policy(_write(tmp_path / "p.yaml", "frobnicate: true"))
        assert any("unknown key" in w for w in warnings)

    def test_non_mapping_is_ignored_with_a_warning(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "- just\n- a\n- list"))
        assert policy.disabled == frozenset() and warnings

    def test_empty_file_is_an_empty_policy(self, tmp_path: Path) -> None:
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", ""))
        assert policy.disabled == frozenset() and warnings == []

    def test_severity_that_is_not_a_mapping_warns_instead_of_raising(self, tmp_path: Path) -> None:
        # A list under `severity:` is an easy thing to write by hand; it must not take
        # the whole scan down with an AttributeError on .items().
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "severity:\n  - TL001\n"))
        assert policy.severity_overrides == {}
        assert any("severity" in w for w in warnings)

    def test_disable_that_is_not_a_list_warns_once(self, tmp_path: Path) -> None:
        # `disable: TL014` iterated the string character by character, warning about
        # five unknown rules 'T', 'L', '0', '1', '4' rather than the real mistake.
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "disable: TL014\n"))
        assert policy.disabled == frozenset()
        assert len(warnings) == 1 and "disable" in warnings[0]

    def test_exclude_that_is_not_a_list_warns_instead_of_splitting(self, tmp_path: Path) -> None:
        # `exclude: examples/**` became eleven single-character globs that match nothing,
        # silently excluding nothing at all.
        policy, warnings = load_policy(_write(tmp_path / "p.yaml", "exclude: examples/**\n"))
        assert policy.exclude_paths == ()
        assert any("exclude" in w for w in warnings)


class TestApply:
    def _findings(self) -> list[Finding]:
        return [
            Finding("TL001", Severity.CRITICAL, "a.tf", "l", "m"),
            Finding("TL006", Severity.HIGH, "a.tf", "l", "m"),
            Finding("TL014", Severity.LOW, "vendor/x.yaml", "l", "m"),
        ]

    def test_disable_removes_findings(self) -> None:
        from iacscanner.policy import Policy
        kept, n = apply_policy(self._findings(), Policy(disabled=frozenset({"TL006"})))
        assert {f.rule_id for f in kept} == {"TL001", "TL014"} and n == 1

    def test_severity_override(self) -> None:
        from iacscanner.policy import Policy
        kept, _ = apply_policy(self._findings(), Policy(severity_overrides={"TL001": Severity.LOW}))
        tl001 = next(f for f in kept if f.rule_id == "TL001")
        assert tl001.severity is Severity.LOW

    def test_exclude_path_glob(self) -> None:
        from iacscanner.policy import Policy
        kept, n = apply_policy(self._findings(), Policy(exclude_paths=("vendor/**",)))
        assert all(f.path != "vendor/x.yaml" for f in kept) and n == 1

    def test_exclude_glob_is_case_sensitive_and_platform_independent(self) -> None:
        # findings.path is always POSIX; a case-mismatched pattern must NOT exclude, so the
        # same policy hides the same findings on Windows and Linux (fnmatchcase, not fnmatch).
        from iacscanner.policy import Policy
        findings = [Finding("TL001", Severity.CRITICAL, "Examples/a.tf", "l", "m")]
        kept, n = apply_policy(findings, Policy(exclude_paths=("examples/**",)))
        assert n == 0 and len(kept) == 1  # 'Examples/...' is not matched by 'examples/**'
        kept2, n2 = apply_policy(findings, Policy(exclude_paths=("Examples/**",)))
        assert n2 == 1 and kept2 == []  # exact-case pattern does match


class TestDiscovery:
    def test_explicit_wins(self, tmp_path: Path) -> None:
        explicit = tmp_path / "custom.yaml"
        explicit.write_text("")
        assert discover_policy(tmp_path, explicit) == explicit

    def test_finds_iacscanner_yaml_beside_target(self, tmp_path: Path) -> None:
        cfg = _write(tmp_path / ".themis.yaml", "disable: [TL001]")
        assert discover_policy(tmp_path, None) == cfg

    def test_none_when_absent(self, tmp_path: Path) -> None:
        assert discover_policy(tmp_path, None) is None

    def test_no_cwd_fallback(self, tmp_path: Path, monkeypatch) -> None:
        # A .themis.yaml in the current working directory must NOT apply to a scan of an
        # unrelated target -- discovery is confined to the target tree.
        cwd = tmp_path / "cwd"
        target = tmp_path / "target"
        cwd.mkdir()
        target.mkdir()
        _write(cwd / ".themis.yaml", "disable: [TL001]")
        monkeypatch.chdir(cwd)
        assert discover_policy(target, None) is None


class TestCliIntegration:
    def test_policy_disable_via_flag(self, tmp_path: Path, capsys) -> None:
        cfg = _write(tmp_path / "pol.yaml", "disable: [TL001, TL002, TL003, TL004, TL005, TL018]")
        main(["scan", str(VULNERABLE), "--format", "json", "--policy", str(cfg)])
        payload = json.loads(capsys.readouterr().out)
        ids = {f["rule_id"] for f in payload["findings"]}
        assert not ({"TL001", "TL005"} & ids)

    def test_policy_warning_is_printed(self, tmp_path: Path, capsys) -> None:
        cfg = _write(tmp_path / "pol.yaml", "disable: [TL404]")
        main(["scan", str(VULNERABLE), "--format", "json", "--policy", str(cfg)])
        assert "TL404" in capsys.readouterr().err

    def test_applied_policy_path_is_surfaced(self, tmp_path: Path, capsys) -> None:
        cfg = _write(tmp_path / "pol.yaml", "disable: [TL001]")
        main(["scan", str(VULNERABLE), "--format", "json", "--policy", str(cfg)])
        assert "policy: applying" in capsys.readouterr().err
