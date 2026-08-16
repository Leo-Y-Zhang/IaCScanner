"""A small, declarative ``.themis.yaml`` policy: tune IaCScanner without forking or Python.

The policy is intentionally NOT Turing-complete -- it only disables rules, overrides a
rule's severity, or excludes paths from reporting:

    disable:
      - TL014            # accepted: we run these workloads unbounded on purpose
    severity:
      TL008: medium      # downgrade versioning/logging for our threat model
    exclude:
      - "examples/**"    # never report findings from vendored example trees

Nothing is ever hidden silently: an unknown rule id, an invalid severity, a malformed file
or an unknown key produces a visible WARNING (surfaced by the CLI), never a quiet no-op.
Precedence is CLI flags > .themis.yaml > built-in defaults. The baseline stays the official
acceptance path; the policy is for standing configuration.
"""
from __future__ import annotations

import dataclasses
import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from iacscanner.models import Finding, Severity
from iacscanner.rules import ALL_RULES

_VALID_RULE_IDS = frozenset(rule.id for rule in ALL_RULES)
_KNOWN_KEYS = frozenset({"disable", "severity", "exclude"})


@dataclass(frozen=True)
class Policy:
    disabled: frozenset[str] = frozenset()
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    exclude_paths: tuple[str, ...] = ()


EMPTY = Policy()


def load_policy(path: Path) -> tuple[Policy, list[str]]:
    """Load and validate a policy file. Returns (policy, warnings); malformed input yields
    an empty policy plus warnings rather than raising."""
    warnings: list[str] = []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        return EMPTY, [f"policy file {path.name} could not be read: {exc}"]
    if raw is None:
        return EMPTY, warnings
    if not isinstance(raw, dict):
        return EMPTY, [f"policy file {path.name} is not a mapping; ignoring it"]

    for key in raw:
        if key not in _KNOWN_KEYS:
            warnings.append(f"policy has unknown key {key!r}")

    # Each key's container type is checked before it is walked. A scalar is iterable in
    # Python but means nothing here: `severity: TL001` used to raise AttributeError and
    # abort the whole scan, `disable: TL014` warned about five unknown rules 'T', 'L',
    # '0', '1', '4', and `exclude: examples/**` became eleven single-character globs that
    # excluded nothing at all. All three are user typos and must read as one warning.
    raw_disable = raw.get("disable") or []
    if not isinstance(raw_disable, list):
        warnings.append("policy key 'disable' must be a list of rule ids; ignoring it")
        raw_disable = []
    raw_severity = raw.get("severity") or {}
    if not isinstance(raw_severity, dict):
        warnings.append("policy key 'severity' must be a mapping of rule id to severity; ignoring it")
        raw_severity = {}
    raw_exclude = raw.get("exclude") or []
    if not isinstance(raw_exclude, list):
        warnings.append("policy key 'exclude' must be a list of path globs; ignoring it")
        raw_exclude = []

    disabled: set[str] = set()
    for rid in raw_disable:
        if rid in _VALID_RULE_IDS:
            disabled.add(rid)
        else:
            warnings.append(f"policy disables unknown rule {rid!r}")

    overrides: dict[str, Severity] = {}
    for rid, level in raw_severity.items():
        if rid not in _VALID_RULE_IDS:
            warnings.append(f"policy overrides unknown rule {rid!r}")
            continue
        try:
            overrides[rid] = Severity(level)
        except ValueError:
            warnings.append(f"policy has invalid severity {level!r} for {rid}")

    exclude = tuple(str(pattern) for pattern in raw_exclude)
    return Policy(frozenset(disabled), overrides, exclude), warnings


def apply_policy(findings: list[Finding], policy: Policy) -> tuple[list[Finding], int]:
    """Apply a policy to *findings*. Returns (kept_findings, suppressed_count)."""
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if finding.rule_id in policy.disabled:
            suppressed += 1
            continue
        # fnmatchcase (not fnmatch) so matching is case-sensitive and platform-independent:
        # finding.path is always POSIX/forward-slash, and fnmatch would case-fold on Windows,
        # making the same policy hide different findings on Windows vs Linux CI.
        if any(fnmatch.fnmatchcase(finding.path, pattern) for pattern in policy.exclude_paths):
            suppressed += 1
            continue
        override = policy.severity_overrides.get(finding.rule_id)
        if override is not None and override is not finding.severity:
            finding = dataclasses.replace(finding, severity=override)
        kept.append(finding)
    return kept, suppressed


def discover_policy(target: Path, explicit: Path | None) -> Path | None:
    """Resolve which policy file to use: ``--policy`` wins, else a ``.themis.yaml`` beside the
    scan target. Discovery is confined to the scan target (no current-working-directory
    fallback) so a stray policy elsewhere can never silently mute an unrelated scan; use
    ``--policy`` to point at a file kept outside the target tree."""
    if explicit is not None:
        return explicit
    root = target if target.is_dir() else target.parent
    candidate = root / ".themis.yaml"
    return candidate if candidate.is_file() else None
