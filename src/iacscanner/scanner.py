"""Scan orchestration: discover files, run rules, collect findings."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from pathlib import Path

from iacscanner.graph import ScanContext
from iacscanner.lines import attach_lines
from iacscanner.models import Finding, ScanFile
from iacscanner.parsers import discover, parse_file
from iacscanner.rules import PARSE_RULE, RULES, get_rule
from iacscanner.suppress import NONE as _NO_SUPPRESSION
from iacscanner.suppress import Suppression, parse_suppressions_with_warnings


@dataclass
class ScanResult:
    """Everything one scan produced, with findings deterministically sorted."""

    target: str
    files: list[ScanFile]
    findings: list[Finding]
    parse_error_count: int
    inline_suppressed_count: int = 0
    suppression_warnings: list[str] = dataclasses.field(default_factory=list)


def _display_path(path: Path, target: Path) -> str:
    """Path shown in reports: relative to the target, POSIX separators."""
    if target.is_file():
        return path.name
    return path.relative_to(target).as_posix()


def scan(target: Path) -> ScanResult:
    """Scan *target* (file or directory) and return all findings.

    Files that fail to parse contribute one TL000 warning finding each
    and are counted in ``parse_error_count``; they never abort the scan.
    """
    target = Path(target)
    files: list[ScanFile] = []
    findings: list[Finding] = []
    parse_errors = 0

    # Parse every file first, so the ScanContext can resolve cross-file references before
    # any rule runs. Parse failures contribute a TL000 finding and are then skipped.
    for path in discover(target):
        sf = parse_file(path, _display_path(path, target))
        files.append(sf)
        if sf.error is not None:
            parse_errors += 1
            findings.append(PARSE_RULE.finding(sf, "file", sf.error))

    context = ScanContext.build(tuple(files))
    for sf in files:
        if sf.error is not None:
            continue
        for rule in RULES:
            if not rule.applies_to(sf.kind):
                continue
            if rule.check_ctx is not None:
                findings.extend(rule.check_ctx(sf, context))
            elif rule.check is not None:
                findings.extend(rule.check(sf))

    # Stamp each finding's confidence from the central metadata table (one source of truth).
    findings = [
        dataclasses.replace(f, confidence=get_rule(f.rule_id).default_confidence)
        for f in findings
    ]

    # Apply inline `# themis:ignore` suppressions (file-scoped; a parse-error file keeps its
    # TL000 finding since a broken file cannot declare a trustworthy suppression). A typo'd
    # rule id suppresses nothing and surfaces a visible warning (never a silent ignore-all).
    suppressions: dict[str, Suppression] = {}
    suppression_warnings: list[str] = []
    for sf in files:
        if sf.error is not None:
            continue
        suppression, warnings = parse_suppressions_with_warnings(sf.text)
        suppressions[sf.path] = suppression
        suppression_warnings.extend(f"{sf.path}: {w}" for w in warnings)
    kept = [
        f for f in findings
        if not suppressions.get(f.path, _NO_SUPPRESSION).suppresses(f.rule_id)
    ]
    inline_suppressed = len(findings) - len(kept)
    findings = kept

    # Resolve each structural anchor to a source line (display metadata only;
    # never part of the fingerprint). Ambiguous/unresolvable anchors stay None.
    findings = attach_lines(files, findings)

    findings.sort(key=lambda f: f.sort_key)
    return ScanResult(
        target=target.as_posix(),
        files=files,
        findings=findings,
        parse_error_count=parse_errors,
        inline_suppressed_count=inline_suppressed,
        suppression_warnings=suppression_warnings,
    )
