"""Report renderers: plain-text table, JSON, and Markdown.

All formatting uses the standard library only, contains no timestamps
(so regenerated reports are reproducible), and never embeds absolute
filesystem paths beyond the target argument the user supplied.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable

from iacscanner import __version__
from iacscanner.models import Confidence, Finding, Severity
from iacscanner.rules import get_rule
from iacscanner.scanner import ScanResult
from iacscanner.scoring import SCORE_FORMULA, grade, per_file_scores, risk_score

_SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
_CONFIDENCE_ORDER = (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)

_SAFETY_LINE = (
    "Read-only static analysis. No network calls, no cloud SDKs, no credentials."
)


def _severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {sev.value: 0 for sev in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


def _line_cell(finding: Finding) -> str:
    """The line column value: the resolved line, or '-' when unknown."""
    return str(finding.line) if finding.line is not None else "-"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    """Render an aligned plain-text table."""
    widths = [max(len(headers[i]), *(len(row[i]) for row in rows)) if rows else len(headers[i]) for i in range(len(headers))]
    lines = [
        "  ".join(headers[i].ljust(widths[i]) for i in range(len(headers))).rstrip(),
        "  ".join("-" * widths[i] for i in range(len(headers))).rstrip(),
    ]
    lines.extend("  ".join(row[i].ljust(widths[i]) for i in range(len(row))).rstrip() for row in rows)
    return "\n".join(lines)


def render_text(result: ScanResult, findings: list[Finding]) -> str:
    """Human-readable report."""
    counts = _severity_counts(findings)
    score = risk_score(findings)
    lines = [
        f"IaCScanner {__version__} - defensive IaC misconfiguration scanner",
        _SAFETY_LINE,
        "",
        f"Target        : {result.target}",
        f"Files scanned : {len(result.files)}",
        f"Findings      : {len(findings)} (" + ", ".join(f"{k} {v}" for k, v in counts.items()) + ")",
        f"Risk score    : {score}/100 (grade {grade(score)})",
        f"Formula       : {SCORE_FORMULA}",
        "",
    ]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    rows = [
        [f.severity.value, f.confidence.value, f.rule_id, f.path, _line_cell(f), f.location, f.message]
        for f in findings
    ]
    lines.append(_table(["SEVERITY", "CONF", "RULE", "FILE", "LINE", "LOCATION", "MESSAGE"], rows))
    lines.extend(["", "PER-FILE SCORES"])
    score_rows = [[path, str(s), grade(s)] for path, s in per_file_scores(findings).items()]
    lines.append(_table(["FILE", "SCORE", "GRADE"], score_rows))
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult, findings: list[Finding]) -> str:
    """Machine-readable report as a JSON document."""
    score = risk_score(findings)
    payload = {
        "tool": "iacscanner",
        "version": __version__,
        "safety": _SAFETY_LINE,
        "target": result.target,
        "files_scanned": len(result.files),
        "parse_errors": result.parse_error_count,
        "summary": {
            "findings": len(findings),
            "by_severity": _severity_counts(findings),
            "risk_score": score,
            "grade": grade(score),
            "score_formula": SCORE_FORMULA,
        },
        "files": [
            {"path": path, "score": s, "grade": grade(s)} for path, s in per_file_scores(findings).items()
        ],
        "findings": [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "path": f.path,
                "location": f.location,
                "line": f.line,
                "message": f.message,
                "title": get_rule(f.rule_id).title,
                "cwe_ids": list(get_rule(f.rule_id).cwe_ids),
                "cis_controls": list(get_rule(f.rule_id).cis_controls),
                "remediation": get_rule(f.rule_id).remediation,
            }
            for f in findings
        ],
    }
    return json.dumps(payload, indent=2)


def _md_escape(cell: str) -> str:
    return cell.replace("|", "\\|")


def render_markdown(result: ScanResult, findings: list[Finding]) -> str:
    """Markdown report suitable for committing or pasting into a PR."""
    counts = _severity_counts(findings)
    score = risk_score(findings)
    lines = [
        "# IaCScanner scan report",
        "",
        f"{_SAFETY_LINE}",
        "",
        f"- Tool: iacscanner {__version__}",
        f"- Target: `{result.target}`",
        f"- Files scanned: {len(result.files)}",
        f"- Risk score: **{score}/100** (grade **{grade(score)}**)",
        f"- Formula: `{SCORE_FORMULA}`",
        "",
        "## Findings by severity",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    lines.extend(f"| {name} | {count} |" for name, count in counts.items())

    lines.extend(["", "## Per-file scores", "", "| File | Score | Grade |", "| --- | --- | --- |"])
    lines.extend(f"| `{path}` | {s} | {grade(s)} |" for path, s in per_file_scores(findings).items())

    lines.extend(["", "## Findings", ""])
    if not findings:
        lines.append("No findings.")
    else:
        lines.extend([
            "| Severity | Confidence | Rule | File | Line | Location | Message |",
            "| --- | --- | --- | --- | --- | --- | --- |",
        ])
        lines.extend(
            f"| {f.severity.value} | {f.confidence.value} | {f.rule_id} | `{f.path}` | "
            f"{_line_cell(f)} | `{_md_escape(f.location)}` | {_md_escape(f.message)} |"
            for f in findings
        )
        lines.extend(["", "## Remediation guidance", ""])
        for rule_id in sorted({f.rule_id for f in findings}):
            rule = get_rule(rule_id)
            refs = ", ".join((*rule.cwe_ids, *rule.cis_controls))
            block = [f"### {rule.id}: {rule.title} ({rule.severity.value})", "", rule.rationale, ""]
            if refs:
                block.extend([f"References: {refs}", ""])
            block.extend(["```", rule.remediation, "```", ""])
            lines.extend(block)
    return "\n".join(lines).rstrip() + "\n"


def render_stats(result: ScanResult, findings: list[Finding]) -> str:
    """A compact, deterministically-ordered summary of a scan (for --stats)."""
    kinds = Counter(sf.kind for sf in result.files)
    sev = _severity_counts(findings)
    conf = Counter(f.confidence.value for f in findings)
    by_rule = Counter(f.rule_id for f in findings)
    lines = [
        "STATS",
        f"  files: {len(result.files)} ("
        + ", ".join(f"{kind} {kinds[kind]}" for kind in sorted(kinds)) + ")",
        f"  findings: {len(findings)} ("
        + ", ".join(f"{s.value} {sev[s.value]}" for s in _SEVERITY_ORDER) + ")",
        "  confidence: "
        + ", ".join(f"{c.value} {conf.get(c.value, 0)}" for c in _CONFIDENCE_ORDER),
        "  by rule:",
    ]
    lines.extend(f"    {rule_id}  {by_rule[rule_id]}" for rule_id in sorted(by_rule))
    return "\n".join(lines) + "\n"
