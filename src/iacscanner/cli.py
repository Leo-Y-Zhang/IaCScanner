"""Command-line interface.

Exit codes: 0 = clean (no findings at or above --fail-on), 1 = findings
at or above the --fail-on threshold (default: high), 2 = usage error,
missing path, malformed/unwritable baseline file, or one or more files
failed to parse. With --baseline only NEW findings count toward exit
code 1; a successful --write-baseline run exits 0 (its findings are
accepted by definition). Parse errors always exit 2.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from iacscanner import __version__
from iacscanner.baseline import BaselineError, load_baseline, split_findings, write_baseline
from iacscanner.models import Confidence, Severity
from iacscanner.policy import apply_policy, discover_policy, load_policy
from iacscanner.report import render_json, render_markdown, render_stats, render_text
from iacscanner.rules import ALL_RULES
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan

_RENDERERS = {
    "text": render_text,
    "json": render_json,
    "markdown": render_markdown,
    "sarif": render_sarif,
}
_SEVERITY_NAMES = [sev.value for sev in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
_CONFIDENCE_NAMES = [c.value for c in (Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH)]


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the iacscanner CLI."""
    parser = argparse.ArgumentParser(
        prog="iacscanner",
        description=(
            "Defensive, local, read-only IaC misconfiguration scanner. "
            "Makes no network calls and needs no credentials."
        ),
    )
    parser.add_argument("--version", action="version", version=f"iacscanner {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="scan a file or directory for misconfigurations")
    scan_parser.add_argument("path", help="file or directory to scan")
    scan_parser.add_argument("--format", choices=sorted(_RENDERERS), default="text", help="output format")
    scan_parser.add_argument(
        "--min-severity",
        choices=_SEVERITY_NAMES,
        default="low",
        help="hide findings below this severity (also excluded from scoring and --fail-on)",
    )
    scan_parser.add_argument(
        "--min-confidence",
        choices=_CONFIDENCE_NAMES,
        default="low",
        help="hide findings below this confidence (also excluded from scoring and --fail-on)",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=_SEVERITY_NAMES,
        default="high",
        help="exit 1 when any reported finding is at or above this severity (default: high)",
    )
    scan_parser.add_argument(
        "--policy",
        metavar="FILE",
        help="policy file (default: .themis.yaml beside the target); disable/severity/exclude",
    )
    scan_parser.add_argument(
        "--stats", action="store_true", help="print a summary (by rule/severity/confidence) to stderr"
    )
    scan_parser.add_argument("--out", metavar="FILE", help="write the report to FILE instead of stdout")
    scan_parser.add_argument(
        "--baseline",
        metavar="FILE",
        help=(
            "suppress the findings recorded in baseline FILE and report only new ones; "
            "exit codes consider only new findings (parse errors still exit 2)"
        ),
    )
    scan_parser.add_argument(
        "--write-baseline",
        metavar="FILE",
        help=(
            "record the reported findings to FILE as a baseline for later --baseline runs "
            "and exit 0 (parse errors still exit 2)"
        ),
    )

    sub.add_parser("rules", help="list every rule with its severity and description")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    baseline = None
    if args.baseline is not None:
        try:
            baseline = load_baseline(Path(args.baseline))
        except BaselineError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    result = scan(target)
    findings = result.findings

    # Inline `# themis:ignore` typos (e.g. a mistyped rule id) are surfaced, never silent.
    for warning in result.suppression_warnings:
        print(f"warning: {warning}", file=sys.stderr)

    # Policy (disable / severity override / exclude) first, then the CLI severity/confidence
    # gates. Warnings are surfaced, never silent, and the applied policy path is named so a
    # discovered policy can never quietly change results.
    policy_path = discover_policy(target, Path(args.policy) if args.policy else None)
    policy_suppressed = 0
    if policy_path is not None:
        print(f"policy: applying {policy_path.as_posix()}", file=sys.stderr)
        policy, warnings = load_policy(policy_path)
        for warning in warnings:
            print(f"warning: {warning}", file=sys.stderr)
        findings, policy_suppressed = apply_policy(findings, policy)

    total_suppressed = result.inline_suppressed_count + policy_suppressed
    if total_suppressed:
        print(
            f"suppressed: {result.inline_suppressed_count} inline, {policy_suppressed} by policy",
            file=sys.stderr,
        )

    min_rank = Severity(args.min_severity).rank
    min_conf = Confidence(args.min_confidence).rank
    findings = [
        f for f in findings
        if f.severity.rank >= min_rank and f.confidence.rank >= min_conf
    ]

    if args.write_baseline is not None:
        # Written before suppression so a --baseline + --write-baseline run
        # refreshes the baseline with every currently reported finding.
        try:
            write_baseline(Path(args.write_baseline), findings)
        except OSError as exc:
            print(f"error: cannot write baseline file: {exc}", file=sys.stderr)
            return 2

    if baseline is not None:
        findings, suppressed = split_findings(findings, baseline)
        print(
            f"baseline: {len(suppressed)} finding(s) suppressed, {len(findings)} new",
            file=sys.stderr,
        )

    report = _RENDERERS[args.format](result, findings)

    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
    else:
        print(report, end="")

    if args.stats:
        print(render_stats(result, findings), end="", file=sys.stderr)

    if result.parse_error_count:
        return 2
    if args.write_baseline is not None:
        return 0
    fail_rank = Severity(args.fail_on).rank
    return 1 if any(f.severity.rank >= fail_rank for f in findings) else 0


def _run_rules() -> int:
    for rule in ALL_RULES:
        print(f"{rule.id}  [{rule.severity.value}]  {rule.title}")
        print(f"       {rule.description}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = build_parser().parse_args(argv)
    if args.command == "rules":
        return _run_rules()
    return _run_scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
