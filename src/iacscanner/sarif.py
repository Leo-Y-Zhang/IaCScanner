"""SARIF 2.1.0 output for GitHub code-scanning (and any SARIF viewer).

A first-class CI artifact: upload it and every finding becomes an inline pull-request
annotation. Deterministic by construction -- no timestamps, sorted keys, a fixed rule
catalogue and POSIX relative URIs -- so the same scan regenerates byte-identical SARIF.
Standard library only; no network, no schema download at runtime.
"""
from __future__ import annotations

import json
from typing import Any

from iacscanner import __version__
from iacscanner.models import Finding, Rule, Severity
from iacscanner.rules import ALL_RULES, get_rule
from iacscanner.scanner import ScanResult

INFORMATION_URI = "https://github.com/Leo-Y-Zhang/IaCScanner"

# SARIF result levels + GitHub's numeric "security-severity" (0.0-10.0) for sorting.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "3.0",
}

# The rule catalogue is fixed and sorted, so ruleIndex is stable across scans.
_CATALOG: tuple[Rule, ...] = tuple(sorted(ALL_RULES, key=lambda rule: rule.id))
_RULE_INDEX = {rule.id: i for i, rule in enumerate(_CATALOG)}


def _descriptor(rule: Rule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "name": rule.title,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.rationale},
        "help": {"text": rule.remediation},
        "defaultConfiguration": {"level": _LEVEL[rule.severity]},
        "properties": {
            "tags": [*rule.cwe_ids, *rule.cis_controls],
            "cwe": list(rule.cwe_ids),
            "cis": list(rule.cis_controls),
            "security-severity": _SECURITY_SEVERITY[rule.severity],
        },
    }


def _result(finding: Finding) -> dict[str, Any]:
    rule = get_rule(finding.rule_id)
    physical: dict[str, Any] = {"artifactLocation": {"uri": finding.path}}
    # region.startLine only when the anchor resolved (always >= 1); an
    # unresolved line is omitted entirely, never guessed or zeroed.
    if finding.line is not None and finding.line >= 1:
        physical["region"] = {"startLine": finding.line}
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": _RULE_INDEX[finding.rule_id],
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": physical,
                "logicalLocations": [{"fullyQualifiedName": finding.location}],
            }
        ],
        "properties": {
            "confidence": finding.confidence.value,
            "cwe": list(rule.cwe_ids),
            "cis": list(rule.cis_controls),
        },
    }


def render_sarif(result: ScanResult, findings: list[Finding]) -> str:
    """Render a deterministic SARIF 2.1.0 log for *findings*."""
    log = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "IaCScanner",
                        "version": __version__,
                        "informationUri": INFORMATION_URI,
                        "rules": [_descriptor(rule) for rule in _CATALOG],
                    }
                },
                "results": [_result(f) for f in findings],
            }
        ],
    }
    return json.dumps(log, indent=2, sort_keys=True) + "\n"
