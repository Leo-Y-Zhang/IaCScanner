"""Rule registry: the TL001-TL032 checks plus the TL000 parse warning."""
from __future__ import annotations

import dataclasses

from iacscanner.metadata import RULE_METADATA
from iacscanner.models import Rule, Severity
from iacscanner.rules import actions, dockerfile, generic, kubernetes, terraform


def _with_metadata(rule: Rule) -> Rule:
    """Attach the central CWE/CIS/confidence metadata onto a rule for the registry."""
    meta = RULE_METADATA.get(rule.id)
    if meta is None:
        return rule
    cwe_ids, cis_controls, confidence = meta
    return dataclasses.replace(
        rule, cwe_ids=cwe_ids, cis_controls=cis_controls, default_confidence=confidence
    )

PARSE_RULE = Rule(
    id="TL000",
    title="File could not be parsed",
    severity=Severity.LOW,
    description="The file failed to parse and was skipped; its content was not analyzed.",
    rationale="Unparseable IaC files hide misconfigurations from every scanner, including this one.",
    remediation="Fix the syntax error so the file can be analyzed (the scan exit code is 2 while parse errors remain).",
    kinds=(),
    check=None,
)

RULES: tuple[Rule, ...] = tuple(
    _with_metadata(rule)
    for rule in sorted(
        terraform.RULES + kubernetes.RULES + actions.RULES + generic.RULES + dockerfile.RULES,
        key=lambda rule: rule.id,
    )
)

ALL_RULES: tuple[Rule, ...] = (PARSE_RULE,) + RULES

_BY_ID = {rule.id: rule for rule in ALL_RULES}


def get_rule(rule_id: str) -> Rule:
    """Look up a rule by id; raises KeyError for unknown ids."""
    return _BY_ID[rule_id]
