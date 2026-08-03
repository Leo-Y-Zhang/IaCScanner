"""CWE/CIS metadata + confidence (models.Confidence, metadata.RULE_METADATA)."""
from __future__ import annotations

from conftest import VULNERABLE
from iacscanner.metadata import RULE_METADATA
from iacscanner.models import Confidence
from iacscanner.report import render_json, render_markdown, render_text
from iacscanner.rules import RULES, get_rule
from iacscanner.scanner import scan


def test_every_rule_has_a_cwe_and_a_cis_control() -> None:
    for rule in RULES:
        assert rule.cwe_ids, f"{rule.id} has no CWE"
        assert all(c.startswith("CWE-") for c in rule.cwe_ids), rule.id
        assert rule.cis_controls, f"{rule.id} has no CIS control"


def test_metadata_table_covers_exactly_the_registered_rules() -> None:
    assert set(RULE_METADATA) == {rule.id for rule in RULES}


def test_confidence_propagates_from_rule_to_finding() -> None:
    result = scan(VULNERABLE)
    assert result.findings
    for finding in result.findings:
        assert finding.confidence == get_rule(finding.rule_id).default_confidence


def test_confidence_defaults_are_calibrated() -> None:
    assert get_rule("TL001").default_confidence is Confidence.HIGH   # literal misconfig
    assert get_rule("TL002").default_confidence is Confidence.MEDIUM  # inferred absence
    assert Confidence.HIGH.rank > Confidence.MEDIUM.rank > Confidence.LOW.rank


def test_confidence_is_not_part_of_the_sort_key() -> None:
    # confidence is metadata, not identity: it must not appear in the baseline fingerprint
    result = scan(VULNERABLE)
    f = result.findings[0]
    assert f.sort_key == (f.path, f.rule_id, f.location, f.message)


def test_cwe_and_cis_appear_in_json() -> None:
    result = scan(VULNERABLE)
    import json
    payload = json.loads(render_json(result, result.findings))
    for finding in payload["findings"]:
        assert finding["cwe_ids"] and finding["cis_controls"]
        assert finding["confidence"] in {"low", "medium", "high"}


def test_confidence_appears_in_text_and_markdown() -> None:
    result = scan(VULNERABLE)
    assert "CONF" in render_text(result, result.findings)
    md = render_markdown(result, result.findings)
    assert "Confidence" in md
    assert "CWE-" in md  # references line in the remediation guidance
