"""SARIF 2.1.0 output (iacscanner/sarif.py) -- structural validity + determinism, offline."""
from __future__ import annotations

import json

from conftest import SECURE, VULNERABLE
from iacscanner import __version__
from iacscanner.models import Severity
from iacscanner.rules import RULES, get_rule
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan


def _sarif(target):
    result = scan(target)
    return json.loads(render_sarif(result, result.findings)), result


def test_top_level_shape() -> None:
    log, _ = _sarif(VULNERABLE)
    assert log["version"] == "2.1.0"
    assert log["$schema"].endswith("sarif-2.1.0.json")
    assert len(log["runs"]) == 1


def test_driver_identifies_iacscanner() -> None:
    driver = _sarif(VULNERABLE)[0]["runs"][0]["tool"]["driver"]
    assert driver["name"] == "IaCScanner"
    assert driver["version"] == __version__
    assert driver["informationUri"].startswith("https://")


def test_every_rule_is_in_the_driver_catalogue() -> None:
    rules = _sarif(VULNERABLE)[0]["runs"][0]["tool"]["driver"]["rules"]
    ids = {r["id"] for r in rules}
    assert {rule.id for rule in RULES} <= ids
    assert "TL000" in ids  # the parse pseudo-rule is catalogued too


def test_rule_levels_map_from_severity() -> None:
    rules = {r["id"]: r for r in _sarif(VULNERABLE)[0]["runs"][0]["tool"]["driver"]["rules"]}
    expected = {
        Severity.CRITICAL: "error", Severity.HIGH: "error",
        Severity.MEDIUM: "warning", Severity.LOW: "note",
    }
    for rule in RULES:
        assert rules[rule.id]["defaultConfiguration"]["level"] == expected[rule.severity]
        assert rules[rule.id]["properties"]["cwe"] == list(rule.cwe_ids)


def test_results_reference_rules_by_index() -> None:
    run = _sarif(VULNERABLE)[0]["runs"][0]
    catalogue = run["tool"]["driver"]["rules"]
    assert run["results"], "expected results for the vulnerable fixtures"
    for res in run["results"]:
        assert catalogue[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in {"error", "warning", "note"}
        assert res["properties"]["confidence"] in {"low", "medium", "high"}


def test_results_carry_region_start_line_when_resolved() -> None:
    run = _sarif(VULNERABLE)[0]["runs"][0]
    by_anchor = {
        (res["ruleId"], res["locations"][0]["logicalLocations"][0]["fullyQualifiedName"]): res
        for res in run["results"]
    }
    physical = by_anchor[("TL001", "aws_s3_bucket.example_data")]["locations"][0]["physicalLocation"]
    assert physical["region"] == {"startLine": 12}
    for res in run["results"]:
        location = res["locations"][0]["physicalLocation"]
        if "region" in location:
            assert location["region"]["startLine"] >= 1


def test_unresolved_line_omits_the_region() -> None:
    import dataclasses

    result = scan(VULNERABLE)
    lineless = dataclasses.replace(result.findings[0], line=None)
    log = json.loads(render_sarif(result, [lineless]))
    physical = log["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in physical  # no line is omission, never startLine 0


def test_uris_are_relative_posix() -> None:
    run = _sarif(VULNERABLE)[0]["runs"][0]
    for res in run["results"]:
        uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "\\" not in uri
        assert ":" not in uri
        assert not uri.startswith("/")


def test_empty_findings_still_valid() -> None:
    log, result = _sarif(SECURE)
    assert result.findings == []
    run = log["runs"][0]
    assert run["results"] == []
    assert run["tool"]["driver"]["rules"], "the catalogue is present even with no results"


def test_sarif_is_byte_identical_across_runs() -> None:
    r = scan(VULNERABLE)
    assert render_sarif(r, r.findings) == render_sarif(r, r.findings)


def test_result_message_and_location_carry_the_finding() -> None:
    r = scan(VULNERABLE)
    log = json.loads(render_sarif(r, r.findings))
    first_finding = r.findings[0]
    first_result = log["runs"][0]["results"][0]
    assert first_result["message"]["text"] == first_finding.message
    assert first_result["locations"][0]["logicalLocations"][0]["fullyQualifiedName"] == first_finding.location
    # the rule catalogue's help text is the remediation
    rule = get_rule(first_finding.rule_id)
    catalogue = {r["id"]: r for r in log["runs"][0]["tool"]["driver"]["rules"]}
    assert catalogue[rule.id]["help"]["text"] == rule.remediation
