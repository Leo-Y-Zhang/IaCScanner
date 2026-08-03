"""Every rule must fire on the vulnerable fixtures and stay silent on the secure ones.

Two fixture pairs exist: examples/vulnerable + examples/secure (Terraform,
Kubernetes, Actions, JSON) and examples/vulnerable-docker +
examples/secure-docker (the Dockerfile pack). The Dockerfile pair is
separate so the committed 1.0.0 baseline and sample artifacts generated
from examples/vulnerable stay byte-for-byte stable.
"""
from __future__ import annotations

import pytest

from conftest import rule_ids
from iacscanner.rules import RULES

ALL_RULE_IDS = [rule.id for rule in RULES]


def test_registry_has_expected_rules() -> None:
    assert len(RULES) == 32
    assert sorted(ALL_RULE_IDS) == ALL_RULE_IDS
    assert ALL_RULE_IDS[0] == "TL001"
    assert ALL_RULE_IDS[-1] == "TL032"


@pytest.mark.parametrize("rule_id", ALL_RULE_IDS)
def test_rule_fires_on_vulnerable_fixtures(
    rule_id: str, vulnerable_result, docker_vulnerable_result
) -> None:
    fired = rule_ids(vulnerable_result.findings) | rule_ids(docker_vulnerable_result.findings)
    assert rule_id in fired


@pytest.mark.parametrize("rule_id", ALL_RULE_IDS)
def test_rule_silent_on_secure_fixtures(
    rule_id: str, secure_result, docker_secure_result
) -> None:
    silent = rule_ids(secure_result.findings) | rule_ids(docker_secure_result.findings)
    assert rule_id not in silent


def test_secure_fixtures_are_fully_clean(secure_result, docker_secure_result) -> None:
    assert secure_result.findings == []
    assert secure_result.parse_error_count == 0
    assert docker_secure_result.findings == []
    assert docker_secure_result.parse_error_count == 0


def test_vulnerable_fixtures_parse_cleanly(vulnerable_result, docker_vulnerable_result) -> None:
    for result in (vulnerable_result, docker_vulnerable_result):
        assert result.parse_error_count == 0
        assert "TL000" not in rule_ids(result.findings)


def test_findings_are_deterministically_sorted(
    vulnerable_result, docker_vulnerable_result
) -> None:
    for result in (vulnerable_result, docker_vulnerable_result):
        keys = [(f.path, f.rule_id, f.location, f.message) for f in result.findings]
        assert keys == sorted(keys)
