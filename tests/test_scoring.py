"""Tests for severity weights, risk scores, and letter grades."""
from __future__ import annotations

import pytest

from iacscanner.models import Finding, Severity
from iacscanner.scoring import grade, per_file_scores, risk_score, total_weight


def _finding(sev: Severity, path: str = "a.tf") -> Finding:
    return Finding(rule_id="TL999", severity=sev, path=path, location="x", message="m")


def test_severity_weights() -> None:
    assert Severity.CRITICAL.weight == 25
    assert Severity.HIGH.weight == 15
    assert Severity.MEDIUM.weight == 7
    assert Severity.LOW.weight == 3


def test_severity_ranks_are_ordered() -> None:
    ranks = [Severity.LOW.rank, Severity.MEDIUM.rank, Severity.HIGH.rank, Severity.CRITICAL.rank]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == 4


def test_total_weight_sums_weights() -> None:
    findings = [_finding(Severity.CRITICAL), _finding(Severity.LOW)]
    assert total_weight(findings) == 28


def test_risk_score_empty_is_zero() -> None:
    assert risk_score([]) == 0
    assert grade(0) == "A"


def test_risk_score_caps_at_100() -> None:
    findings = [_finding(Severity.CRITICAL)] * 10
    assert risk_score(findings) == 100


@pytest.mark.parametrize(
    ("score", "expected"),
    [(0, "A"), (1, "B"), (14, "B"), (15, "C"), (39, "C"), (40, "D"), (69, "D"), (70, "F"), (100, "F")],
)
def test_grade_boundaries(score: int, expected: str) -> None:
    assert grade(score) == expected


def test_per_file_scores_grouped_and_sorted() -> None:
    findings = [
        _finding(Severity.HIGH, "b.tf"),
        _finding(Severity.CRITICAL, "a.tf"),
        _finding(Severity.LOW, "a.tf"),
    ]
    scores = per_file_scores(findings)
    assert list(scores) == ["a.tf", "b.tf"]
    assert scores["a.tf"] == 28
    assert scores["b.tf"] == 15
