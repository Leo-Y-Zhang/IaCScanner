"""Risk scoring.

Formula (documented in the README): every finding contributes its
severity weight (critical=25, high=15, medium=7, low=3). A score is
``min(100, sum_of_weights)`` computed per file and overall. Grades:
A = 0, B = 1-14, C = 15-39, D = 40-69, F = 70-100.
"""
from __future__ import annotations

from collections.abc import Iterable

from iacscanner.models import Finding

SCORE_FORMULA = "min(100, sum of severity weights: critical=25 high=15 medium=7 low=3)"

_GRADE_STEPS = ((0, "A"), (14, "B"), (39, "C"), (69, "D"))


def total_weight(findings: Iterable[Finding]) -> int:
    """Sum of severity weights across *findings* (uncapped)."""
    return sum(f.severity.weight for f in findings)


def risk_score(findings: Iterable[Finding]) -> int:
    """Overall 0-100 risk score for *findings*."""
    return min(100, total_weight(findings))


def grade(score: int) -> str:
    """Letter grade A-F for a 0-100 *score*."""
    for ceiling, letter in _GRADE_STEPS:
        if score <= ceiling:
            return letter
    return "F"


def per_file_scores(findings: Iterable[Finding]) -> dict[str, int]:
    """Risk score per file path, sorted by path."""
    weights: dict[str, int] = {}
    for f in findings:
        weights[f.path] = weights.get(f.path, 0) + f.severity.weight
    return {path: min(100, weight) for path, weight in sorted(weights.items())}
