"""Shared test fixtures and helpers for the IaCScanner test suite."""
from __future__ import annotations

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = PROJECT_ROOT / "examples"
VULNERABLE = EXAMPLES / "vulnerable"
SECURE = EXAMPLES / "secure"
# The Dockerfile fixtures live in their own directories so the committed
# 1.0.0 baseline (and the sample artifacts) for examples/vulnerable stay
# byte-for-byte reproducible.
VULNERABLE_DOCKER = EXAMPLES / "vulnerable-docker"
SECURE_DOCKER = EXAMPLES / "secure-docker"
DATA = PROJECT_ROOT / "tests" / "data"


def parse_snippet(tmp_path: Path, name: str, content: str):
    """Write *content* to tmp_path/name and parse it into a ScanFile."""
    from iacscanner.parsers import parse_file

    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return parse_file(path, name)


def rule_ids(findings) -> set[str]:
    """Return the set of rule ids present in *findings*."""
    return {f.rule_id for f in findings}


@pytest.fixture(scope="session")
def vulnerable_result():
    """Scan the vulnerable fixture directory once per session."""
    from iacscanner.scanner import scan

    return scan(VULNERABLE)


@pytest.fixture(scope="session")
def secure_result():
    """Scan the secure fixture directory once per session."""
    from iacscanner.scanner import scan

    return scan(SECURE)


@pytest.fixture(scope="session")
def docker_vulnerable_result():
    """Scan the vulnerable Dockerfile fixture directory once per session."""
    from iacscanner.scanner import scan

    return scan(VULNERABLE_DOCKER)


@pytest.fixture(scope="session")
def docker_secure_result():
    """Scan the secure Dockerfile fixture directory once per session."""
    from iacscanner.scanner import scan

    return scan(SECURE_DOCKER)
