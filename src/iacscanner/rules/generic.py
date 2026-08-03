"""Generic text rules that apply to every scanned file: TL018."""
from __future__ import annotations

import re

from iacscanner.models import ANY_KIND, Finding, Rule, ScanFile, Severity

_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub personal access token", re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")),
    (
        "hardcoded password assignment",
        re.compile(r"(?i)\bpassword\b[\"']?\s*[:=]\s*[\"']?(?P<value>[^\s\"',;]{4,})"),
    ),
)

# Values that are references or templates, not literals.
_REFERENCE_PREFIXES = ("$", "var.", "local.", "data.", "{{", "<", "*")


def _mask(token: str) -> str:
    """Show only a short prefix of a matched secret-looking token."""
    return token if len(token) <= 8 else token[:8] + "..."


def _check_tl018(sf: ScanFile) -> list[Finding]:
    findings = []
    for lineno, line in enumerate(sf.text.splitlines(), start=1):
        for label, pattern in _PATTERNS:
            for match in pattern.finditer(line):
                value = match.groupdict().get("value")
                if value is not None and value.startswith(_REFERENCE_PREFIXES):
                    continue
                token = value if value is not None else match.group(0)
                findings.append(
                    TL018.finding(sf, f"line {lineno}", f"{label} detected ({_mask(token)})")
                )
    return findings


TL018 = Rule(
    id="TL018",
    title="Hardcoded credential pattern in file",
    severity=Severity.CRITICAL,
    description="The raw file text contains an AWS access key ID, a GitHub token, or a literal password assignment.",
    rationale="Credentials committed to configuration files spread through clones, backups, and CI caches and must be treated as compromised.",
    remediation="Remove the literal value, rotate the credential, and load it from an environment variable or secret manager.",
    kinds=(ANY_KIND,),
    check=_check_tl018,
)

RULES: tuple[Rule, ...] = (TL018,)
