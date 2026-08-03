"""Core data model: severities, scan files, rules, and findings."""
from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from iacscanner.graph import ScanContext

# File kinds produced by the parsers. Rules declare which kinds they apply
# to; "*" means every successfully parsed file.
KIND_TERRAFORM = "terraform"
KIND_KUBERNETES = "kubernetes"
KIND_GITHUB_ACTIONS = "github-actions"
KIND_YAML = "yaml"
KIND_JSON = "json"
KIND_DOCKERFILE = "dockerfile"
ANY_KIND = "*"


class Severity(str, enum.Enum):
    """Finding severity with a stable ordering and scoring weight."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Ordering value; higher means more severe."""
        return _RANKS[self]

    @property
    def weight(self) -> int:
        """Contribution of one finding of this severity to a risk score."""
        return _WEIGHTS[self]


_RANKS = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}
_WEIGHTS = {Severity.LOW: 3, Severity.MEDIUM: 7, Severity.HIGH: 15, Severity.CRITICAL: 25}


class Confidence(str, enum.Enum):
    """How certain a finding is, independent of how severe it would be if real."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _CONFIDENCE_RANKS[self]


_CONFIDENCE_RANKS = {Confidence.LOW: 0, Confidence.MEDIUM: 1, Confidence.HIGH: 2}


@dataclass
class ScanFile:
    """One parsed input file.

    ``path`` is a display path relative to the scan target (never an
    absolute filesystem path), ``kind`` is one of the KIND_* constants,
    ``data`` is the parsed structure, ``text`` is the raw file content,
    and ``error`` holds a short parse-error summary when parsing failed.
    """

    path: str
    kind: str
    data: Any
    text: str
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    """A single misconfiguration detected in a file.

    ``line`` is the 1-based source line the structural anchor (``location``)
    resolves to, or ``None`` when the resolver could not map it unambiguously.
    It is display metadata only: never part of equality, the sort key, or the
    baseline fingerprint.
    """

    rule_id: str
    severity: Severity
    path: str
    location: str
    message: str
    confidence: Confidence = Confidence.HIGH
    line: int | None = field(default=None, compare=False)
    # Distinguishes findings a rule emits for the SAME location: the port, the
    # property, the container. Part of the baseline fingerprint, because without
    # it one baselined entry suppresses every sibling at that location — measured
    # on examples/vulnerable, two CRITICAL findings (world-open SSH and world-open
    # RDP on one security group) shared a single fingerprint. Structural and
    # stable by contract, like `location`, unlike `message`.
    sub_key: str = ""

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        """Deterministic ordering key: path, then rule, then position. Confidence and
        line are metadata, not identity, so they stay out of the key (and the baseline
        fingerprint)."""
        return (self.path, self.rule_id, self.location, self.message)


@dataclass(frozen=True)
class Rule:
    """A misconfiguration rule.

    ``check`` inspects one ScanFile and returns findings; it is ``None``
    only for the TL000 parse-warning pseudo-rule, whose findings are
    emitted by the scanner itself.
    """

    id: str
    title: str
    severity: Severity
    description: str
    rationale: str
    remediation: str
    kinds: tuple[str, ...]
    check: Callable[[ScanFile], list[Finding]] | None = field(default=None, compare=False)
    # Graph-aware variant: receives the whole-scan ScanContext for cross-file analysis.
    # A rule defines exactly one of `check` / `check_ctx` (or neither, for TL000).
    check_ctx: Callable[[ScanFile, ScanContext], list[Finding]] | None = field(
        default=None, compare=False
    )
    # Triage metadata, attached from a central table when the registry is assembled.
    cwe_ids: tuple[str, ...] = ()
    cis_controls: tuple[str, ...] = ()
    default_confidence: Confidence = Confidence.HIGH

    def applies_to(self, kind: str) -> bool:
        """Return True when this rule should run against files of *kind*."""
        return ANY_KIND in self.kinds or kind in self.kinds

    def finding(
        self, sf: ScanFile, location: str, message: str, sub_key: str = ""
    ) -> Finding:
        """Build a Finding for this rule against *sf*. Confidence is stamped centrally by
        the scanner from the metadata table, so checks stay free of triage bookkeeping.

        Pass *sub_key* whenever this rule can emit more than one finding for the
        same ``location`` - the port, the property, the container. Without it those
        findings share a baseline fingerprint, and one baselined entry suppresses
        every sibling, including ones that did not exist when the baseline was
        written. Keep it structural and stable ("SSH", "versioning"), never a slice
        of the message: message wording is deliberately outside the fingerprint so
        it can be retuned freely.
        """
        return Finding(
            rule_id=self.id,
            severity=self.severity,
            path=sf.path,
            location=location,
            message=message,
            sub_key=sub_key,
        )
