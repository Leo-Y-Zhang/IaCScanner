"""Finding baselines for CI ergonomics.

``iacscanner scan PATH --write-baseline FILE`` records every reported
finding's fingerprint to FILE. A later ``iacscanner scan PATH --baseline
FILE`` suppresses exactly those findings and reports (and gates the exit
code on) only NEW findings, so a legacy tree can adopt IaCScanner in CI
without first fixing every historical issue.

Fingerprint stability contract
------------------------------
A finding's fingerprint is ``(rule_id, path, location, sub_key)``:

* ``rule_id`` -- stable rule identifiers (``TL000``-``TL032``); existing
  ids are never renumbered or reused for a different check.
* ``path`` -- the display path relative to the scan target with POSIX
  separators, so fingerprints match across machines and operating systems
  as long as the same target root is scanned.
* ``location`` -- the rule's structural anchor (Terraform resource
  address, Kubernetes ``Kind/name`` container path, workflow job/step
  index, or ``line N`` for text-pattern rules). Structural locations
  survive unrelated edits to the file; line-based locations shift when
  lines are added or removed above the finding, in which case the finding
  deliberately resurfaces as new.
* ``sub_key`` -- which of several findings a rule emits for that one
  location: the port (``"SSH"``), the property (``"versioning"``), the
  host namespace (``"hostPID"``). ``""`` for rules that emit at most one
  finding per location. Added in schema 2, because without it siblings
  shared an identity and ONE baselined entry suppressed ALL of them.
  Measured on ``examples/vulnerable``: 39 findings, 37 fingerprints, and
  one collision was two CRITICALs on a single security group -- world-open
  SSH and world-open RDP. Baselining one silently suppressed a
  newly-added other, so a reviewed gate stayed green while the tree got
  worse. Structural and stable, like ``location``, never a slice of the
  message.

Schema 1 baselines are still accepted and still suppress exactly what
they always did: an entry written before ``sub_key`` existed cannot say
which sibling it meant, so it keeps its original, coarser meaning and
matches every finding at that location. That honours the compatibility
promise below -- silently narrowing an old baseline would resurface
findings a user had already reviewed and accepted. Regenerate the
baseline to get the precise identity.

The finding ``message`` and ``severity`` are intentionally NOT part of the
fingerprint: message wording and severity classifications may be tuned
between IaCScanner versions without invalidating existing baselines. The
resolved source ``line`` (added in 1.1.0) is display metadata and is
likewise excluded, so baselines written by any earlier release keep
suppressing the same findings.

Matching is set-based: one baselined fingerprint suppresses every current
finding with that exact fingerprint. Parse errors always keep exit code 2,
baselined or not. The baseline file itself is deterministic (sorted,
de-duplicated, newline-terminated JSON), so it diffs cleanly in git.
"""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from iacscanner.models import Finding

BASELINE_TOOL = "themis-baseline"
# 2: added sub_key. A version-1 baseline is REJECTED by load_baseline rather than
# reinterpreted, which is the safe direction for a gate: regenerate and review,
# never keep suppressing silently under changed identity rules.
BASELINE_SCHEMA_VERSION = 2

# Fingerprint component order; also the key order of baseline entries.
_ENTRY_KEYS = ("rule_id", "path", "location", "sub_key")
# The three that must always be present and non-empty; sub_key may legitimately
# be "" for a rule that emits at most one finding per location.
_IDENTITY_KEYS = ("rule_id", "path", "location")
_SUPPORTED_SCHEMA_VERSIONS = frozenset({1, BASELINE_SCHEMA_VERSION})

# Stands in for "this entry predates sub_key and means every sibling at that
# location". Not producible by any rule, so it cannot collide with a real one.
ANY_SUB_KEY = "\x00any"

Fingerprint = tuple[str, str, str, str]


class BaselineError(ValueError):
    """Raised when a baseline file is missing, unreadable, or malformed."""


def fingerprint(finding: Finding) -> Fingerprint:
    """Stable identity of a finding: ``(rule_id, path, location, sub_key)``.

    See the module docstring for the stability contract.
    """
    return (finding.rule_id, finding.path, finding.location, finding.sub_key)


def write_baseline(path: Path, findings: Iterable[Finding]) -> None:
    """Write the fingerprints of *findings* to *path* as a baseline file.

    Output is deterministic: entries are de-duplicated and sorted by
    (path, rule_id, location), matching report ordering.
    """
    entries = sorted({fingerprint(f) for f in findings}, key=lambda fp: (fp[1], fp[0], fp[2]))
    payload = {
        "tool": BASELINE_TOOL,
        "schema_version": BASELINE_SCHEMA_VERSION,
        "findings": [dict(zip(_ENTRY_KEYS, fp, strict=True)) for fp in entries],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def load_baseline(path: Path) -> set[Fingerprint]:
    """Load *path* and return its set of fingerprints.

    Raises BaselineError (never a bare parse exception) when the file is
    missing, not JSON, or does not match the baseline schema. Unknown
    extra keys are ignored for forward compatibility.
    """
    name = path.as_posix()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise BaselineError(f"cannot read baseline file {name}: {exc}") from exc
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"baseline file {name} is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise BaselineError(f"baseline file {name}: top level must be a JSON object")
    if data.get("tool") != BASELINE_TOOL:
        raise BaselineError(f"baseline file {name}: 'tool' must be '{BASELINE_TOOL}'")
    version = data.get("schema_version")
    if version not in _SUPPORTED_SCHEMA_VERSIONS:
        raise BaselineError(
            f"baseline file {name}: unsupported schema_version "
            f"{version!r} (expected one of {sorted(_SUPPORTED_SCHEMA_VERSIONS)})"
        )
    entries = data.get("findings")
    if not isinstance(entries, list):
        raise BaselineError(f"baseline file {name}: 'findings' must be a list")

    fingerprints: set[Fingerprint] = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise BaselineError(f"baseline file {name}: findings[{index}] must be an object")
        values = []
        for key in _IDENTITY_KEYS:
            value = entry.get(key)
            if not isinstance(value, str) or not value:
                raise BaselineError(
                    f"baseline file {name}: findings[{index}].{key} must be a non-empty string"
                )
            values.append(value)
        if version == 1:
            # A version-1 entry predates sub_key and cannot say which sibling at
            # that location it meant, so it keeps its original, coarser meaning:
            # it suppresses everything at that location. That is the documented
            # promise (baselines written by any earlier release keep suppressing
            # the same findings) and it is why the promise is worth keeping —
            # silently narrowing an old baseline would resurface findings a user
            # had already reviewed. Regenerate to get the precise identity.
            sub = ANY_SUB_KEY
        else:
            sub = entry.get("sub_key", "")
            if not isinstance(sub, str):
                raise BaselineError(
                    f"baseline file {name}: findings[{index}].sub_key must be a string"
                )
        fingerprints.add((values[0], values[1], values[2], sub))
    return fingerprints


def split_findings(
    findings: Iterable[Finding], baseline: set[Fingerprint]
) -> tuple[list[Finding], list[Finding]]:
    """Partition *findings* into (new, suppressed) against *baseline*."""
    new: list[Finding] = []
    suppressed: list[Finding] = []
    for finding in findings:
        fp = fingerprint(finding)
        legacy = (fp[0], fp[1], fp[2], ANY_SUB_KEY)  # a version-1 entry, if any
        (suppressed if fp in baseline or legacy in baseline else new).append(finding)
    return new, suppressed
