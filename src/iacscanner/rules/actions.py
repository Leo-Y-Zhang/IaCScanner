"""GitHub Actions workflow rules: TL016-TL017."""
from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from iacscanner.models import KIND_GITHUB_ACTIONS, Finding, Rule, ScanFile, Severity

_HEAD_REF_TOKENS = ("pull_request.head", "head.ref", "head.sha")
_ECHO_RE = re.compile(r"\b(echo|printf|print)\b")


def _workflows(sf: ScanFile) -> Iterator[dict[Any, Any]]:
    docs = sf.data if isinstance(sf.data, list) else []
    for doc in docs:
        if isinstance(doc, dict) and isinstance(doc.get("jobs"), dict):
            yield doc


def _triggers(doc: dict[Any, Any]) -> set[str]:
    # PyYAML parses the bare key `on:` as boolean True.
    raw: Any = doc.get("on", doc.get(True))
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(item) for item in raw}
    if isinstance(raw, dict):
        return {str(key) for key in raw}
    return set()


def _steps(doc: dict[Any, Any]) -> Iterator[tuple[str, int, dict[Any, Any]]]:
    for job_name, job in doc["jobs"].items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or []):
            if isinstance(step, dict):
                yield str(job_name), index, step


def _check_tl016(sf: ScanFile) -> list[Finding]:
    findings = []
    for doc in _workflows(sf):
        if "pull_request_target" not in _triggers(doc):
            continue
        for job_name, index, step in _steps(doc):
            uses = step.get("uses", "")
            raw_with = step.get("with")
            with_block = raw_with if isinstance(raw_with, dict) else {}
            ref = str(with_block.get("ref", ""))
            if isinstance(uses, str) and uses.startswith("actions/checkout") and any(
                token in ref for token in _HEAD_REF_TOKENS
            ):
                findings.append(
                    TL016.finding(
                        sf,
                        f"jobs.{job_name}.steps[{index}]",
                        "pull_request_target workflow checks out the PR head",
                    )
                )
    return findings


def _check_tl017(sf: ScanFile) -> list[Finding]:
    findings = []
    for doc in _workflows(sf):
        for job_name, index, step in _steps(doc):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            for line in run.splitlines():
                if "${{" in line and "secrets." in line and _ECHO_RE.search(line):
                    findings.append(
                        TL017.finding(
                            sf,
                            f"jobs.{job_name}.steps[{index}]",
                            "run step echoes a secret into the build log",
                        )
                    )
                    break
    return findings


_MUTABLE_BRANCHES = {"main", "master", "head", "develop", "trunk", "latest"}


def _check_tl028(sf: ScanFile) -> list[Finding]:
    findings = []
    for doc in _workflows(sf):
        for job_name, index, step in _steps(doc):
            uses = step.get("uses")
            if not isinstance(uses, str) or "@" not in uses:
                continue  # a local action (./path) or no ref
            ref = uses.rsplit("@", 1)[1]
            if ref.lower() in _MUTABLE_BRANCHES:
                findings.append(
                    TL028.finding(
                        sf,
                        f"jobs.{job_name}.steps[{index}]",
                        f"action '{uses}' is pinned to the mutable ref '{ref}'",
                    )
                )
    return findings


_GHA = (KIND_GITHUB_ACTIONS,)

TL016 = Rule(
    id="TL016",
    title="pull_request_target checks out untrusted PR code",
    severity=Severity.CRITICAL,
    description="A workflow triggered by pull_request_target checks out the pull request head ref/sha.",
    rationale="pull_request_target runs with repository secrets; executing attacker-controlled PR code with them is a known takeover pattern.",
    remediation="on: pull_request  # or keep pull_request_target but never check out the PR head",
    kinds=_GHA,
    check=_check_tl016,
)

TL017 = Rule(
    id="TL017",
    title="Secret echoed into the build log",
    severity=Severity.HIGH,
    description="A run step prints a ${{ secrets.* }} value with echo/printf/print.",
    rationale="Log masking is best-effort; transformed or partial secrets routinely leak through build logs.",
    remediation="env:\n  API_TOKEN: ${{ secrets.API_TOKEN }}  # pass via env, never echo it",
    kinds=_GHA,
    check=_check_tl017,
)

TL028 = Rule(
    id="TL028",
    title="Action pinned to a mutable branch",
    severity=Severity.HIGH,
    description="A workflow step uses an action pinned to a mutable ref (@main, @master, ...) rather than a version tag or commit SHA.",
    rationale="A mutable branch ref runs whatever code that branch holds at run time; if the action is compromised or retargeted, it executes in your workflow with its secrets.",
    remediation="uses: owner/action@<40-char commit SHA>  # or at least a version tag",
    kinds=_GHA,
    check=_check_tl028,
)

RULES: tuple[Rule, ...] = (TL016, TL017, TL028)
