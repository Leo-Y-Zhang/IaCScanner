"""Property-based robustness: the never-crashes threat model, mechanised.

The threat model treats every scanned file as attacker-controlled input and
promises that a scan degrades - it never raises, never guesses, and stays
deterministic. These properties feed Hypothesis-generated adversarial text
(a mix of arbitrary unicode and Dockerfile-shaped fragments with hostile
continuations, escape directives, and stage references) through the
Dockerfile parser, the TL029-TL032 rule pack, line attachment, inline
suppression parsing, the SARIF renderer, and a whole on-disk scan.

Every test is derandomized with no example database, so the suite explores
a fixed, reproducible example sequence on every machine - matching the
repository's determinism guarantees (a randomly flaking gate would be worse
than a smaller one). Bump ``max_examples`` locally for a deeper hunt.
"""
from __future__ import annotations

import json
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from iacscanner.docker import parse_dockerfile
from iacscanner.lines import attach_lines
from iacscanner.models import KIND_DOCKERFILE, Finding, ScanFile
from iacscanner.rules import dockerfile as dockerfile_rules
from iacscanner.sarif import render_sarif
from iacscanner.scanner import ScanResult, scan
from iacscanner.suppress import parse_suppressions_with_warnings

_SETTINGS = {"derandomize": True, "database": None, "deadline": None}

_KEYWORDS = (
    "FROM", "RUN", "ENV", "ARG", "USER", "EXPOSE", "COPY", "WORKDIR",
    "ENTRYPOINT", "HEALTHCHECK", "ONBUILD", "from", "EnV", "#",
    "# escape=`", "# escape=\\", "# themis:ignore",
)
_token = st.text(max_size=12)
_line = st.one_of(
    _token,
    st.tuples(st.sampled_from(_KEYWORDS), _token).map(lambda kv: f"{kv[0]} {kv[1]}"),
    st.tuples(st.sampled_from(_KEYWORDS), _token).map(lambda kv: f"{kv[0]} {kv[1]} \\"),
    st.just("\\"),
    st.just("FROM alpine:3.20 AS build"),
    st.just("FROM ${BASE}"),
    st.just("FROM build"),
    st.just("USER root"),
    st.just("ENV DB_PASSWORD=x A=$B"),
    st.just("EXPOSE 22 22/tcp $PORT"),
    st.just("RUN <<EOF"),
    st.just("COPY <<-'EOF' <<\"X\" /dest"),
    st.just("EOF"),
)
# Dockerfile-shaped input (hits the parser's structure) mixed with raw noise.
_dockerfiles = st.lists(_line, max_size=30).map("\n".join)
_texts = st.one_of(_dockerfiles, st.text(max_size=2000))


def _scan_file(text: str) -> ScanFile:
    return ScanFile(path="Dockerfile", kind=KIND_DOCKERFILE, data=parse_dockerfile(text), text=text)


def _all_findings(sf: ScanFile) -> list[Finding]:
    findings: list[Finding] = []
    for rule in dockerfile_rules.RULES:
        assert rule.check is not None
        findings.extend(rule.check(sf))
    return findings


@given(text=_texts)
@settings(max_examples=200, **_SETTINGS)
def test_parse_dockerfile_is_total_and_deterministic(text: str) -> None:
    first = parse_dockerfile(text)
    assert first == parse_dockerfile(text)
    bound = max(1, len(text.splitlines()))
    for position, stage in enumerate(first.stages):
        assert stage.index == position
        assert 1 <= stage.line <= bound
        for instruction in stage.instructions:
            assert instruction.cmd == instruction.cmd.upper()
            assert 1 <= instruction.line <= bound


@given(text=_texts)
@settings(max_examples=100, **_SETTINGS)
def test_rule_pack_is_total_and_findings_are_well_formed(text: str) -> None:
    sf = _scan_file(text)
    for rule in dockerfile_rules.RULES:
        assert rule.check is not None
        first = rule.check(sf)
        assert first == rule.check(sf)
        for finding in first:
            assert finding.rule_id == rule.id
            assert finding.path == "Dockerfile"
            assert finding.location.startswith("stage[")
            assert finding.message


@given(text=_texts)
@settings(max_examples=100, **_SETTINGS)
def test_line_attachment_never_crashes_or_guesses_below_one(text: str) -> None:
    sf = _scan_file(text)
    findings = _all_findings(sf)
    resolved = attach_lines([sf], findings)
    assert len(resolved) == len(findings)
    for finding in resolved:
        assert finding.line is None or finding.line >= 1


@given(text=_texts)
@settings(max_examples=60, **_SETTINGS)
def test_sarif_stays_valid_2_1_0_on_hostile_dockerfiles(text: str) -> None:
    sf = _scan_file(text)
    findings = sorted(_all_findings(sf), key=lambda f: f.sort_key)
    result = ScanResult(target="target", files=[sf], findings=findings, parse_error_count=0)
    log = json.loads(render_sarif(result, findings))
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert len(run["results"]) == len(findings)
    for res in run["results"]:
        assert 0 <= res["ruleIndex"] < len(rules)
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]


@given(text=st.text(max_size=2000))
@settings(max_examples=100, **_SETTINGS)
def test_suppression_parsing_is_total_and_deterministic(text: str) -> None:
    first = parse_suppressions_with_warnings(text)
    assert first == parse_suppressions_with_warnings(text)


@given(text=_texts)
@settings(max_examples=25, suppress_health_check=[HealthCheck.function_scoped_fixture], **_SETTINGS)
def test_whole_scan_of_a_hostile_dockerfile_never_crashes(tmp_path: Path, text: str) -> None:
    (tmp_path / "Dockerfile").write_text(text, encoding="utf-8")
    result = scan(tmp_path)
    keys = [finding.sort_key for finding in result.findings]
    assert keys == sorted(keys)
