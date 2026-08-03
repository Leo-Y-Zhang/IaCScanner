"""Baseline workflow: fingerprints, write/read round-trip, suppression,
new-finding detection, malformed-file handling, and CLI end-to-end runs."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from conftest import DATA, SECURE, VULNERABLE
from iacscanner.baseline import (
    BASELINE_SCHEMA_VERSION,
    BASELINE_TOOL,
    BaselineError,
    fingerprint,
    load_baseline,
    split_findings,
    write_baseline,
)
from iacscanner.cli import main
from iacscanner.models import Finding, Severity


def _finding(
    rule_id="TL001",
    path="main.tf",
    location="aws_s3_bucket.x",
    message="m",
    severity=Severity.HIGH,
    sub_key="",
):
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        location=location,
        message=message,
        sub_key=sub_key,
    )


# ---------------------------------------------------------------- fingerprints


def test_fingerprint_is_rule_path_location_subkey() -> None:
    f = _finding()
    assert fingerprint(f) == ("TL001", "main.tf", "aws_s3_bucket.x", "")


def test_fingerprint_separates_siblings_at_one_location() -> None:
    """Two findings a rule emits for the SAME location must not share identity.

    They did. Measured on examples/vulnerable: 39 findings, 37 fingerprints, and
    one of the collisions was two CRITICALs on a single security group - world-open
    SSH and world-open RDP. Baselining the SSH one silently suppressed a
    newly-added RDP one, so a gate that had been reviewed and accepted stayed
    green while the tree got worse.
    """
    ssh = _finding(sub_key="SSH")
    rdp = _finding(sub_key="RDP")
    assert fingerprint(ssh) != fingerprint(rdp)
    assert split_findings([rdp], {fingerprint(ssh)}) == ([rdp], [])


def test_fingerprint_ignores_message_and_severity() -> None:
    a = _finding(message="old wording", severity=Severity.HIGH)
    b = _finding(message="new wording", severity=Severity.CRITICAL)
    assert fingerprint(a) == fingerprint(b)


def test_fingerprint_distinguishes_each_component() -> None:
    base = _finding()
    assert fingerprint(_finding(rule_id="TL002")) != fingerprint(base)
    assert fingerprint(_finding(path="other.tf")) != fingerprint(base)
    assert fingerprint(_finding(location="aws_s3_bucket.y")) != fingerprint(base)


# ------------------------------------------------------------ write/load unit


def test_write_then_load_round_trip(tmp_path: Path) -> None:
    findings = [_finding(), _finding(rule_id="TL002", path="a.tf", location="loc")]
    path = tmp_path / "baseline.json"
    write_baseline(path, findings)
    assert load_baseline(path) == {fingerprint(f) for f in findings}


def test_write_baseline_is_deterministic_sorted_and_deduped(tmp_path: Path) -> None:
    f1 = _finding(path="b.tf", message="first message")
    f2 = _finding(path="b.tf", message="second message")  # same fingerprint as f1
    f3 = _finding(rule_id="TL002", path="a.tf", location="loc")
    one, two = tmp_path / "one.json", tmp_path / "two.json"
    write_baseline(one, [f1, f2, f3])
    write_baseline(two, [f3, f2, f1])
    assert one.read_bytes() == two.read_bytes()
    data = json.loads(one.read_text(encoding="utf-8"))
    assert data["tool"] == BASELINE_TOOL
    assert data["schema_version"] == BASELINE_SCHEMA_VERSION
    assert len(data["findings"]) == 2  # duplicates collapsed
    assert data["findings"][0]["path"] == "a.tf"  # sorted by path first


def test_load_missing_file_raises() -> None:
    with pytest.raises(BaselineError):
        load_baseline(Path("does-not-exist-anywhere.json"))


def test_load_invalid_json_raises(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


@pytest.mark.parametrize(
    "payload",
    [
        [],  # top level must be an object
        {"schema_version": 1, "findings": []},  # missing tool
        {"tool": "other-tool", "schema_version": 1, "findings": []},
        {"tool": "themis-baseline", "schema_version": 99, "findings": []},
        {"tool": "themis-baseline", "schema_version": 1},  # missing findings
        {"tool": "themis-baseline", "schema_version": 1, "findings": "nope"},
        {"tool": "themis-baseline", "schema_version": 1, "findings": ["nope"]},
        {"tool": "themis-baseline", "schema_version": 1, "findings": [{"rule_id": "TL001", "path": "a.tf"}]},
        {"tool": "themis-baseline", "schema_version": 1, "findings": [{"rule_id": "TL001", "path": "a.tf", "location": 3}]},
        {"tool": "themis-baseline", "schema_version": 1, "findings": [{"rule_id": "", "path": "a.tf", "location": "l"}]},
    ],
)
def test_load_rejects_malformed_payloads(tmp_path: Path, payload) -> None:
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_load_ignores_unknown_extra_keys(tmp_path: Path) -> None:
    payload = {
        "tool": BASELINE_TOOL,
        "schema_version": BASELINE_SCHEMA_VERSION,
        "generated_by": "future iacscanner",
        "findings": [
            {"rule_id": "TL001", "path": "a.tf", "location": "l", "sub_key": "", "note": "extra"}
        ],
    }
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    assert load_baseline(path) == {("TL001", "a.tf", "l", "")}


def test_split_findings_partitions_by_fingerprint() -> None:
    known = _finding()
    fresh = _finding(rule_id="TL002")
    new, suppressed = split_findings([known, fresh], {fingerprint(known)})
    assert new == [fresh]
    assert suppressed == [known]


# ---------------------------------------------------- released-baseline guard


def test_baseline_written_by_release_1_0_0_still_suppresses_every_finding(capsys) -> None:
    """Cross-release fingerprint stability, pinned to a committed artifact.

    ``tests/data/baseline-1.0.0.json`` was generated by release 1.0.0 (commit
    25b6032, before line resolution existed), back when the tool was called
    Themis and its console script was ``themis``::

        themis scan examples/vulnerable --write-baseline tests/data/baseline-1.0.0.json

    That is why the committed file still carries ``"tool": "themis-baseline"``.
    It is a genuine artifact of an older release rather than one regenerated
    under the current name - regenerating it would destroy the only thing it
    proves, so the anachronism stays and this docstring explains it.

    The fingerprint is the triple (rule_id, path, location) and must never
    change between releases, so this old baseline must keep suppressing every
    finding the current code reports for the same tree - zero new findings.
    """
    fixture = DATA / "baseline-1.0.0.json"
    assert main(["scan", str(VULNERABLE), "--baseline", str(fixture), "--fail-on", "low"]) == 0
    captured = capsys.readouterr()
    assert "No findings" in captured.out
    assert "39 finding(s) suppressed, 0 new" in captured.err


# ------------------------------------------------------------------- CLI flow


def test_write_baseline_cli_exits_zero_and_records_findings(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(VULNERABLE), "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()
    fps = load_baseline(baseline)
    assert fps  # vulnerable fixtures produce findings
    assert all(len(fp) == 4 for fp in fps)


def test_baseline_suppresses_known_findings(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(VULNERABLE), "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()
    assert main(["scan", str(VULNERABLE), "--baseline", str(baseline)]) == 0
    captured = capsys.readouterr()
    assert "No findings" in captured.out
    assert "suppressed" in captured.err


def test_baseline_reports_only_new_findings_when_fixture_worsens(tmp_path: Path, capsys) -> None:
    target = tmp_path / "iac"
    target.mkdir()
    shutil.copy(VULNERABLE / "config.json", target / "config.json")
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(target), "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()

    # The tree worsens: a new vulnerable manifest appears.
    shutil.copy(VULNERABLE / "deployment.yaml", target / "deployment.yaml")
    code = main(["scan", str(target), "--format", "json", "--baseline", str(baseline)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1  # new findings at/above the fail-on threshold
    assert payload["findings"]  # something new is reported
    assert {f["path"] for f in payload["findings"]} == {"deployment.yaml"}


def test_baseline_exit_code_considers_only_new_findings(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    main(["scan", str(VULNERABLE), "--write-baseline", str(baseline)])
    capsys.readouterr()
    # Nothing new anywhere in the tree: exit 0 even though old criticals exist.
    assert main(["scan", str(VULNERABLE), "--baseline", str(baseline), "--fail-on", "low"]) == 0
    capsys.readouterr()


def test_write_baseline_respects_min_severity(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(VULNERABLE), "--min-severity", "critical", "--write-baseline", str(baseline)]) == 0
    capsys.readouterr()
    code = main(["scan", str(VULNERABLE), "--format", "json", "--baseline", str(baseline)])
    payload = json.loads(capsys.readouterr().out)
    severities = {f["severity"] for f in payload["findings"]}
    assert "critical" not in severities  # every critical was baselined
    assert severities  # lower-severity findings are still new
    assert code == 1  # vulnerable fixtures contain new high findings


def test_refresh_flow_writes_superset_baseline(tmp_path: Path, capsys) -> None:
    target = tmp_path / "iac"
    target.mkdir()
    shutil.copy(VULNERABLE / "config.json", target / "config.json")
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    main(["scan", str(target), "--write-baseline", str(old)])
    capsys.readouterr()
    shutil.copy(VULNERABLE / "deployment.yaml", target / "deployment.yaml")
    # Refresh: suppress against the old baseline while accepting everything new.
    assert main(["scan", str(target), "--baseline", str(old), "--write-baseline", str(new)]) == 0
    capsys.readouterr()
    assert load_baseline(old) < load_baseline(new)


def test_malformed_baseline_exits_two(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not json", encoding="utf-8")
    assert main(["scan", str(SECURE), "--baseline", str(baseline)]) == 2
    assert "baseline" in capsys.readouterr().err.lower()


def test_missing_baseline_file_exits_two(tmp_path: Path, capsys) -> None:
    assert main(["scan", str(SECURE), "--baseline", str(tmp_path / "absent.json")]) == 2
    assert "error" in capsys.readouterr().err.lower()


def test_wrong_schema_version_exits_two(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"tool": BASELINE_TOOL, "schema_version": 99, "findings": []}), encoding="utf-8")
    assert main(["scan", str(SECURE), "--baseline", str(baseline)]) == 2
    assert "schema" in capsys.readouterr().err.lower()


def test_write_baseline_to_missing_directory_exits_two(tmp_path: Path, capsys) -> None:
    dest = tmp_path / "no-such-dir" / "baseline.json"
    assert main(["scan", str(SECURE), "--write-baseline", str(dest)]) == 2
    assert "error" in capsys.readouterr().err.lower()


def test_parse_errors_still_exit_two_with_baseline(tmp_path: Path, capsys) -> None:
    target = tmp_path / "iac"
    target.mkdir()
    (target / "bad.tf").write_text('resource "x" {\n', encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    assert main(["scan", str(target), "--write-baseline", str(baseline)]) == 2
    capsys.readouterr()
    # A baselined parse warning never downgrades the parse-error exit code.
    assert main(["scan", str(target), "--baseline", str(baseline)]) == 2
    capsys.readouterr()


def test_baseline_note_goes_to_stderr_keeping_json_stdout_valid(tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    main(["scan", str(VULNERABLE), "--write-baseline", str(baseline)])
    capsys.readouterr()
    main(["scan", str(VULNERABLE), "--format", "json", "--baseline", str(baseline)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)  # stdout is pure JSON
    assert payload["summary"]["findings"] == 0
    assert "suppressed" in captured.err


def test_cli_end_to_end_subprocess_baseline(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    first = subprocess.run(
        [sys.executable, "-m", "iacscanner", "scan", str(VULNERABLE), "--write-baseline", str(baseline)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert first.returncode == 0
    second = subprocess.run(
        [sys.executable, "-m", "iacscanner", "scan", str(VULNERABLE), "--baseline", str(baseline)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert second.returncode == 0
    assert "No findings" in second.stdout
    assert "suppressed" in second.stderr
