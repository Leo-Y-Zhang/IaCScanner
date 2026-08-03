"""Unit edge cases for the curated AWS expansion (TL020-TL025).

The discipline: each rule fires on an EXPLICIT misconfiguration and stays silent both on the
secure value AND when the field is omitted (its insecure default), so brownfield code that
simply hasn't set the field is not flagged.
"""
from __future__ import annotations

from pathlib import Path

from conftest import parse_snippet, rule_ids
from iacscanner.rules import get_rule


def _ids(rule_id: str, tmp_path: Path, text: str) -> set[str]:
    sf = parse_snippet(tmp_path, "a.tf", text)
    return rule_ids(get_rule(rule_id).check(sf))


class TestTL020KmsRotation:
    def test_explicit_false_fires(self, tmp_path):
        assert "TL020" in _ids("TL020", tmp_path, 'resource "aws_kms_key" "k" { enable_key_rotation = false }')

    def test_true_silent(self, tmp_path):
        assert "TL020" not in _ids("TL020", tmp_path, 'resource "aws_kms_key" "k" { enable_key_rotation = true }')

    def test_omitted_silent(self, tmp_path):
        assert "TL020" not in _ids("TL020", tmp_path, 'resource "aws_kms_key" "k" { description = "x" }')


class TestTL021EcrScan:
    def test_explicit_false_fires(self, tmp_path):
        text = 'resource "aws_ecr_repository" "r" { image_scanning_configuration { scan_on_push = false } }'
        assert "TL021" in _ids("TL021", tmp_path, text)

    def test_true_silent(self, tmp_path):
        text = 'resource "aws_ecr_repository" "r" { image_scanning_configuration { scan_on_push = true } }'
        assert "TL021" not in _ids("TL021", tmp_path, text)

    def test_no_block_silent(self, tmp_path):
        assert "TL021" not in _ids("TL021", tmp_path, 'resource "aws_ecr_repository" "r" { name = "a" }')


class TestTL022EfsEncryption:
    def test_explicit_false_fires(self, tmp_path):
        assert "TL022" in _ids("TL022", tmp_path, 'resource "aws_efs_file_system" "f" { encrypted = false }')

    def test_true_silent(self, tmp_path):
        assert "TL022" not in _ids("TL022", tmp_path, 'resource "aws_efs_file_system" "f" { encrypted = true }')


class TestTL023Imdsv2:
    def test_optional_fires(self, tmp_path):
        text = 'resource "aws_instance" "i" { metadata_options { http_tokens = "optional" } }'
        assert "TL023" in _ids("TL023", tmp_path, text)

    def test_required_silent(self, tmp_path):
        text = 'resource "aws_instance" "i" { metadata_options { http_tokens = "required" } }'
        assert "TL023" not in _ids("TL023", tmp_path, text)

    def test_launch_template_also_covered(self, tmp_path):
        text = 'resource "aws_launch_template" "t" { metadata_options { http_tokens = "optional" } }'
        assert "TL023" in _ids("TL023", tmp_path, text)

    def test_no_metadata_options_silent(self, tmp_path):
        assert "TL023" not in _ids("TL023", tmp_path, 'resource "aws_instance" "i" { ami = "ami-1" }')


class TestTL024DynamoPitr:
    def test_disabled_fires(self, tmp_path):
        text = 'resource "aws_dynamodb_table" "d" { point_in_time_recovery { enabled = false } }'
        assert "TL024" in _ids("TL024", tmp_path, text)

    def test_enabled_silent(self, tmp_path):
        text = 'resource "aws_dynamodb_table" "d" { point_in_time_recovery { enabled = true } }'
        assert "TL024" not in _ids("TL024", tmp_path, text)


class TestTL025RdsBackups:
    def test_zero_retention_fires(self, tmp_path):
        assert "TL025" in _ids("TL025", tmp_path, 'resource "aws_db_instance" "db" { backup_retention_period = 0 }')

    def test_positive_retention_silent(self, tmp_path):
        assert "TL025" not in _ids("TL025", tmp_path, 'resource "aws_db_instance" "db" { backup_retention_period = 7 }')

    def test_omitted_silent(self, tmp_path):
        assert "TL025" not in _ids("TL025", tmp_path, 'resource "aws_db_instance" "db" { engine = "postgres" }')


_POD = """\
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
{spec}
  containers:
    - name: c
      image: nginx:1.0
{container}
"""

_WORKFLOW = """\
name: w
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: {uses}
"""


def _yaml_ids(rule_id: str, tmp_path: Path, text: str) -> set[str]:
    sf = parse_snippet(tmp_path, "a.yaml", text)
    return rule_ids(get_rule(rule_id).check(sf))


class TestTL026RootUid:
    def test_container_runasuser_zero_fires(self, tmp_path):
        text = _POD.format(spec="", container="      securityContext:\n        runAsUser: 0")
        assert "TL026" in _yaml_ids("TL026", tmp_path, text)

    def test_nonzero_uid_silent(self, tmp_path):
        text = _POD.format(spec="", container="      securityContext:\n        runAsUser: 1000")
        assert "TL026" not in _yaml_ids("TL026", tmp_path, text)

    def test_pod_fsgroup_zero_fires(self, tmp_path):
        text = _POD.format(spec="  securityContext:\n    fsGroup: 0", container="")
        assert "TL026" in _yaml_ids("TL026", tmp_path, text)

    def test_omitted_silent(self, tmp_path):
        assert "TL026" not in _yaml_ids("TL026", tmp_path, _POD.format(spec="", container=""))


class TestTL027HostMounts:
    def test_hostpid_fires(self, tmp_path):
        text = _POD.format(spec="  hostPID: true", container="")
        assert "TL027" in _yaml_ids("TL027", tmp_path, text)

    def test_hostpath_volume_fires(self, tmp_path):
        text = _POD.format(spec="  volumes:\n    - name: h\n      hostPath:\n        path: /", container="")
        assert "TL027" in _yaml_ids("TL027", tmp_path, text)

    def test_no_host_mounts_silent(self, tmp_path):
        assert "TL027" not in _yaml_ids("TL027", tmp_path, _POD.format(spec="", container=""))


class TestTL028UnpinnedAction:
    def test_main_branch_fires(self, tmp_path):
        assert "TL028" in _yaml_ids("TL028", tmp_path, _WORKFLOW.format(uses="some-org/action@main"))

    def test_master_branch_fires(self, tmp_path):
        assert "TL028" in _yaml_ids("TL028", tmp_path, _WORKFLOW.format(uses="some-org/action@master"))

    def test_version_tag_silent(self, tmp_path):
        assert "TL028" not in _yaml_ids("TL028", tmp_path, _WORKFLOW.format(uses="actions/checkout@v4"))

    def test_sha_pin_silent(self, tmp_path):
        sha = "8f4b7f84864484a7bf31766abe9204da3cbe65b3"
        assert "TL028" not in _yaml_ids("TL028", tmp_path, _WORKFLOW.format(uses=f"actions/checkout@{sha}"))

    def test_local_action_silent(self, tmp_path):
        assert "TL028" not in _yaml_ids("TL028", tmp_path, _WORKFLOW.format(uses="./.github/actions/local"))
