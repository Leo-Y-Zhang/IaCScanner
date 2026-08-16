"""Targeted edge-case tests for individual rule checks."""
from __future__ import annotations

from pathlib import Path

from conftest import parse_snippet, rule_ids
from iacscanner.rules import get_rule


def _check(rule_id: str, sf) -> list:
    from iacscanner.graph import ScanContext

    rule = get_rule(rule_id)
    if rule.check_ctx is not None:
        return rule.check_ctx(sf, ScanContext.build((sf,)))
    return rule.check(sf) if rule.check is not None else []


# --- TL005: security group ingress ---------------------------------------

SG_TMPL = """
resource "aws_security_group" "sg" {{
  name = "example-sg"
  ingress {{
    from_port   = {frm}
    to_port     = {to}
    protocol    = "{proto}"
    cidr_blocks = ["{cidr}"]
  }}
}}
"""


def test_ig005_fires_on_world_open_ssh_range(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", SG_TMPL.format(frm=20, to=25, proto="tcp", cidr="0.0.0.0/0"))
    assert len(_check("TL005", sf)) == 1


def test_ig005_ignores_world_open_http(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", SG_TMPL.format(frm=80, to=80, proto="tcp", cidr="0.0.0.0/0"))
    assert _check("TL005", sf) == []


def test_ig005_ignores_private_cidr(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", SG_TMPL.format(frm=22, to=22, proto="tcp", cidr="10.0.0.0/16"))
    assert _check("TL005", sf) == []


def test_ig005_fires_on_all_protocols(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", SG_TMPL.format(frm=0, to=0, proto="-1", cidr="0.0.0.0/0"))
    assert len(_check("TL005", sf)) == 1


def test_ig005_fires_on_ipv6_world_open(tmp_path: Path) -> None:
    text = """
resource "aws_security_group" "sg" {
  ingress {
    from_port        = 3389
    to_port          = 3389
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
"""
    sf = parse_snippet(tmp_path, "a.tf", text)
    assert len(_check("TL005", sf)) == 1


def test_ig005_fires_on_standalone_sg_rule(tmp_path: Path) -> None:
    text = """
resource "aws_security_group_rule" "ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-00000000000000000"
}
"""
    sf = parse_snippet(tmp_path, "a.tf", text)
    assert len(_check("TL005", sf)) == 1


# --- TL003 / TL004: IAM wildcards -----------------------------------------

def _policy_tf(statement: str) -> str:
    return (
        'resource "aws_iam_policy" "p" {\n'
        "  policy = <<EOT\n"
        '{"Version": "2012-10-17", "Statement": [' + statement + "]}\n"
        "EOT\n"
        "}\n"
    )


def test_ig003_fires_on_wildcard_in_action_list(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", _policy_tf('{"Effect": "Allow", "Action": ["s3:GetObject", "*"], "Resource": "*"}'))
    assert len(_check("TL003", sf)) == 1


def test_ig003_ignores_deny_statements(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", _policy_tf('{"Effect": "Deny", "Action": "*", "Resource": "*"}'))
    assert _check("TL003", sf) == []


def test_ig004_fires_on_wildcard_aws_principal(tmp_path: Path) -> None:
    stmt = '{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:GetObject", "Resource": "*"}'
    sf = parse_snippet(tmp_path, "a.tf", _policy_tf(stmt))
    assert len(_check("TL004", sf)) == 1


def test_ig004_ignores_scoped_principal(tmp_path: Path) -> None:
    stmt = '{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "s3:GetObject", "Resource": "*"}'
    sf = parse_snippet(tmp_path, "a.tf", _policy_tf(stmt))
    assert _check("TL004", sf) == []


# --- TL010: hardcoded Terraform secrets ------------------------------------

def test_ig010_ignores_variable_without_default(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'variable "db_password" {\n  type      = string\n  sensitive = true\n}\n')
    assert _check("TL010", sf) == []


def test_ig010_fires_on_secret_default(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'variable "api_token" {\n  default = "abc123def456"\n}\n')
    assert len(_check("TL010", sf)) == 1


def test_ig010_ignores_variable_references(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n')
    assert _check("TL010", sf) == []


def test_ig010_siblings_in_one_resource_have_distinct_fingerprints(tmp_path: Path) -> None:
    """Two secret attributes on ONE resource must not share a baseline identity.

    Both findings anchor to the same resource address, so with an empty sub_key
    they are the same fingerprint: a baseline that accepted `access_key` also
    suppresses a `secret_key` added later, and the gate stays green while the
    tree gets worse - the collision sub_key exists to prevent.
    """
    from iacscanner.baseline import fingerprint

    text = (
        'resource "datadog_integration_aws" "main" {\n'
        '  access_key = "AKIAIOSFODNN7EXAMPLE"\n'
        '  secret_key = "not-a-real-secret-value"\n'
        "}\n"
    )
    findings = _check("TL010", parse_snippet(tmp_path, "a.tf", text))
    assert len(findings) == 2
    assert len({fingerprint(f) for f in findings}) == 2


# --- TL019: publicly accessible RDS ----------------------------------------

def test_ig019_fires_on_publicly_accessible_true(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n}\n')
    assert len(_check("TL019", sf)) == 1


def test_ig019_ignores_publicly_accessible_false(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  publicly_accessible = false\n}\n')
    assert _check("TL019", sf) == []


def test_ig019_ignores_default_private_instance(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  engine = "postgres"\n}\n')
    assert _check("TL019", sf) == []


def test_ig019_fires_on_public_rds_cluster_instance(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_rds_cluster_instance" "d" {\n  publicly_accessible = true\n}\n')
    assert len(_check("TL019", sf)) == 1


# --- TL012: runAsNonRoot ----------------------------------------------------

POD_TMPL = """
apiVersion: v1
kind: Pod
metadata:
  name: p
spec:
  {pod_ctx}
  containers:
    - name: c
      image: app:1.0.0
      {container_ctx}
      resources:
        limits:
          cpu: 100m
          memory: 64Mi
"""


def test_ig012_pod_level_run_as_non_root_passes(tmp_path: Path) -> None:
    text = POD_TMPL.format(pod_ctx="securityContext:\n    runAsNonRoot: true", container_ctx="")
    sf = parse_snippet(tmp_path, "p.yaml", text)
    assert _check("TL012", sf) == []


def test_ig012_container_false_overrides_pod_true(tmp_path: Path) -> None:
    text = POD_TMPL.format(
        pod_ctx="securityContext:\n    runAsNonRoot: true",
        container_ctx="securityContext:\n        runAsNonRoot: false",
    )
    sf = parse_snippet(tmp_path, "p.yaml", text)
    assert len(_check("TL012", sf)) == 1


# --- TL015: image tags -------------------------------------------------------

def _pod_with_image(image: str) -> str:
    return POD_TMPL.format(pod_ctx="securityContext:\n    runAsNonRoot: true", container_ctx="").replace(
        "app:1.0.0", image
    )


def test_ig015_digest_pinned_image_passes(tmp_path: Path) -> None:
    digest = "sha256:" + "0" * 64
    sf = parse_snippet(tmp_path, "p.yaml", _pod_with_image(f"nginx@{digest}"))
    assert _check("TL015", sf) == []


def test_ig015_registry_port_with_tag_passes(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "p.yaml", _pod_with_image("registry.example.com:5000/app:1.2.3"))
    assert _check("TL015", sf) == []


def test_ig015_untagged_image_fires(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "p.yaml", _pod_with_image("nginx"))
    assert len(_check("TL015", sf)) == 1


def test_ig015_latest_tag_fires(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "p.yaml", _pod_with_image("nginx:latest"))
    assert len(_check("TL015", sf)) == 1


# --- TL016: pull_request_target --------------------------------------------

WF_TMPL = """
name: ci
on: {trigger}
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        {with_ref}
"""


def test_ig016_needs_both_trigger_and_head_ref(tmp_path: Path) -> None:
    safe_trigger = WF_TMPL.format(trigger="pull_request", with_ref="with:\n          ref: ${{ github.event.pull_request.head.sha }}")
    sf = parse_snippet(tmp_path, "w.yml", safe_trigger)
    assert _check("TL016", sf) == []

    safe_checkout = WF_TMPL.format(trigger="pull_request_target", with_ref="")
    sf = parse_snippet(tmp_path, "w.yml", safe_checkout)
    assert _check("TL016", sf) == []

    vulnerable = WF_TMPL.format(trigger="pull_request_target", with_ref="with:\n          ref: ${{ github.event.pull_request.head.sha }}")
    sf = parse_snippet(tmp_path, "w.yml", vulnerable)
    assert len(_check("TL016", sf)) == 1


# --- TL018: generic hardcoded credentials -----------------------------------

def test_ig018_ignores_reference_values(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  password = var.db_password\n}\n')
    assert _check("TL018", sf) == []


def test_ig018_fires_on_literal_password(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", 'resource "aws_db_instance" "d" {\n  password = "hunter2-example"\n}\n')
    findings = _check("TL018", sf)
    assert len(findings) == 1
    assert "hunter2-example" not in findings[0].message  # secrets are masked


def test_ig018_fires_on_akia_and_ghp(tmp_path: Path) -> None:
    text = '{"key": "AKIAIOSFODNN7EXAMPLE", "tok": "ghp_' + "0" * 36 + '"}\n'
    sf = parse_snippet(tmp_path, "c.json", text)
    assert len(_check("TL018", sf)) == 2


def test_ig018_siblings_on_one_line_have_distinct_fingerprints(tmp_path: Path) -> None:
    """Several secrets on ONE line must not share a baseline identity.

    TL018 anchors to `line N`, which a minified JSON or a single-line env
    assignment makes a very coarse location: without a sub_key every secret on
    that line is one fingerprint, so a baseline written when the line held one
    key silently suppresses the next one added beside it.
    """
    from iacscanner.baseline import fingerprint

    text = '{"a": "AKIAIOSFODNN7EXAMPLE", "b": "AKIAIOSFODNN7EXAMPLE", "password": "hunter2-example"}\n'
    findings = _check("TL018", parse_snippet(tmp_path, "c.json", text))
    assert len(findings) == 3
    assert len({fingerprint(f) for f in findings}) == 3


def test_ig018_reports_line_numbers(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "c.json", '{\n  "key": "AKIAIOSFODNN7EXAMPLE"\n}\n')
    findings = _check("TL018", sf)
    assert findings[0].location == "line 2"


# --- TL002: public access block heuristics ----------------------------------

def test_ig002_fires_when_pab_flag_false(tmp_path: Path) -> None:
    text = """
resource "aws_s3_bucket" "b" {
  bucket = "example-data-bucket"
}

resource "aws_s3_bucket_public_access_block" "b" {
  bucket              = "example-data-bucket"
  block_public_acls   = true
  block_public_policy = false
}
"""
    sf = parse_snippet(tmp_path, "a.tf", text)
    assert len(_check("TL002", sf)) == 1
    assert rule_ids(_check("TL002", sf)) == {"TL002"}
