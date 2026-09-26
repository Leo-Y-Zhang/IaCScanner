"""Realistic IaC spellings that must not slip past the rules.

Each test here pins a false negative (or a spurious parse failure) found by
feeding the scanner ordinary real-world input: modern Terraform idioms
(``dynamic`` blocks, ``jsonencode``, ``aws_iam_policy_document``, the split
AWS provider v4/v5 resources), ``kubectl get -o yaml``/``-o json`` output,
common GitHub Actions spellings, CloudFormation short-form tags, a UTF-8
byte-order mark, and Dockerfile port ranges.
"""
from __future__ import annotations

import json
from pathlib import Path

from conftest import parse_snippet, rule_ids
from iacscanner.cli import main
from iacscanner.graph import ScanContext
from iacscanner.rules import get_rule
from iacscanner.scanner import scan


def _check(rule_id: str, sf) -> list:
    rule = get_rule(rule_id)
    if rule.check_ctx is not None:
        return rule.check_ctx(sf, ScanContext.build((sf,)))
    return rule.check(sf) if rule.check is not None else []


# --- Terraform ------------------------------------------------------------


def test_tl005_fires_on_dynamic_ingress_with_literal_content(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", """
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = [1]
    content {
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
""")
    findings = _check("TL005", sf)
    assert [f.location for f in findings] == ["aws_security_group.sg"]
    assert "SSH" in findings[0].message


def test_tl005_dynamic_ingress_with_unresolved_content_stays_silent(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", """
resource "aws_security_group" "sg" {
  dynamic "ingress" {
    for_each = var.rules
    content {
      from_port   = ingress.value.port
      to_port     = ingress.value.port
      protocol    = "tcp"
      cidr_blocks = ingress.value.cidrs
    }
  }
  dynamic "ingress" {
    for_each = []
    content {
      from_port   = 3389
      to_port     = 3389
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
  dynamic "egress" {
    for_each = [1]
    content {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}
""")
    assert _check("TL005", sf) == []


def test_tl005_fires_on_vpc_security_group_ingress_rule(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", """
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  security_group_id = aws_security_group.sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "all6" {
  security_group_id = aws_security_group.sg.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1"
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  security_group_id = aws_security_group.sg.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "office_ssh" {
  security_group_id = aws_security_group.sg.id
  cidr_ipv4         = "10.0.0.0/8"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}
""")
    findings = _check("TL005", sf)
    assert sorted((f.location, f.message) for f in findings) == [
        ("aws_vpc_security_group_ingress_rule.all6", "ingress open to the world on all ports"),
        ("aws_vpc_security_group_ingress_rule.ssh", "ingress open to the world on SSH"),
    ]


def test_tl001_fires_on_separate_s3_bucket_acl_resource(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", """
resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.b.id
  acl    = "public-read-write"
}

resource "aws_s3_bucket_acl" "private" {
  bucket = aws_s3_bucket.b.id
  acl    = "private"
}
""")
    findings = _check("TL001", sf)
    assert [(f.location, f.message) for f in findings] == [
        ("aws_s3_bucket_acl.public", "bucket ACL is 'public-read-write'")
    ]


JSONENCODE_POLICY = """
resource "aws_iam_policy" "admin" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = aws_s3_bucket.b.arn
      },
    ]
  })
}

resource "aws_s3_bucket_policy" "open" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = ["s3:GetObject"]
      Resource  = "${aws_s3_bucket.b.arn}/*"
    }]
  })
}

resource "aws_iam_policy" "scoped" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow", Action = ["s3:GetObject"], Resource = "*" }]
  })
}
"""


def test_tl003_tl004_read_jsonencode_policies(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", JSONENCODE_POLICY)
    assert [f.location for f in _check("TL003", sf)] == ["aws_iam_policy.admin"]
    assert [f.location for f in _check("TL004", sf)] == ["aws_s3_bucket_policy.open"]


def test_jsonencode_of_a_reference_stays_silent(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", """
resource "aws_iam_policy" "p" {
  policy = jsonencode(local.policy)
}
""")
    assert _check("TL003", sf) == [] and _check("TL004", sf) == []


POLICY_DOCUMENT = """
data "aws_iam_policy_document" "admin" {
  statement {
    actions   = ["*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "public" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "anonymous" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::b/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "denied" {
  statement {
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

data "aws_iam_policy_document" "scoped" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}
"""


def test_tl003_tl004_read_aws_iam_policy_document_data_sources(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "a.tf", POLICY_DOCUMENT)
    assert [f.location for f in _check("TL003", sf)] == ["data.aws_iam_policy_document.admin"]
    assert sorted(f.location for f in _check("TL004", sf)) == [
        "data.aws_iam_policy_document.anonymous",
        "data.aws_iam_policy_document.public",
    ]


def test_policy_document_findings_resolve_to_their_block_line(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text(POLICY_DOCUMENT, encoding="utf-8")
    result = scan(tmp_path)
    lines = {(f.rule_id, f.location): f.line for f in result.findings}
    assert lines[("TL003", "data.aws_iam_policy_document.admin")] == 2
    assert lines[("TL004", "data.aws_iam_policy_document.public")] == 9


# --- Kubernetes -----------------------------------------------------------


KUBECTL_LIST_YAML = """
apiVersion: v1
kind: List
items:
- apiVersion: v1
  kind: Service
  metadata: {name: svc}
  spec: {ports: [{port: 80}]}
- apiVersion: apps/v1
  kind: Deployment
  metadata: {name: app}
  spec:
    template:
      spec:
        hostPID: true
        containers:
        - name: web
          image: nginx:1.27.1
          securityContext: {privileged: true}
"""


def test_kubernetes_list_items_are_scanned(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "export.yaml", KUBECTL_LIST_YAML)
    assert [f.location for f in _check("TL011", sf)] == ["Deployment/app container web"]
    assert [f.location for f in _check("TL027", sf)] == ["Deployment/app"]


def test_kubernetes_list_findings_resolve_to_lines(tmp_path: Path) -> None:
    (tmp_path / "export.yaml").write_text(KUBECTL_LIST_YAML, encoding="utf-8")
    lines = {(f.rule_id, f.location): f.line for f in scan(tmp_path).findings}
    assert lines[("TL027", "Deployment/app")] == 9
    assert lines[("TL011", "Deployment/app container web")] == 17


def test_kubernetes_json_manifest_is_scanned(tmp_path: Path) -> None:
    manifest = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p"},
        "spec": {"containers": [{"name": "c", "image": "nginx:1", "securityContext": {"privileged": True}}]},
    }
    sf = parse_snippet(tmp_path, "pod.json", json.dumps(manifest, indent=2))
    assert sf.error is None
    assert [f.location for f in _check("TL011", sf)] == ["Pod/p container c"]


def test_plain_json_is_not_reclassified(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "package.json", '{"name": "x", "kind": "app"}')
    assert sf.kind == "json"


# --- GitHub Actions -------------------------------------------------------


def test_tl016_fires_on_head_ref_and_pull_merge_refs(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "wf.yml", """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.head_ref }}
      - uses: actions/checkout@v4
        with:
          ref: refs/pull/${{ github.event.pull_request.number }}/merge
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
""")
    assert [f.location for f in _check("TL016", sf)] == ["jobs.build.steps[0]", "jobs.build.steps[1]"]


def test_tl028_fires_on_job_level_reusable_workflow(tmp_path: Path) -> None:
    (tmp_path / "wf.yml").write_text("""on: push
jobs:
  deploy:
    uses: some-org/workflows/.github/workflows/deploy.yml@main
  pinned:
    uses: some-org/workflows/.github/workflows/deploy.yml@v1.2.3
  local:
    uses: ./.github/workflows/local.yml
""", encoding="utf-8")
    findings = [f for f in scan(tmp_path).findings if f.rule_id == "TL028"]
    # The job anchor resolves to the first line of the job body.
    assert [(f.location, f.line) for f in findings] == [("jobs.deploy", 4)]


# --- YAML parsing ---------------------------------------------------------


CFN_TEMPLATE = """AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  Env: {Type: String}
Resources:
  Bucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "${AWS::StackName}-data"
      Tags:
        - Key: env
          Value: !Ref Env
  User:
    Type: AWS::IAM::User
    Properties:
      LoginProfile:
        Password: hunter2hunter2
  Db:
    Type: AWS::RDS::DBInstance
    Properties:
      Arn: !GetAtt Bucket.Arn
      Zone: !Select [0, !GetAZs ""]
      Name: !Join ["-", [!Ref Env, db]]
      Cond: !If [IsProd, !Ref "AWS::NoValue", !Base64 abc]
Outputs:
  Out:
    Value: !ImportValue
      Fn::Sub: "${Env}-x"
"""


def test_cloudformation_short_form_tags_parse(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "stack.yaml", CFN_TEMPLATE)
    assert sf.error is None
    props = sf.data[0]["Resources"]["Bucket"]["Properties"]
    assert props["BucketName"] == {"Fn::Sub": "${AWS::StackName}-data"}
    assert props["Tags"][0]["Value"] == {"Ref": "Env"}
    db = sf.data[0]["Resources"]["Db"]["Properties"]
    assert db["Arn"] == {"Fn::GetAtt": ["Bucket", "Arn"]}
    assert db["Zone"] == {"Fn::Select": [0, {"Fn::GetAZs": ""}]}
    assert sf.data[0]["Outputs"]["Out"]["Value"] == {"Fn::ImportValue": {"Fn::Sub": "${Env}-x"}}


def test_cloudformation_template_is_scanned_not_reported_unparseable(tmp_path: Path, capsys) -> None:
    (tmp_path / "stack.yaml").write_text(CFN_TEMPLATE, encoding="utf-8")
    result = scan(tmp_path)
    assert result.parse_error_count == 0
    assert rule_ids(result.findings) == {"TL018"}  # the literal password is still caught
    assert main(["scan", str(tmp_path), "--fail-on", "critical"]) == 1


def test_unknown_yaml_tag_is_still_a_reported_parse_error(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "x.yaml", "a: !NotCloudFormation 1\n")
    assert sf.error is not None and "NotCloudFormation" in sf.error


def test_python_object_tags_are_still_refused(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "x.yaml", "a: !!python/object/apply:os.system ['true']\n")
    assert sf.error is not None


# --- byte-order mark ------------------------------------------------------


BOM = "﻿"


def test_dockerfile_with_bom_is_analyzed(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "Dockerfile", BOM + "FROM ubuntu:latest\nUSER root\n")
    assert rule_ids(_check("TL029", sf) + _check("TL031", sf)) == {"TL029", "TL031"}


def test_terraform_and_json_with_bom_parse(tmp_path: Path) -> None:
    tf = parse_snippet(tmp_path, "a.tf", BOM + 'resource "aws_ebs_volume" "v" {\n  size = 1\n}\n')
    assert tf.error is None
    assert [f.location for f in _check("TL006", tf)] == ["aws_ebs_volume.v"]
    js = parse_snippet(tmp_path, "a.json", BOM + '{"password": "hunter2hunter2"}')
    assert js.error is None


def test_bom_file_line_numbers_are_unchanged(tmp_path: Path) -> None:
    (tmp_path / "a.tf").write_text(BOM + '\nresource "aws_ebs_volume" "v" {\n  size = 1\n}\n', encoding="utf-8")
    [finding] = scan(tmp_path).findings
    assert finding.line == 2


# --- Dockerfile -----------------------------------------------------------


def test_tl032_fires_on_expose_range_covering_22(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "Dockerfile", "FROM alpine:3.20\nEXPOSE 20-25/tcp 8000-8080\n")
    findings = _check("TL032", sf)
    assert [f.message for f in findings] == ["final image exposes SSH port 22 (20-25/tcp)"]


def test_tl032_ignores_ranges_without_22(tmp_path: Path) -> None:
    sf = parse_snippet(tmp_path, "Dockerfile", "FROM alpine:3.20\nEXPOSE 23-25 1-21 22/udp 10-x\n")
    assert _check("TL032", sf) == []


# --- CLI ------------------------------------------------------------------


def test_unwritable_out_exits_two_not_one(tmp_path: Path, capsys) -> None:
    (tmp_path / "a.tf").write_text('resource "aws_ebs_volume" "v" {}\n', encoding="utf-8")
    code = main(["scan", str(tmp_path / "a.tf"), "--out", str(tmp_path / "missing" / "r.txt")])
    assert code == 2
    assert "cannot write report" in capsys.readouterr().err
