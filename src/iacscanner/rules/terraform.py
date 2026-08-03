"""Terraform (AWS-style) rules: TL001-TL010, TL019."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from iacscanner.models import KIND_TERRAFORM, Finding, Rule, ScanFile, Severity
from iacscanner.rules import _tf

if TYPE_CHECKING:
    from iacscanner.graph import ResourceGraph, ScanContext

_PUBLIC_ACLS = {"public-read", "public-read-write"}
_PAB_FLAGS = ("block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets")
_ADMIN_PORTS = {22: "SSH", 3389: "RDP"}
_SECRET_NAME_RE = re.compile(r"password|secret|token|api_key|access_key|private_key", re.I)
_WORLD_CIDRS = {"0.0.0.0/0", "::/0"}


def _check_tl001(sf: ScanFile) -> list[Finding]:
    return [
        TL001.finding(sf, f"aws_s3_bucket.{name}", f"bucket ACL is '{body['acl']}'")
        for _, name, body in _tf.resources(sf, "aws_s3_bucket")
        if body.get("acl") in _PUBLIC_ACLS
    ]


# -- cross-file S3 companion binding (see graph.py) ---------------------------

def _bucket_literal(graph: ResourceGraph, body: dict[str, Any]) -> str | None:
    """The resolved literal bucket name of an aws_s3_bucket, or None if unresolved."""
    resolved = graph.resolve(body.get("bucket"))
    return resolved if isinstance(resolved, str) and "${" not in resolved else None


def _covers_bucket(
    graph: ResourceGraph, companion: dict[str, Any], name: str, literal: str | None,
    attr: str = "bucket",
) -> bool:
    """True if a companion resource's *attr* binds it to the bucket ``aws_s3_bucket.name``
    (by resource address or resolved literal name). An UNRESOLVED reference conservatively
    counts as coverage, so an unknown binding never manufactures a false positive."""
    ref_val = companion.get(attr)
    if ref_val is None:
        return False
    address = graph.resolve_reference(ref_val)
    if address is not None:
        return address.type == "aws_s3_bucket" and address.name == name
    resolved = graph.resolve(ref_val)
    if isinstance(resolved, str) and "${" in resolved:
        return True  # unresolved reference: assume coverage (false-positive firewall)
    return literal is not None and resolved == literal


def _check_tl002(sf: ScanFile, ctx: ScanContext) -> list[Finding]:
    findings = []
    pabs = [body for _, _, _, body in ctx.graph.resources("aws_s3_bucket_public_access_block")]
    for _, name, body in _tf.resources(sf, "aws_s3_bucket"):
        literal = _bucket_literal(ctx.graph, body)
        covering = [pab for pab in pabs if _covers_bucket(ctx.graph, pab, name, literal)]
        location = f"aws_s3_bucket.{name}"
        if not covering:
            findings.append(TL002.finding(sf, location, "no public access block protects this bucket"))
        elif not any(all(pab.get(flag) is True for flag in _PAB_FLAGS) for pab in covering):
            weak = [flag for flag in _PAB_FLAGS if covering[0].get(flag) is not True]
            findings.append(
                TL002.finding(sf, location, "public access block leaves " + ", ".join(weak) + " unset or false")
            )
    return findings


def _check_tl003(sf: ScanFile) -> list[Finding]:
    findings = []
    for location, doc in _tf.policy_documents(sf):
        for stmt in _tf.allow_statements(doc):
            actions = _tf.as_list(stmt.get("Action"))
            if any(action in ("*", "*:*") for action in actions):
                findings.append(TL003.finding(sf, location, "policy statement allows Action '*'"))
    return findings


def _is_wildcard_principal(principal: object) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        return any("*" in _tf.as_list(value) for value in principal.values())
    return False


def _check_tl004(sf: ScanFile) -> list[Finding]:
    findings = []
    for location, doc in _tf.policy_documents(sf):
        for stmt in _tf.allow_statements(doc):
            if _is_wildcard_principal(stmt.get("Principal")):
                findings.append(TL004.finding(sf, location, "policy statement allows Principal '*'"))
    return findings


def _open_to_world(rule_block: dict[str, Any]) -> bool:
    cidrs = _tf.as_list(rule_block.get("cidr_blocks")) + _tf.as_list(rule_block.get("ipv6_cidr_blocks"))
    return any(cidr in _WORLD_CIDRS for cidr in cidrs)


def _exposed_service(rule_block: dict[str, Any]) -> str | None:
    """Name the sensitive exposure of an ingress rule, if any."""
    protocol = str(rule_block.get("protocol", ""))
    try:
        from_port = int(rule_block.get("from_port", 0))
        to_port = int(rule_block.get("to_port", 0))
    except (TypeError, ValueError):
        return None
    if protocol == "-1" or (from_port == 0 and to_port == 0):
        return "all ports"
    exposed = [label for port, label in _ADMIN_PORTS.items() if from_port <= port <= to_port]
    return " and ".join(exposed) if exposed else None


def _check_tl005(sf: ScanFile) -> list[Finding]:
    findings = []
    for _, name, body in _tf.resources(sf, "aws_security_group"):
        for rule_block in _tf.blocks(body, "ingress"):
            service = _exposed_service(rule_block)
            if service and _open_to_world(rule_block):
                findings.append(
                    TL005.finding(sf, f"aws_security_group.{name}", f"ingress open to the world on {service}", sub_key=service)
                )
    for _, name, body in _tf.resources(sf, "aws_security_group_rule"):
        service = _exposed_service(body)
        if body.get("type") == "ingress" and service and _open_to_world(body):
            findings.append(
                TL005.finding(sf, f"aws_security_group_rule.{name}", f"ingress open to the world on {service}", sub_key=service)
            )
    return findings


def _check_tl006(sf: ScanFile) -> list[Finding]:
    findings = []
    for _, name, body in _tf.resources(sf, "aws_ebs_volume"):
        if body.get("encrypted") is not True:
            findings.append(TL006.finding(sf, f"aws_ebs_volume.{name}", "EBS volume is not encrypted"))
    for _, name, body in _tf.resources(sf, "aws_db_instance"):
        if body.get("storage_encrypted") is not True:
            findings.append(TL006.finding(sf, f"aws_db_instance.{name}", "RDS storage is not encrypted"))
    return findings


def _check_tl007(sf: ScanFile, ctx: ScanContext) -> list[Finding]:
    findings = []
    sse = [body for _, _, _, body in ctx.graph.resources("aws_s3_bucket_server_side_encryption_configuration")]
    for _, name, body in _tf.resources(sf, "aws_s3_bucket"):
        if _tf.blocks(body, "server_side_encryption_configuration"):
            continue  # inline SSE block
        literal = _bucket_literal(ctx.graph, body)
        if any(_covers_bucket(ctx.graph, s, name, literal) for s in sse):
            continue  # a server-side encryption configuration elsewhere protects this bucket
        findings.append(
            TL007.finding(sf, f"aws_s3_bucket.{name}", "no server-side encryption configuration protects this bucket")
        )
    return findings


def _versioning_enabled(graph: ResourceGraph, body: dict[str, Any], name: str, literal: str | None) -> bool:
    if any(cfg.get("enabled") is True for cfg in _tf.blocks(body, "versioning")):
        return True  # inline versioning
    return any(
        _covers_bucket(graph, vbody, name, literal)
        and any(str(cfg.get("status", "")).lower() == "enabled"
                for cfg in _tf.blocks(vbody, "versioning_configuration"))
        for _, _, _, vbody in graph.resources("aws_s3_bucket_versioning")
    )


def _logging_enabled(graph: ResourceGraph, body: dict[str, Any], name: str, literal: str | None) -> bool:
    if _tf.blocks(body, "logging"):
        return True  # inline logging
    return any(
        _covers_bucket(graph, lbody, name, literal)
        for _, _, _, lbody in graph.resources("aws_s3_bucket_logging")
    )


def _check_tl008(sf: ScanFile, ctx: ScanContext) -> list[Finding]:
    findings = []
    for _, name, body in _tf.resources(sf, "aws_s3_bucket"):
        location = f"aws_s3_bucket.{name}"
        literal = _bucket_literal(ctx.graph, body)
        if not _versioning_enabled(ctx.graph, body, name, literal):
            findings.append(TL008.finding(sf, location, "bucket versioning is not enabled", sub_key="versioning"))
        if not _logging_enabled(ctx.graph, body, name, literal):
            findings.append(TL008.finding(sf, location, "bucket access logging is not enabled", sub_key="logging"))
    return findings


def _check_tl009(sf: ScanFile) -> list[Finding]:
    return [
        TL009.finding(sf, f"aws_cloudtrail.{name}", "enable_logging is set to false")
        for _, name, body in _tf.resources(sf, "aws_cloudtrail")
        if body.get("enable_logging") is False
    ]


def _literal_secret(value: object) -> bool:
    return isinstance(value, str) and bool(value) and not _tf.is_reference(value)


def _check_tl010(sf: ScanFile) -> list[Finding]:
    findings = []
    for name, body in _tf.variables(sf):
        if _SECRET_NAME_RE.search(name) and _literal_secret(body.get("default")):
            findings.append(
                TL010.finding(sf, f"variable.{name}", "secret-looking variable has a hardcoded default")
            )
    for rtype, name, body in _tf.resources(sf):
        for attr, value in body.items():
            if _SECRET_NAME_RE.search(attr) and _literal_secret(value):
                findings.append(
                    TL010.finding(sf, f"{rtype}.{name}", f"attribute '{attr}' holds a hardcoded literal")
                )
    return findings


def _check_tl019(sf: ScanFile) -> list[Finding]:
    findings = []
    for rtype in ("aws_db_instance", "aws_rds_cluster_instance"):
        for _, name, body in _tf.resources(sf, rtype):
            if body.get("publicly_accessible") is True:
                findings.append(
                    TL019.finding(sf, f"{rtype}.{name}", "database instance is publicly accessible")
                )
    return findings


# -- curated expansion (TL020-TL025): fire only on EXPLICIT misconfiguration ---

def _check_tl020(sf: ScanFile) -> list[Finding]:
    return [
        TL020.finding(sf, f"aws_kms_key.{name}", "automatic key rotation is disabled")
        for _, name, body in _tf.resources(sf, "aws_kms_key")
        if body.get("enable_key_rotation") is False
    ]


def _check_tl021(sf: ScanFile) -> list[Finding]:
    findings = []
    for _, name, body in _tf.resources(sf, "aws_ecr_repository"):
        for cfg in _tf.blocks(body, "image_scanning_configuration"):
            if cfg.get("scan_on_push") is False:
                findings.append(
                    TL021.finding(sf, f"aws_ecr_repository.{name}", "image scan-on-push is disabled")
                )
    return findings


def _check_tl022(sf: ScanFile) -> list[Finding]:
    return [
        TL022.finding(sf, f"aws_efs_file_system.{name}", "EFS file system is not encrypted")
        for _, name, body in _tf.resources(sf, "aws_efs_file_system")
        if body.get("encrypted") is False
    ]


def _check_tl023(sf: ScanFile) -> list[Finding]:
    findings = []
    for rtype in ("aws_instance", "aws_launch_template"):
        for _, name, body in _tf.resources(sf, rtype):
            for opts in _tf.blocks(body, "metadata_options"):
                if str(opts.get("http_tokens", "")).lower() == "optional":
                    findings.append(
                        TL023.finding(sf, f"{rtype}.{name}", "IMDSv2 is not enforced (http_tokens is 'optional')")
                    )
    return findings


def _check_tl024(sf: ScanFile) -> list[Finding]:
    return [
        TL024.finding(sf, f"aws_dynamodb_table.{name}", "point-in-time recovery is disabled")
        for _, name, body in _tf.resources(sf, "aws_dynamodb_table")
        if any(b.get("enabled") is False for b in _tf.blocks(body, "point_in_time_recovery"))
    ]


def _check_tl025(sf: ScanFile) -> list[Finding]:
    return [
        TL025.finding(sf, f"aws_db_instance.{name}", "automated backups are disabled (backup_retention_period = 0)")
        for _, name, body in _tf.resources(sf, "aws_db_instance")
        if body.get("backup_retention_period") == 0
    ]


_TF = (KIND_TERRAFORM,)

TL001 = Rule(
    id="TL001",
    title="S3 bucket has a public ACL",
    severity=Severity.CRITICAL,
    description="An aws_s3_bucket sets acl to public-read or public-read-write.",
    rationale="Public bucket ACLs expose every object to anonymous readers and are a leading cause of data leaks.",
    remediation='acl = "private"',
    kinds=_TF,
    check=_check_tl001,
)

TL002 = Rule(
    id="TL002",
    title="S3 public access block missing or weakened",
    severity=Severity.HIGH,
    description="A bucket has no aws_s3_bucket_public_access_block (resolved across the whole scan), or the block leaves flags disabled.",
    rationale="Without the account/bucket public access block, a single ACL or policy mistake can make data public.",
    remediation=(
        'resource "aws_s3_bucket_public_access_block" "this" {\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}"
    ),
    kinds=_TF,
    check_ctx=_check_tl002,
)

TL003 = Rule(
    id="TL003",
    title="IAM policy allows wildcard actions",
    severity=Severity.HIGH,
    description="An IAM policy document contains an Allow statement with Action '*' or '*:*'.",
    rationale="Wildcard actions grant far more than intended and defeat least-privilege review.",
    remediation='"Action": ["s3:GetObject"]  // list only the actions actually needed',
    kinds=_TF,
    check=_check_tl003,
)

TL004 = Rule(
    id="TL004",
    title="IAM policy allows wildcard principal",
    severity=Severity.CRITICAL,
    description="An IAM/resource policy contains an Allow statement whose Principal is '*'.",
    rationale="A wildcard principal lets any AWS account or anonymous user exercise the granted actions.",
    remediation='"Principal": {"AWS": "arn:aws:iam::123456789012:role/app-role"}',
    kinds=_TF,
    check=_check_tl004,
)

TL005 = Rule(
    id="TL005",
    title="Security group open to the world on an admin port",
    severity=Severity.CRITICAL,
    description="A security group ingress rule allows 0.0.0.0/0 or ::/0 on SSH (22), RDP (3389), or all ports.",
    rationale="World-open admin ports are scanned and brute-forced within minutes of exposure.",
    remediation='cidr_blocks = ["10.0.0.0/16"]  # restrict to a trusted range or use SSM/VPN',
    kinds=_TF,
    check=_check_tl005,
)

TL006 = Rule(
    id="TL006",
    title="EBS volume or RDS storage not encrypted",
    severity=Severity.HIGH,
    description="An aws_ebs_volume lacks encrypted = true, or an aws_db_instance lacks storage_encrypted = true.",
    rationale="Unencrypted storage exposes data if snapshots, volumes, or backups are copied or mis-shared.",
    remediation="encrypted = true            # aws_ebs_volume\nstorage_encrypted = true    # aws_db_instance",
    kinds=_TF,
    check=_check_tl006,
)

TL007 = Rule(
    id="TL007",
    title="S3 bucket has no server-side encryption configuration",
    severity=Severity.MEDIUM,
    description="No server_side_encryption_configuration block or resource protects the bucket (resolved across the whole scan).",
    rationale="Explicit SSE configuration guarantees objects are encrypted at rest with the intended key.",
    remediation=(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "this" {\n'
        "  rule {\n"
        "    apply_server_side_encryption_by_default {\n"
        '      sse_algorithm = "aws:kms"\n'
        "    }\n"
        "  }\n"
        "}"
    ),
    kinds=_TF,
    check_ctx=_check_tl007,
)

TL008 = Rule(
    id="TL008",
    title="S3 bucket versioning or access logging not enabled",
    severity=Severity.LOW,
    description="The bucket has neither an enabled versioning configuration nor an access logging configuration (resolved across the whole scan).",
    rationale="Versioning protects against accidental deletion; access logs support incident investigation.",
    remediation=(
        'resource "aws_s3_bucket_versioning" "this" {\n'
        '  versioning_configuration { status = "Enabled" }\n'
        "}\n"
        'resource "aws_s3_bucket_logging" "this" {\n'
        '  target_bucket = "example-log-bucket"\n'
        '  target_prefix = "s3-access/"\n'
        "}"
    ),
    kinds=_TF,
    check_ctx=_check_tl008,
)

TL009 = Rule(
    id="TL009",
    title="CloudTrail logging disabled",
    severity=Severity.HIGH,
    description="An aws_cloudtrail resource sets enable_logging = false.",
    rationale="Disabling CloudTrail removes the audit trail attackers most want gone.",
    remediation="enable_logging = true",
    kinds=_TF,
    check=_check_tl009,
)

TL010 = Rule(
    id="TL010",
    title="Hardcoded secret in Terraform variable or resource",
    severity=Severity.HIGH,
    description="A secret-looking variable has a literal default, or a secret-looking resource attribute holds a literal string.",
    rationale="Literal secrets in .tf files end up in version control and state files.",
    remediation=(
        'variable "db_password" {\n'
        "  type      = string\n"
        "  sensitive = true      # supply the value at deploy time\n"
        "}"
    ),
    kinds=_TF,
    check=_check_tl010,
)

TL019 = Rule(
    id="TL019",
    title="RDS instance is publicly accessible",
    severity=Severity.HIGH,
    description="An aws_db_instance or aws_rds_cluster_instance sets publicly_accessible = true.",
    rationale="A publicly accessible database gets a public IP and is reachable from the internet; combined with a permissive security group it exposes data to credential-stuffing and direct attack.",
    remediation="publicly_accessible = false  # keep the database in private subnets",
    kinds=_TF,
    check=_check_tl019,
)

TL020 = Rule(
    id="TL020",
    title="KMS key rotation disabled",
    severity=Severity.MEDIUM,
    description="An aws_kms_key sets enable_key_rotation = false.",
    rationale="Without automatic rotation, a long-lived KMS key that is ever exposed keeps decrypting old and new data indefinitely.",
    remediation="enable_key_rotation = true",
    kinds=_TF,
    check=_check_tl020,
)

TL021 = Rule(
    id="TL021",
    title="ECR image scan-on-push disabled",
    severity=Severity.MEDIUM,
    description="An aws_ecr_repository sets image_scanning_configuration.scan_on_push = false.",
    rationale="Without scan-on-push, images with known CVEs are stored and deployed unnoticed; scanning is the cheapest supply-chain check.",
    remediation="image_scanning_configuration {\n  scan_on_push = true\n}",
    kinds=_TF,
    check=_check_tl021,
)

TL022 = Rule(
    id="TL022",
    title="EFS file system not encrypted",
    severity=Severity.HIGH,
    description="An aws_efs_file_system sets encrypted = false.",
    rationale="An unencrypted shared file system exposes data to anyone who can reach the backing storage or a stray mount target.",
    remediation='encrypted  = true\nkms_key_id = "arn:aws:kms:...:key/..."',
    kinds=_TF,
    check=_check_tl022,
)

TL023 = Rule(
    id="TL023",
    title="IMDSv2 not enforced (IMDSv1 allowed)",
    severity=Severity.HIGH,
    description="An aws_instance or aws_launch_template sets metadata_options.http_tokens = \"optional\".",
    rationale="IMDSv1 lets any SSRF on the instance harvest its IAM role credentials; IMDSv2 requires a signed, hop-limited token.",
    remediation='metadata_options {\n  http_tokens   = "required"\n  http_endpoint = "enabled"\n}',
    kinds=_TF,
    check=_check_tl023,
)

TL024 = Rule(
    id="TL024",
    title="DynamoDB point-in-time recovery disabled",
    severity=Severity.LOW,
    description="An aws_dynamodb_table sets point_in_time_recovery.enabled = false.",
    rationale="Without point-in-time recovery, an accidental or malicious write/delete cannot be rolled back.",
    remediation="point_in_time_recovery {\n  enabled = true\n}",
    kinds=_TF,
    check=_check_tl024,
)

TL025 = Rule(
    id="TL025",
    title="RDS automated backups disabled",
    severity=Severity.MEDIUM,
    description="An aws_db_instance sets backup_retention_period = 0, which disables automated backups.",
    rationale="With no automated backups, there is no recovery point after corruption, ransomware, or an errant migration.",
    remediation="backup_retention_period = 7  # days of automated backups",
    kinds=_TF,
    check=_check_tl025,
)

RULES: tuple[Rule, ...] = (
    TL001, TL002, TL003, TL004, TL005, TL006, TL007, TL008, TL009, TL010,
    TL019, TL020, TL021, TL022, TL023, TL024, TL025,
)
