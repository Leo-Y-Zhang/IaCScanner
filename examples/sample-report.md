# IaCScanner scan report

Read-only static analysis. No network calls, no cloud SDKs, no credentials.

- Tool: iacscanner 1.2.0
- Target: `examples/vulnerable`
- Files scanned: 4
- Risk score: **100/100** (grade **F**)
- Formula: `min(100, sum of severity weights: critical=25 high=15 medium=7 low=3)`

## Findings by severity

| Severity | Count |
| --- | --- |
| critical | 10 |
| high | 16 |
| medium | 6 |
| low | 7 |

## Per-file scores

| File | Score | Grade |
| --- | --- | --- |
| `ci-workflow.yml` | 55 | D |
| `config.json` | 75 | F |
| `deployment.yaml` | 100 | F |
| `main.tf` | 100 | F |

## Findings

| Severity | Confidence | Rule | File | Line | Location | Message |
| --- | --- | --- | --- | --- | --- | --- |
| critical | high | TL016 | `ci-workflow.yml` | 11 | `jobs.build.steps[0]` | pull_request_target workflow checks out the PR head |
| high | high | TL017 | `ci-workflow.yml` | 14 | `jobs.build.steps[1]` | run step echoes a secret into the build log |
| high | medium | TL028 | `ci-workflow.yml` | 16 | `jobs.build.steps[2]` | action 'some-org/deploy-action@main' is pinned to the mutable ref 'main' |
| critical | medium | TL018 | `config.json` | 3 | `line 3` | AWS access key ID detected (AKIAIOSF...) |
| critical | medium | TL018 | `config.json` | 4 | `line 4` | GitHub personal access token detected (ghp_0000...) |
| critical | medium | TL018 | `config.json` | 8 | `line 8` | hardcoded password assignment detected (hunter2-...) |
| critical | high | TL011 | `deployment.yaml` | 24 | `Deployment/example-app container web` | container runs privileged |
| medium | medium | TL012 | `deployment.yaml` | 29 | `Deployment/example-app container sidecar` | runAsNonRoot is not set |
| medium | medium | TL012 | `deployment.yaml` | 24 | `Deployment/example-app container web` | runAsNonRoot is not set |
| high | high | TL013 | `deployment.yaml` | 3 | `Deployment/example-app` | pod uses hostNetwork: true |
| low | medium | TL014 | `deployment.yaml` | 29 | `Deployment/example-app container sidecar` | no resource limits for cpu and memory |
| low | medium | TL014 | `deployment.yaml` | 24 | `Deployment/example-app container web` | no resource limits for cpu and memory |
| low | medium | TL015 | `deployment.yaml` | 29 | `Deployment/example-app container sidecar` | image 'example-sidecar' has no tag |
| low | medium | TL015 | `deployment.yaml` | 24 | `Deployment/example-app container web` | image 'nginx:latest' uses :latest |
| high | high | TL026 | `deployment.yaml` | 24 | `Deployment/example-app container web` | container runAsUser is 0 (root) |
| high | high | TL027 | `deployment.yaml` | 3 | `Deployment/example-app` | pod sets hostPID: true |
| high | high | TL027 | `deployment.yaml` | 20 | `Deployment/example-app volume host-root` | mounts host path '/' |
| critical | high | TL001 | `main.tf` | 12 | `aws_s3_bucket.example_data` | bucket ACL is 'public-read' |
| high | medium | TL002 | `main.tf` | 12 | `aws_s3_bucket.example_data` | no public access block protects this bucket |
| high | high | TL003 | `main.tf` | 61 | `aws_iam_policy.admin` | policy statement allows Action '*' |
| critical | high | TL004 | `main.tf` | 73 | `aws_s3_bucket_policy.public_read` | policy statement allows Principal '*' |
| critical | high | TL005 | `main.tf` | 17 | `aws_security_group.admin` | ingress open to the world on RDP |
| critical | high | TL005 | `main.tf` | 17 | `aws_security_group.admin` | ingress open to the world on SSH |
| high | high | TL006 | `main.tf` | 44 | `aws_db_instance.app` | RDS storage is not encrypted |
| high | high | TL006 | `main.tf` | 38 | `aws_ebs_volume.scratch` | EBS volume is not encrypted |
| medium | medium | TL007 | `main.tf` | 12 | `aws_s3_bucket.example_data` | no server-side encryption configuration protects this bucket |
| low | medium | TL008 | `main.tf` | 12 | `aws_s3_bucket.example_data` | bucket access logging is not enabled |
| low | medium | TL008 | `main.tf` | 12 | `aws_s3_bucket.example_data` | bucket versioning is not enabled |
| high | high | TL009 | `main.tf` | 55 | `aws_cloudtrail.main` | enable_logging is set to false |
| high | high | TL010 | `main.tf` | 44 | `aws_db_instance.app` | attribute 'password' holds a hardcoded literal |
| high | high | TL010 | `main.tf` | 6 | `variable.db_password` | secret-looking variable has a hardcoded default |
| critical | medium | TL018 | `main.tf` | 50 | `line 50` | hardcoded password assignment detected (hunter2-...) |
| high | high | TL019 | `main.tf` | 44 | `aws_db_instance.app` | database instance is publicly accessible |
| medium | high | TL020 | `main.tf` | 92 | `aws_kms_key.example` | automatic key rotation is disabled |
| medium | high | TL021 | `main.tf` | 97 | `aws_ecr_repository.example` | image scan-on-push is disabled |
| high | high | TL022 | `main.tf` | 104 | `aws_efs_file_system.example` | EFS file system is not encrypted |
| high | high | TL023 | `main.tf` | 108 | `aws_instance.example` | IMDSv2 is not enforced (http_tokens is 'optional') |
| low | medium | TL024 | `main.tf` | 116 | `aws_dynamodb_table.example` | point-in-time recovery is disabled |
| medium | medium | TL025 | `main.tf` | 124 | `aws_db_instance.backups` | automated backups are disabled (backup_retention_period = 0) |

## Remediation guidance

### TL001: S3 bucket has a public ACL (critical)

Public bucket ACLs expose every object to anonymous readers and are a leading cause of data leaks.

References: CWE-284, CIS Controls v8 Control 3

```
acl = "private"
```

### TL002: S3 public access block missing or weakened (high)

Without the account/bucket public access block, a single ACL or policy mistake can make data public.

References: CWE-284, CIS Controls v8 Control 3

```
resource "aws_s3_bucket_public_access_block" "this" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### TL003: IAM policy allows wildcard actions (high)

Wildcard actions grant far more than intended and defeat least-privilege review.

References: CWE-269, CIS Controls v8 Control 6

```
"Action": ["s3:GetObject"]  // list only the actions actually needed
```

### TL004: IAM policy allows wildcard principal (critical)

A wildcard principal lets any AWS account or anonymous user exercise the granted actions.

References: CWE-284, CIS Controls v8 Control 6

```
"Principal": {"AWS": "arn:aws:iam::123456789012:role/app-role"}
```

### TL005: Security group open to the world on an admin port (critical)

World-open admin ports are scanned and brute-forced within minutes of exposure.

References: CWE-284, CIS Controls v8 Control 4

```
cidr_blocks = ["10.0.0.0/16"]  # restrict to a trusted range or use SSM/VPN
```

### TL006: EBS volume or RDS storage not encrypted (high)

Unencrypted storage exposes data if snapshots, volumes, or backups are copied or mis-shared.

References: CWE-311, CIS Controls v8 Control 3

```
encrypted = true            # aws_ebs_volume
storage_encrypted = true    # aws_db_instance
```

### TL007: S3 bucket has no server-side encryption configuration (medium)

Explicit SSE configuration guarantees objects are encrypted at rest with the intended key.

References: CWE-311, CIS Controls v8 Control 3

```
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
```

### TL008: S3 bucket versioning or access logging not enabled (low)

Versioning protects against accidental deletion; access logs support incident investigation.

References: CWE-778, CIS Controls v8 Control 8

```
resource "aws_s3_bucket_versioning" "this" {
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_logging" "this" {
  target_bucket = "example-log-bucket"
  target_prefix = "s3-access/"
}
```

### TL009: CloudTrail logging disabled (high)

Disabling CloudTrail removes the audit trail attackers most want gone.

References: CWE-778, CIS Controls v8 Control 8

```
enable_logging = true
```

### TL010: Hardcoded secret in Terraform variable or resource (high)

Literal secrets in .tf files end up in version control and state files.

References: CWE-798, CIS Controls v8 Control 3

```
variable "db_password" {
  type      = string
  sensitive = true      # supply the value at deploy time
}
```

### TL011: Container runs privileged (critical)

Privileged containers can access host devices and typically escape to the node.

References: CWE-250, CIS Controls v8 Control 6

```
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
```

### TL012: runAsNonRoot missing or false (medium)

Root inside a container amplifies any container escape or file mount mistake.

References: CWE-250, CIS Controls v8 Control 6

```
securityContext:
  runAsNonRoot: true
```

### TL013: Pod uses the host network (high)

Host networking bypasses network policy and exposes node-local services to the pod.

References: CWE-668, CIS Controls v8 Control 4

```
hostNetwork: false  # or simply omit the field
```

### TL014: Container has no resource limits (low)

Unbounded containers can starve the node, a denial-of-service and noisy-neighbor risk.

References: CWE-400, CIS Controls v8 Control 4

```
resources:
  limits:
    cpu: 500m
    memory: 256Mi
```

### TL015: Image is untagged or uses :latest (low)

Mutable tags make deployments unreproducible and let unexpected images roll out.

References: CWE-1104, CIS Controls v8 Control 4

```
image: nginx:1.27.1  # pin a version, or better, a digest
```

### TL016: pull_request_target checks out untrusted PR code (critical)

pull_request_target runs with repository secrets; executing attacker-controlled PR code with them is a known takeover pattern.

References: CWE-94, CIS Controls v8 Control 16

```
on: pull_request  # or keep pull_request_target but never check out the PR head
```

### TL017: Secret echoed into the build log (high)

Log masking is best-effort; transformed or partial secrets routinely leak through build logs.

References: CWE-532, CIS Controls v8 Control 8

```
env:
  API_TOKEN: ${{ secrets.API_TOKEN }}  # pass via env, never echo it
```

### TL018: Hardcoded credential pattern in file (critical)

Credentials committed to configuration files spread through clones, backups, and CI caches and must be treated as compromised.

References: CWE-798, CIS Controls v8 Control 3

```
Remove the literal value, rotate the credential, and load it from an environment variable or secret manager.
```

### TL019: RDS instance is publicly accessible (high)

A publicly accessible database gets a public IP and is reachable from the internet; combined with a permissive security group it exposes data to credential-stuffing and direct attack.

References: CWE-284, CIS Controls v8 Control 4

```
publicly_accessible = false  # keep the database in private subnets
```

### TL020: KMS key rotation disabled (medium)

Without automatic rotation, a long-lived KMS key that is ever exposed keeps decrypting old and new data indefinitely.

References: CWE-320, CIS Controls v8 Control 3

```
enable_key_rotation = true
```

### TL021: ECR image scan-on-push disabled (medium)

Without scan-on-push, images with known CVEs are stored and deployed unnoticed; scanning is the cheapest supply-chain check.

References: CWE-693, CIS Controls v8 Control 7

```
image_scanning_configuration {
  scan_on_push = true
}
```

### TL022: EFS file system not encrypted (high)

An unencrypted shared file system exposes data to anyone who can reach the backing storage or a stray mount target.

References: CWE-311, CIS Controls v8 Control 3

```
encrypted  = true
kms_key_id = "arn:aws:kms:...:key/..."
```

### TL023: IMDSv2 not enforced (IMDSv1 allowed) (high)

IMDSv1 lets any SSRF on the instance harvest its IAM role credentials; IMDSv2 requires a signed, hop-limited token.

References: CWE-918, CIS Controls v8 Control 4

```
metadata_options {
  http_tokens   = "required"
  http_endpoint = "enabled"
}
```

### TL024: DynamoDB point-in-time recovery disabled (low)

Without point-in-time recovery, an accidental or malicious write/delete cannot be rolled back.

References: CWE-693, CIS Controls v8 Control 11

```
point_in_time_recovery {
  enabled = true
}
```

### TL025: RDS automated backups disabled (medium)

With no automated backups, there is no recovery point after corruption, ransomware, or an errant migration.

References: CWE-693, CIS Controls v8 Control 11

```
backup_retention_period = 7  # days of automated backups
```

### TL026: Container or pod runs as root by UID (high)

A hardcoded UID 0 runs as root even when a policy sets runAsNonRoot, amplifying any container escape.

References: CWE-250, CIS Controls v8 Control 4

```
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
```

### TL027: Pod mounts the host filesystem or namespaces (high)

Host mounts and shared host namespaces give a compromised pod a direct path to read host files or other processes and escape to the node.

References: CWE-668, CIS Controls v8 Control 4

```
Remove hostPath volumes and hostPID/hostIPC; use a PersistentVolumeClaim or emptyDir instead.
```

### TL028: Action pinned to a mutable branch (high)

A mutable branch ref runs whatever code that branch holds at run time; if the action is compromised or retargeted, it executes in your workflow with its secrets.

References: CWE-829, CIS Controls v8 Control 16

```
uses: owner/action@<40-char commit SHA>  # or at least a version tag
```
