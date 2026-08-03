# Migrating to IaCScanner 1.0

IaCScanner 1.0 is a large capability release, but it is designed to drop in over a
0.x setup with no changes to your commands. This guide lists what is new, the
one behaviour change to be aware of, and why your existing baselines keep
working.

## TL;DR

- **CLI is backward compatible.** Every 0.x flag, subcommand, and exit code
  behaves the same. New flags are additive.
- **Baselines still apply.** The finding fingerprint `(rule_id, path,
  location)` is unchanged and the new `confidence` field is not part of it, so
  a `baseline.json` written by 0.x continues to suppress the same findings.
- **One behaviour change:** the S3 companion rules (TL002 / TL007 / TL008) now
  resolve companion resources *across files*, which removes false positives -
  so you may see **fewer** of those three findings, not more.

## New capabilities

### Output and filtering

- `--format sarif` - SARIF 2.1.0 output for GitHub code scanning and other
  SARIF UIs. See the README's "SARIF output" section for an upload snippet.
- `--min-confidence {low,medium,high}` - mirrors `--min-severity`; filters
  findings below a confidence level out of the report, scoring, and
  `--fail-on`.
- `--stats` - prints a deterministic scan summary (by rule / severity /
  confidence / file kind) to **stderr**, so it never contaminates a JSON or
  SARIF report on stdout.

### Policy and suppressions

- `--policy FILE` and auto-discovered `.themis.yaml` beside the target:
  `disable:` rules, `severity:` overrides, and `exclude:` path globs. Malformed
  entries emit visible `warning:` lines on stderr and are ignored.
- Inline `# themis:ignore` / `# themis:ignore TL005,TL010` comments suppress
  findings in a file (markers inside string literals are not treated as
  directives). Suppressed counts are reported on stderr.

### Metadata

- Every finding now carries a **confidence** level and **CWE** + **CIS Controls
  v8** references, surfaced in text (CONF column), Markdown (Confidence column
  + References), SARIF (result properties), and JSON.
- JSON findings gained `confidence`, `cwe_ids`, and `cis_controls` fields.
  These are additive; existing fields are unchanged, so JSON consumers that
  read by key keep working.

### New rules (TL019-TL028)

Ten rules were added since 0.1's TL001-TL018. Each fires only on an explicit
misconfiguration and stays silent on the secure value and on the omitted
insecure default:

| Rule | Severity | Flags |
| --- | --- | --- |
| TL019 | high | RDS instance `publicly_accessible = true` |
| TL020 | medium | KMS key `enable_key_rotation = false` |
| TL021 | medium | ECR `image_scanning_configuration.scan_on_push = false` |
| TL022 | high | EFS `encrypted = false` |
| TL023 | high | IMDSv2 not enforced (`metadata_options.http_tokens = "optional"`) |
| TL024 | low | DynamoDB `point_in_time_recovery.enabled = false` |
| TL025 | medium | RDS `backup_retention_period = 0` |
| TL026 | high | K8s `runAsUser: 0` or `fsGroup: 0` |
| TL027 | high | K8s `hostPath` volume / `hostPID` / `hostIPC` |
| TL028 | high | Action pinned to a mutable branch (`@main`/`@master`, not a tag/SHA) |

If you gate CI with `--fail-on high` on a tree that has any of these
conditions, you may see **new** high findings after upgrading. Adopt them the
same way as any new rule: run `--write-baseline` once to accept the current
state, or fix the misconfigurations.

## The one behaviour change: cross-file S3 rules

In 0.x, TL002 (public access block), TL007 (server-side encryption) and TL008
(versioning/logging) only looked within the *same file* for a bucket's
companion resource. A bucket in `s3.tf` whose public-access-block lived in
`security.tf` was falsely flagged.

In 1.0 these three rules resolve companions across the whole scan root through
the resource graph, binding a companion to a bucket by resource address,
resolved literal name, or variable reference. Net effect:

- A bucket whose companion sits in a **different file** is no longer flagged
  (fewer false positives).
- A bucket with a **genuinely missing** companion still fires.
- All three rules anchor their `location` on the bucket resource address
  (e.g. `aws_s3_bucket.example_data`), so their fingerprints are stable and a
  0.x baseline keeps matching. Only the finding **message** wording and the
  *set* of buckets flagged changed; message is not part of the fingerprint.

This is an accuracy improvement, guarded so it cannot introduce silent false
negatives: the rules still fire when a companion is truly absent.

## Upgrade checklist

1. Reinstall: `pip install -e ".[dev]"` (runtime deps are still just
   `python-hcl2` and `pyyaml`).
2. Run your existing command unchanged; confirm the exit code is what you
   expect.
3. If `--fail-on` now trips on a new rule (TL019-TL028) or a re-anchored
   TL007/TL008 finding, either fix the issue or refresh the baseline:
   `iacscanner scan PATH --baseline baseline.json --write-baseline baseline.json`.
4. Optionally adopt the new capabilities: add a `.themis.yaml`, switch CI to
   `--format sarif`, or add `--min-confidence` / `--stats`.
