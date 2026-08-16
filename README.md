# IaCScanner - read-only Infrastructure-as-Code misconfiguration scanner

[![CI](https://github.com/Leo-Y-Zhang/IaCScanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Leo-Y-Zhang/IaCScanner/actions/workflows/ci.yml)

IaCScanner is a defensive, local, **read-only** Infrastructure-as-Code
scanner. It reads Terraform (HCL), YAML (Kubernetes manifests and GitHub
Actions workflows), JSON files, and Dockerfiles on your disk and reports
common security misconfigurations with severities, a 0-100 risk score, and
remediation snippets.

The non-obvious part is what IaCScanner *refuses* to do: it makes zero network
calls, ships no cloud SDKs, and never touches credentials or live
infrastructure. Everything is derived from file content alone, so a scan is
safe to run against untrusted repositories and produces byte-identical,
timestamp-free reports that diff cleanly in git. That determinism powers a
baseline workflow (below) that lets CI fail only on *new* misconfigurations.

> **Educational / defensive only.** IaCScanner makes **zero network calls**,
> ships **zero cloud SDKs**, and **never needs credentials**. It only reads
> files and prints findings. It is a portfolio/educational tool, not a
> replacement for production scanners such as Checkov, tfsec, or Trivy.

## What it is

- A static analyzer for local IaC files: `.tf`, `.yaml`, `.yml`, `.json`,
  and Dockerfiles (`Dockerfile`, `Containerfile`, `*.dockerfile`, and
  `Dockerfile.<variant>` names like `Dockerfile.prod`).
- 32 built-in rules (TL001-TL032), each tagged with CWE and CIS Controls v8
  references and a confidence level, across five areas:
  - **Terraform (AWS-style)**: public S3 ACLs and missing/weak public access
    block, no S3 server-side encryption/versioning/logging, IAM wildcard
    actions/principals, world-open security groups on SSH/RDP/all ports,
    unencrypted EBS/RDS/EFS, CloudTrail logging disabled, publicly accessible
    RDS, hardcoded secrets, KMS rotation off, ECR scan-on-push off, IMDSv2 not
    enforced, DynamoDB PITR off, RDS backups disabled.
  - **Kubernetes**: privileged containers, `runAsNonRoot` missing/false,
    `runAsUser`/`fsGroup: 0`, `hostNetwork`/`hostPID`/`hostIPC`/`hostPath`
    mounts, missing resource limits, `:latest`/untagged images.
  - **GitHub Actions**: `pull_request_target` combined with a PR-head
    checkout ("pwn request"), secrets echoed into build logs, actions pinned
    to a mutable branch instead of a tag or commit SHA.
  - **Dockerfile**: final image runs as root, secret-looking literal ENV
    baked into the final image, mutable/untagged external base tag, SSH
    port exposed - each scoped to the **final-image stage chain** so
    builder-stage decoys never fire (see the dedicated section below).
  - **Generic (any file)**: hardcoded credential patterns (`AKIA...` keys,
    `ghp_...` tokens, literal `password =` assignments).
- A **cross-file resource graph** resolves `${var.x}` / `${local.y}` /
  `${type.name.attr}` references across the whole scan root, so the S3
  companion-resource rules (TL002/TL007/TL008) pair a bucket with its public
  access block / encryption / versioning even when they live in different
  files. Unresolved or circular references fall back to the literal and never
  fire - references reduce false positives, they never invent findings.
- A parse failure never crashes a scan: the file becomes a `TL000`
  warning finding and the scan exit code is 2.

## Features

- Risk-scored findings with a documented formula and letter grades A-F.
- Four output formats: aligned text table (pure stdlib), `--format json`,
  `--format markdown`, and **`--format sarif`** (SARIF 2.1.0 for GitHub code
  scanning and other SARIF UIs); optional `--out FILE`.
- **Precise source lines**: every finding's structural anchor is resolved to
  the 1-based line of the structure it names - Terraform addresses to their
  block start line (via the HCL parse tree's position metadata), Kubernetes
  and workflow anchors to their YAML node lines, `line N` text anchors
  directly. Surfaced as a LINE column (text), a `line` field (JSON), a Line
  column (Markdown), and `region.startLine` (SARIF), so code-scanning
  annotations land on the exact line. When a mapping is ambiguous or
  unavailable the line is **omitted, never guessed**, and it is never part
  of the baseline fingerprint.
- CWE / CIS Controls v8 references and a **confidence** level on every
  finding, surfaced in all formats; `--min-severity` and `--min-confidence`
  filters and a `--fail-on` threshold for CI-style use.
- **Declarative policy** (`.themis.yaml`, auto-discovered or `--policy FILE`):
  disable rules, override severities, exclude path globs - with **visible**
  warnings for anything malformed, never a silent hide.
- **Inline suppressions**: a `# themis:ignore` or `# themis:ignore TL005,TL010`
  comment (string-literal-safe) suppresses findings in that file.
- Baseline workflow for adopting IaCScanner on an existing tree:
  `--write-baseline` records current findings, `--baseline` suppresses
  exactly those and fails only on **new** findings.
- `--stats`: a deterministic scan summary (by rule / severity / confidence /
  file kind) printed to stderr, so it never pollutes a JSON/SARIF report.
- Deterministic output: findings are sorted, reports contain no timestamps,
  and file paths are shown relative to the scan target with POSIX separators
  (never absolute, never OS-dependent) - reports diff cleanly in git.
- **Dockerfile rules with final-image stage attribution** (TL029-TL032):
  a stdlib-only multi-stage parser (escape-directive-aware Docker-faithful
  continuations, BuildKit heredocs consumed as content, `FROM ${VAR}`
  resolution from pre-`FROM` `ARG` defaults) feeds rules that walk only
  the stages that reach the shipped image, so `USER root` or a
  `golang:latest` toolchain in a discarded builder stage stays silent.
- Paired `examples/vulnerable/` + `examples/secure/` and
  `examples/vulnerable-docker/` + `examples/secure-docker/` fixtures, all
  synthetic, each vulnerable file clearly marked as an intentionally
  insecure example.
- Tested: every rule is verified to fire on its vulnerable fixture and to
  stay silent on the secure counterpart, output is proven byte-identical
  under load, the committed sample report/SARIF are drift-tested against a
  fresh render, and a derandomized Hypothesis suite feeds adversarial text
  through the Dockerfile parser, rules, line attachment, suppressions,
  SARIF rendering and whole scans (419 pytest tests, ruff + mypy `--strict`
  clean). Containment is proved twice over with real links, so **417 passed,
  2 skipped** is the expected result on *either* platform: the two
  real-symlink discovery tests skip on Windows without the symlink-creation
  privilege, and the two real-NTFS-junction tests skip everywhere that is not
  Windows.

## Install

Requires Python 3.10+ (developed on 3.13). Runtime dependencies:
`python-hcl2` and `pyyaml` only.

```bash
python -m venv .venv
. .venv/bin/activate          # Linux/macOS
# .venv\Scripts\activate      # Windows (PowerShell: .venv\Scripts\Activate.ps1)
python -m pip install -e ".[dev]"
```

## Quickstart

Every command below uses the `iacscanner` console script that pip installs
into the environment. `python -m iacscanner ...` is exactly equivalent and
works without activating the environment; on Windows that spelling is
`.venv\Scripts\python.exe -m iacscanner ...`.

Scan the intentionally vulnerable fixtures (from the repository root):

```bash
iacscanner scan examples/vulnerable
```

Real output; the 39-row findings table is elided to six representative rows:

```
IaCScanner 1.2.0 - defensive IaC misconfiguration scanner
Read-only static analysis. No network calls, no cloud SDKs, no credentials.

Target        : examples/vulnerable
Files scanned : 4
Findings      : 39 (critical 10, high 16, medium 6, low 7)
Risk score    : 100/100 (grade F)
Formula       : min(100, sum of severity weights: critical=25 high=15 medium=7 low=3)

SEVERITY  CONF    RULE   FILE             LINE  LOCATION                                  MESSAGE
--------  ------  -----  ---------------  ----  ----------------------------------------  ------------------------------------
critical  high    TL016  ci-workflow.yml  11    jobs.build.steps[0]                       pull_request_target workflow checks out the PR head
high      medium  TL028  ci-workflow.yml  16    jobs.build.steps[2]                       action 'some-org/deploy-action@main' is pinned to the mutable ref 'main'
critical  high    TL011  deployment.yaml  24    Deployment/example-app container web      container runs privileged
high      high    TL027  deployment.yaml  3     Deployment/example-app                    pod sets hostPID: true
critical  high    TL001  main.tf          12    aws_s3_bucket.example_data                bucket ACL is 'public-read'
high      high    TL023  main.tf          108   aws_instance.example                      IMDSv2 is not enforced (http_tokens is 'optional')
...
PER-FILE SCORES
FILE             SCORE  GRADE
---------------  -----  -----
ci-workflow.yml  55     D
config.json      75     F
deployment.yaml  100    F
main.tf          100    F
```

The exit code is `1` because findings at or above `--fail-on high` exist.
The secure counterparts come back clean with exit code `0`:

```bash
iacscanner scan examples/secure
```

```
Findings      : 0 (critical 0, high 0, medium 0, low 0)
Risk score    : 0/100 (grade A)

No findings.
```

More things to try:

```bash
# list every rule (with severity, CWE/CIS come through in JSON/SARIF/markdown)
iacscanner rules

# JSON report, only critical findings
iacscanner scan examples/vulnerable --format json --min-severity critical

# SARIF 2.1.0 for GitHub code scanning
iacscanner scan examples/vulnerable --format sarif --out results.sarif

# high-confidence findings only, with a per-rule/severity summary on stderr
iacscanner scan examples/vulnerable --min-confidence high --stats

# apply a policy file (disable rules / override severities / exclude paths):
# 39 findings become 37, and the two TL008 findings move from low to medium
iacscanner scan examples/vulnerable --policy examples/example.themis.yaml

# regenerate the committed sample artifacts (exit 1 by design)
iacscanner scan examples/vulnerable --format markdown --out examples/sample-report.md
iacscanner scan examples/vulnerable --format sarif   --out examples/sample.sarif

# run the test suite
pytest
```

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No findings at or above the `--fail-on` threshold |
| 1 | At least one reported finding at or above `--fail-on` (default: `high`) |
| 2 | Usage error, path not found, malformed/unwritable baseline file, or one or more files failed to parse |

Exit code 2 takes precedence over 1. `--min-severity` hides findings from
the report **and** from scoring and `--fail-on` evaluation. With
`--baseline`, only **new** findings count toward exit code 1; a successful
`--write-baseline` run exits 0 (everything it records is accepted by
definition). Parse errors always exit 2, baselined or not.

### Baseline workflow (CI)

Adopting a scanner on an existing tree usually drowns you in historical
findings. The baseline workflow lets CI fail only on **regressions**:

```bash
# One-time (or whenever you consciously accept the current state):
iacscanner scan infra/ --write-baseline baseline.json     # exits 0
git add baseline.json && git commit -m "Accept current IaCScanner findings"

# In CI on every push/PR:
iacscanner scan infra/ --baseline baseline.json --fail-on high
# exit 0  -> nothing new at/above high; known findings stay suppressed
# exit 1  -> NEW findings appeared; the report shows only those
# exit 2  -> parse/usage error or a malformed baseline file (fails closed)
```

To refresh a baseline after fixing some findings (or accepting new ones),
combine both flags in one run:

```bash
iacscanner scan infra/ --baseline baseline.json --write-baseline baseline.json
```

The refreshed file records **all** currently reported findings, so fixed
ones drop out and anything new is accepted.

#### Fingerprint stability contract

A finding's fingerprint is the quadruple
**(rule_id, path, location, sub_key)**:

- `rule_id` - stable rule identifiers (`TL000`-`TL032`); existing ids are
  never renumbered or reused for a different check.
- `path` - the display path relative to the scan target with POSIX
  separators, so fingerprints match across machines and operating systems
  as long as you scan the same target root.
- `location` - the rule's structural anchor (Terraform resource address,
  Kubernetes `Kind/name` container path, workflow job/step index, or
  `line N` for text-pattern rules). Structural locations survive unrelated
  edits; line-based locations shift when lines are added or removed above
  the finding, in which case the finding deliberately resurfaces as new.
- `sub_key` - which of several findings a rule emits at that one location:
  the port (`"SSH"`), the property (`"versioning"`), the host namespace
  (`"hostPID"`). Empty for rules that emit at most one finding per
  location. Added in baseline schema 2 after the collision described
  below; structural and stable like `location`, never a slice of the
  message.

Without `sub_key`, siblings shared an identity. On `examples/vulnerable`
that was 39 findings but only 37 fingerprints, and one collision was two
CRITICALs on a single security group - world-open SSH and world-open RDP.
Baselining one silently suppressed the other, including one added later,
so a reviewed gate stayed green while the tree got worse. Schema 1
baselines are still accepted and still suppress exactly what they always
did: an entry written before `sub_key` existed cannot say which sibling it
meant, so it keeps its original, coarser meaning and matches every finding
at that location. Regenerate the baseline to get the precise identity.

The finding *message* and *severity* are deliberately **not** part of the
fingerprint, so message wording and severity classifications can be tuned
between IaCScanner versions without invalidating existing baselines. The
resolved source *line* (1.1.0) is display metadata and is likewise
excluded: **a baseline written by any earlier release keeps suppressing the
same findings.** That guarantee is regression-tested, not aspirational:
`tests/data/baseline-1.0.0.json` was written by release 1.0.0, in July 2026,
when this tool was still called Themis and before line resolution existed. No
version of it has ever been published under the name `iacscanner`, which is
why the file's header still reads `"tool": "themis-baseline"` - the fixture is
a real artifact of an older release, not one regenerated to match the current
name, and it would prove nothing if it were. A pinned test requires it to
suppress everything the current code finds. You can replay the check yourself:

```bash
iacscanner scan examples/vulnerable \
    --baseline tests/data/baseline-1.0.0.json --fail-on low
```

```
baseline: 39 finding(s) suppressed, 0 new
...
Findings      : 0 (critical 0, high 0, medium 0, low 0)
...
No findings.
```

and the exit code is `0`.

Matching is set-based: one baselined fingerprint suppresses every current
finding with that exact fingerprint. Baseline files are deterministic
(sorted, de-duplicated, newline-terminated JSON) and diff cleanly in git.
Both `--min-severity` and `--min-confidence` apply before writing and before
matching, so a baseline written under a filter records only what that filter
let through.

### Policy and inline suppressions

Two complementary ways to tune a scan, both of which surface (never silently
hide) anything malformed.

A `.themis.yaml` next to the target (or `--policy FILE`) applies before the CLI
filters:

```yaml
# .themis.yaml
disable:            # never report these rules
  - TL014           # resource limits are handled elsewhere
severity:           # override a rule's severity
  TL008: medium     # treat missing versioning/logging as medium here
exclude:            # skip files matching these globs
  - "**/generated/**"
```

That exact policy is checked in as
[`examples/example.themis.yaml`](examples/example.themis.yaml), so the command
above is runnable rather than illustrative. It is deliberately not named
`.themis.yaml`: a file with the discoverable name sitting in `examples/` would
be picked up automatically and would change the output of every other example
in this README. Auto-discovery only ever matches `.themis.yaml` beside the
target; anything else has to be named with `--policy`.

Unknown rule ids, invalid severities, unknown keys, or a non-mapping file
each emit a `warning:` line on stderr and are ignored - the scan still runs.
A `--policy` path that does not exist is reported the same way (`warning:
policy file ... could not be read`) and the scan continues unfiltered, so a
typo cannot silently produce a quieter result that looks like a clean one.

For a one-off exception, an inline comment suppresses findings in that file:

```hcl
# themis:ignore TL010            # suppress only TL010 in this file
variable "db_password" { default = "hunter2-not-real" }

# themis:ignore                  # suppress every rule in this file
```

A `# themis:ignore` marker inside a string literal is not treated as a
directive. Suppressed counts are reported on stderr, so suppression is always
visible in the run output.

### SARIF output

`--format sarif` emits a SARIF 2.1.0 log with the full rule catalogue as
`reportingDescriptor`s and each finding as a result with a stable `ruleIndex`,
a POSIX `physicalLocation` URI, a `region.startLine` whenever the finding's
anchor resolved to a source line (omitted otherwise, never guessed), and
`confidence`/CWE/CIS properties. One result, verbatim from the committed
`examples/sample.sarif` (the TL001 finding from the quickstart above):

```json
{
  "level": "error",
  "locations": [
    {
      "logicalLocations": [
        {
          "fullyQualifiedName": "aws_s3_bucket.example_data"
        }
      ],
      "physicalLocation": {
        "artifactLocation": {
          "uri": "main.tf"
        },
        "region": {
          "startLine": 12
        }
      }
    }
  ],
  "message": {
    "text": "bucket ACL is 'public-read'"
  },
  "properties": {
    "cis": [
      "CIS Controls v8 Control 3"
    ],
    "confidence": "high",
    "cwe": [
      "CWE-284"
    ]
  },
  "ruleId": "TL001",
  "ruleIndex": 1
}
```

The `region` block is the 1.1.0 addition: the git diff of
`examples/sample.sarif` between 1.0.0 and 1.1.0 is exactly one
`region.startLine` gained per result (all 39) plus the tool version string -
nothing else moved. The log is deterministic (no timestamps, sorted keys) so
it diffs cleanly, and uploads to GitHub code scanning, where the start line
puts each annotation on the exact offending line:

```yaml
# .github/workflows/iacscanner.yml (excerpt)
- run: iacscanner scan infra/ --format sarif --out iacscanner.sarif || true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: iacscanner.sarif
```

`examples/sample.sarif` is a committed, regenerable example of the output.

### Dockerfile rules and stage attribution

`Dockerfile`, `Containerfile`, `*.dockerfile`, and `Dockerfile.<variant>` /
`Containerfile.<variant>` names (the `docker build -f Dockerfile.prod`
convention) are discovered automatically; a variant whose extension is
another scanned kind keeps that kind (`Dockerfile.yaml` stays YAML). The
parser is stdlib-only, total on hostile input, and mirrors Docker where it
matters: `# escape=` directives, continuations joined exactly as Docker
joins them (no separator inserted), BuildKit heredoc bodies consumed as
content (a `FROM` inside a `RUN <<EOF` block can never fabricate a stage),
`FROM ${VAR}` resolved from pre-`FROM` `ARG` defaults, and case-insensitive
stage references.

The false-positive discipline is **final-image scoping**: a multi-stage
build discards every builder stage, so TL029 (runs as root, high), TL030
(secret-looking literal ENV, high), TL031 (mutable/untagged external base,
low), and TL032 (SSH port exposed, medium) walk only the final stage plus
the internal stages it extends through `FROM <stage>` chains. `USER root`,
a `golang:latest` toolchain, or a build-time ENV token in a discarded stage
never fire - `examples/secure-docker/` keeps exactly those decoys in its
builder stage and scans clean. Findings inherited through a stage chain say
so, and anchor to real source lines. Real output (elided to the findings
table) from `examples/vulnerable-docker/`, whose builder stage is
deliberately clean and pinned:

```
SEVERITY  CONF    RULE   FILE        LINE  LOCATION                  MESSAGE
--------  ------  -----  ----------  ----  ------------------------  ---------------------------------------------
high      high    TL029  Dockerfile  14    stage[runtime].USER[0]    final image runs as root (USER root)
high      medium  TL030  Dockerfile  11    stage[runtime].ENV[0]     final image bakes secret-looking environment variable 'APP_DB_PASSWORD' (value hunter2-...)
low       medium  TL031  Dockerfile  10    stage[runtime].FROM       final image is built from mutable base 'ubuntu:latest'
medium    high    TL032  Dockerfile  12    stage[runtime].EXPOSE[0]  final image exposes SSH port 22 (22)
```

Unresolved stays silent, never guessed: a `$VAR` user, an
`ARG`-parameterised base without a literal default, a digest-pinned ref,
`scratch`, and a base that names another stage all produce no finding, and
a Dockerfile with no `USER` in its final chain is silent because the base
image's default user is unknown.

### Scoring formula

Each finding contributes its severity weight: critical = 25, high = 15,
medium = 7, low = 3. The score is `min(100, sum_of_weights)`, computed per
file and overall. Grades: A = 0, B = 1-14, C = 15-39, D = 40-69, F = 70-100.
A saturated score of 100 simply means "many serious findings".

## Architecture

```
src/iacscanner/
  __init__.py        package docstring + version
  __main__.py        python -m iacscanner entry
  cli.py             argparse CLI: scan / rules, exit codes, policy/stats wiring
  baseline.py        finding fingerprints + baseline write/load/suppress
  graph.py           cross-file ResourceGraph + resolve() + frozen ScanContext
  models.py          Severity, Confidence, ScanFile, Rule, Finding dataclasses
  metadata.py        curated per-rule CWE + CIS Controls v8 + confidence table
  parsers.py         file discovery + HCL/YAML/JSON/Dockerfile parsing (safe_load only)
  docker.py          stdlib-only multi-stage Dockerfile parser (heredocs, continuations, ARG substitution)
  lines.py           structural-anchor -> source-line resolver (omits, never guesses)
  scanner.py         orchestration: parse, build context, run rules, suppress, resolve lines, sort
  scoring.py         weights, 0-100 scores, letter grades
  report.py          text / json / markdown renderers + render_stats (stdlib only)
  sarif.py           SARIF 2.1.0 renderer (deterministic, offline)
  policy.py          .themis.yaml load/discover/apply (visible warnings)
  suppress.py        inline # themis:ignore parsing (string-literal-safe)
  rules/
    __init__.py      registry (RULES, ALL_RULES, get_rule) + metadata attach
    _tf.py           shared helpers for python-hcl2 output
    terraform.py     TL001-TL010, TL019-TL025 (TL002/007/008 are graph-aware)
    kubernetes.py    TL011-TL015, TL026-TL027
    actions.py       TL016-TL017, TL028
    dockerfile.py    TL029-TL032 (final-image stage attribution)
    generic.py       TL018
examples/
  vulnerable/        intentionally insecure fixtures (synthetic data)
  secure/            hardened counterparts (scan comes back clean)
  vulnerable-docker/ intentionally insecure Dockerfile (clean builder stage)
  secure-docker/     hardened Dockerfile (deliberate builder-stage decoys)
  sample-report.md   committed markdown report generated from the fixtures
  sample.sarif       committed SARIF 2.1.0 report generated from the fixtures
tests/               419 tests: rules, graph, scoring, parsers, lines, reports, baseline,
                     SARIF, policy, suppress, stress/determinism, drift, CLI e2e,
                     property-based robustness (Hypothesis, derandomized)
```

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full pipeline and
the determinism invariants, [`docs/MIGRATION.md`](docs/MIGRATION.md) for
upgrading from 0.x, and [`docs/PRD.md`](docs/PRD.md) /
[`docs/TDD.md`](docs/TDD.md) for the problem statement and the design
decisions behind the code.

## Naming and on-disk compatibility

This project was called **Themis** through 1.2.0 and was renamed to
**IaCScanner** afterwards. Everything that is *identity* moved: the
distribution, the import path (`import iacscanner`), the console script, the
`--version` string, the report headers, and the SARIF `tool.driver.name`.

Three names are deliberately **frozen at the old spelling**, because they are
not identity - they are on-disk file formats, written into working trees the
tool does not control, and renaming them would silently stop honouring files
that used to work:

| Frozen name | Where it lives | Why |
| --- | --- | --- |
| `.themis.yaml` | auto-discovered policy filename | a renamed default would silently ignore an existing policy - a scan would quietly get *louder or quieter* with no warning |
| `# themis:ignore` | inline suppression comment | renaming it would resurrect every suppressed finding at once, in files the tool must never edit |
| `"tool": "themis-baseline"` | baseline file header, **validated on load** | `load_baseline` rejects any other value, so a rename would make every existing baseline fail closed with a hard error |

The alternative - accepting both spellings - is a real feature with real
tests, not a rename, so it is on the roadmap rather than smuggled into a
rename commit. Rule ids (`TL000`-`TL032`) and finding fingerprints are
unaffected: **a baseline written by Themis 1.0.0 still suppresses exactly what
it always did**, and the pinned regression test in `tests/data/` proves it.

## Safety and privacy notes

- **Read-only**: IaCScanner opens files for reading and writes only the
  report you request with `--out`. It never modifies scanned files.
- **Offline**: no network access of any kind; no telemetry; no cloud SDKs.
- **No credentials**: nothing to configure, nothing to leak. The scanner
  works purely on file content.
- YAML is parsed exclusively with SafeLoader construction: `yaml.safe_load_all`
  for scanning, and the line resolver uses a `SafeLoader` subclass whose only
  change is remembering each mapping's source line (still no object
  instantiation).
- Secret-looking values found by TL018 are masked in reports (only a short
  prefix is shown).
- All fixture data is synthetic: account id `123456789012`, hosts under
  `example.com`, and documented fake secrets such as
  `AKIAIOSFODNN7EXAMPLE` (the official AWS documentation example key).
- Reports show paths relative to the scan target, so committed reports do
  not embed local directory layouts.

## Threat model

IaCScanner treats every scanned file as **untrusted attacker-controlled input**
and is meant to be safe to point at a repository you do not trust. The
input surfaces are the `.tf`, `.yaml`/`.yml`, and `.json` files it reads.

What it defends against:

- **No code execution from input.** Terraform is parsed with `python-hcl2`
  (a Lark grammar, no `eval`/`exec`); YAML uses SafeLoader construction only -
  `yaml.safe_load_all` for scanning and a line-marking `SafeLoader` subclass
  in the resolver (never full `yaml.load`, so no arbitrary object
  construction / RCE); JSON uses the standard library. IaCScanner never imports
  `hcl2.query` and so never reaches its expression evaluator.
- **No network, no credentials.** IaCScanner opens no sockets, ships no cloud
  SDKs, reads no environment credentials, and makes no calls to any
  provider. Everything is derived from local file bytes.
- **Discovery is bounded to the scan root.** Before descending into any
  directory or accepting any file, IaCScanner resolves its `os.path.realpath`
  and requires it to lie within `realpath(scan_root)` (a boundary-aware
  prefix check, not a bare `startswith`). Anything whose real path escapes
  the root is pruned - a POSIX symlink, a **Windows NTFS directory junction**
  (`mklink /J`, which needs no admin and which `os.walk`/`is_symlink` do
  *not* flag as a link), or any other reparse point - so a hostile repo
  cannot make IaCScanner read or report files outside the scan root. A `seen`
  set of visited directory real paths provides loop protection:
  a self-referential junction or symlink is pruned the moment its real path
  (or an ancestor of it) has already been visited, so discovery cannot be
  driven into runaway recursion. This containment is link-type- and
  Python-version-independent (`os.walk(followlinks=False)` alone declines
  POSIX symlinks but not junctions, and only stopped `rglob` following
  symlinks by default in 3.13; the real-path check covers all of them).
- **Malformed / adversarial parses degrade gracefully.** A file that fails
  to parse - including deeply nested YAML/JSON/HCL that exhausts the
  recursion limit - becomes a single `TL000` finding (exit code 2) and
  never aborts the scan or crashes the process. YAML anchor/alias reuse
  ("billion laughs") shares references and is never materialised or
  re-serialised by any rule, so it does not blow up memory. The source-line
  resolver inherits the same posture: any parse or traversal failure while
  mapping an anchor to a line simply omits the line, and an anchor that two
  structures produce on different lines is treated as ambiguous rather than
  guessed (adversarially tested with recursive aliases, deep nesting, huge
  single-line files, and colliding anchor names).
- **Bounded rule regexes.** The credential/pattern regexes run per line and
  contain no nested-quantifier constructs, so they are linear-time (no
  ReDoS); this was checked against megabyte-scale pathological lines.
- **Read-only.** IaCScanner opens scanned files only for reading and writes
  solely to the `--out` / `--write-baseline` file you name.

What it does **not** defend against (out of scope):

- **Resource use is proportional to input size.** A legitimately enormous
  file (many megabytes) will take proportional CPU/RAM to parse, because
  the whole file is read into memory - IaCScanner does not impose a size or time
  cap. Point it at your own tree; it is not a sandbox for hostile inputs of
  unbounded size.
- **Third-party parser robustness.** Parse-level DoS resistance for
  Terraform ultimately depends on `python-hcl2`/`lark`; IaCScanner contains
  recursion errors and rejects the file, but does not otherwise sandbox the
  parser.
- **Report consumers.** Findings echo short, masked snippets of file
  content (e.g. an image name or a masked token prefix); treat generated
  reports with the same care as the scanned files.

## Limitations

IaCScanner is a pattern scanner with a lightweight cross-file reference resolver,
not a full graph-aware analyzer or a `terraform plan` evaluator:

- **Reference resolution is textual, not semantic.** The resource graph pairs
  the S3 companion rules (TL002/TL007/TL008) across files and follows
  `${var.x}` / `${local.y}` / `${type.name.attr}` chains by regex, not by
  evaluating HCL. Functions, `for`/`count`/`for_each` expansion, module
  inputs, remote state, and `terraform plan` semantics are not evaluated; an
  unresolved reference falls back to its literal and never invents a finding.
- Secret-looking values behind `var.*`/`local.*` are deliberately **not**
  flagged as hardcoded secrets (only literal defaults/attributes are).
- IAM analysis only reads inline JSON policy documents (heredoc or string);
  `jsonencode()` expressions and data-source policies are not parsed.
- Kubernetes coverage is limited to common workload kinds (Pod, Deployment,
  StatefulSet, DaemonSet, ReplicaSet, Job, CronJob).
- TL018 is a regex heuristic: it can miss encoded secrets and can flag
  password-like test values. Tune or filter with `--min-severity`.
- Dockerfile analysis reads the file, not the build: `RUN` shell bodies are
  not interpreted, `EXPOSE` port ranges (`21-23`) are not expanded (only a
  literal `22`/`22/tcp` token fires TL032), TL030 matches secret-looking
  variable **names** (it cannot judge values), and only the attached
  heredoc spelling (`<<EOF`, not `<< EOF`) is recognised. TL031 treats a
  base that shares a stage name - even a forward reference - as internal
  and stays silent, preferring a missed finding over a guessed one.
- Severity weights and grade boundaries are opinionated defaults, not an
  industry standard.
- Not a substitute for Checkov/tfsec/Trivy/OPA in production pipelines.

## Roadmap

Shipped in 1.0: cross-file resolution, SARIF output, inline `# themis:ignore`
comments, and a `.themis.yaml` policy (rule disable / severity override / path
exclude). Shipped in 1.1: precise source lines in every format (SARIF
`region.startLine`). Shipped in 1.2: Dockerfile checks (TL029-TL032 with
final-image stage attribution) and a property-based robustness suite. Still
on the list:

- A `--rules`/`--exclude-rules` CLI selector (policy `disable:` covers this
  from a file today).
- More rules: Azure/GCP Terraform equivalents, more Dockerfile checks
  (`ADD` of remote URLs, `--chmod` extremes, apt/apk cache hygiene).
- Optional `security-severity` tuning surfaced through policy.
- Accept `.iacscanner.yaml` and `# iacscanner:ignore` alongside the frozen
  `.themis.*` spellings (see *Naming and on-disk compatibility*), with the old
  names kept working and a test for each - a compatibility feature, not a
  rename.

## License

Proprietary source-available - see [LICENSE](LICENSE). Copyright (c) 2026
Leo Y. Zhang. All rights reserved. You may read the code and run it locally
(test suite included) to evaluate it; no other rights are granted.
