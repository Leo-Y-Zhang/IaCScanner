# IaCScanner architecture

IaCScanner is a read-only static analyzer for Infrastructure-as-Code. This document
describes how a scan flows through the code and the invariants that keep its
output safe and byte-for-byte reproducible. For the user-facing feature list,
see the [README](../README.md); for upgrading from 0.x, see
[MIGRATION.md](MIGRATION.md). For *why* it is shaped this way — the problem,
the scope boundaries, the rejected alternatives, and the failure/rollback
analysis — see [PRD.md](PRD.md) and [TDD.md](TDD.md).

## The pipeline

```
target path
    |
    v
parsers.discover ----> a bounded, sorted list of ScanFile paths
    |                   (realpath-confined to the scan root; no symlink/junction escape)
    v
parsers.parse_file --> ScanFile{path, kind, data, text, error}
    |                   HCL via python-hcl2, YAML via safe_load_all, JSON via stdlib,
    |                   Dockerfiles via the stdlib-only parser in docker.py
    v
graph.ScanContext.build(files) --> ResourceGraph over ALL Terraform files
    |                              (resource/variable/local index + resolve())
    v
scanner.scan
    |  for each ScanFile, for each Rule:
    |     rule.check_ctx(sf, ctx)  if the rule is graph-aware (TL002/007/008)
    |     rule.check(sf)           otherwise
    |  stamp finding.confidence from the rule's metadata
    |  apply inline `# themis:ignore` suppressions (suppress.py)
    |  resolve each structural anchor to a source line (lines.py; metadata only)
    |  sort findings by (path, rule_id, location)
    v
ScanResult{target, files, findings, parse_error_count, inline_suppressed_count}
    |
    +--> policy.apply_policy      (.themis.yaml: disable / severity / exclude)   [cli.py]
    +--> --min-severity / --min-confidence filters                              [cli.py]
    +--> baseline.split_findings  (suppress known, report only new)             [cli.py]
    |
    v
report.render_text / render_json / render_markdown / render_stats
sarif.render_sarif
```

Parsing, graph construction, and rule evaluation live in `scanner.scan()` and
are pure functions of the file bytes. Everything downstream of `ScanResult`
(policy, filters, baseline, rendering) is orchestrated by `cli.py` so that the
library core stays free of argument-parsing and process concerns.

## Modules

| Module | Responsibility |
| --- | --- |
| `parsers.py` | File discovery (realpath-confined, symlink/junction-safe) and HCL/YAML/JSON/Dockerfile parsing. A parse failure becomes a `TL000` finding, never a crash. |
| `docker.py` | Stdlib-only, total multi-stage Dockerfile parser: escape-directive-aware Docker-faithful continuations (no separator inserted), BuildKit heredoc bodies consumed as content, pre-`FROM` `ARG` substitution for `FROM ${VAR}`, frozen dataclasses with 1-based source lines, and the shared `stage[<label>].<CMD>[<n>]` anchor builder used by both rules and the line resolver. |
| `graph.py` | The cross-file `ResourceGraph`, the `resolve()` reference resolver, `ResourceRef`, and the frozen `ScanContext`. |
| `models.py` | `Severity`, `Confidence`, `ScanFile`, `Rule`, `Finding` dataclasses and the finding sort key. |
| `metadata.py` | The curated per-rule CWE + CIS Controls v8 + default-confidence table. |
| `rules/` | Rule definitions grouped by domain (`terraform`, `kubernetes`, `actions`, `dockerfile`, `generic`) plus the registry (`RULES`, `ALL_RULES`, `get_rule`). The `dockerfile` pack (TL029-TL032) walks only the final-image stage chain. |
| `lines.py` | Structural-anchor -> source-line resolver: Terraform block start lines from the hcl2 lark tree, YAML node lines from a mark-capturing SafeLoader subclass, `line N` anchors directly. Ambiguous or unresolvable anchors omit the line; hostile input can never make it raise. |
| `scanner.py` | Orchestrates parse -> context -> rules -> confidence -> suppress -> resolve lines -> sort. |
| `scoring.py` | Severity weights, 0-100 risk score, letter grades. |
| `report.py` | Text / JSON / Markdown renderers and `render_stats`. |
| `sarif.py` | SARIF 2.1.0 renderer. |
| `policy.py` | `.themis.yaml` discovery, loading (with visible warnings), and application. |
| `suppress.py` | Inline `# themis:ignore` parsing. |
| `baseline.py` | Finding fingerprints and baseline write / load / suppress. |
| `cli.py` | The `scan` / `rules` subcommands, flag wiring, and exit codes. |

## The resource graph (crown jewel)

`graph.py` builds one immutable, read-only layer over every Terraform file in
the scan root:

- **Index.** Resources by address (`type.name`), plus `variable` and `local`
  values, first-definition-wins for determinism.
- **`resolve(value)`.** Substitutes `${var.x}` / `${local.y}` interpolations on
  the *raw string* using a regex (`_INTERP_RE`), not an HCL evaluator. It is
  depth-limited (`_MAX_DEPTH = 12`) and cycle-detected.
- **The false-positive firewall.** If a reference is unresolved, missing, or
  circular, `resolve()` returns the value **unchanged**. Consequently the
  resolver can only ever *reduce* false positives - it never fabricates a
  value that could make a rule fire.
- **`resolve_reference(value)`.** Parses `${type.name.attr}` into a
  `ResourceRef` so a companion resource (e.g. an
  `aws_s3_bucket_public_access_block` whose `bucket` points at a bucket) can be
  bound to its target across files.

Rules opt into the graph via a `check_ctx(sf, ctx)` hook (vs the plain
`check(sf)`); `scanner.scan()` builds the `ScanContext` once per scan and
routes each rule to the right entry point. Today TL002 / TL007 / TL008 are
graph-aware; the `_bucket_literal` / `_covers_bucket` helpers in
`rules/terraform.py` are the reusable binding pattern for future ones.

## Rules and metadata

A `Rule` is a frozen dataclass carrying its id, title, description, severity,
rationale, remediation, and either a `check` or a `check_ctx`. The registry in
`rules/__init__.py` attaches CWE / CIS / default-confidence from
`metadata.py` via `dataclasses.replace`, so the metadata lives in exactly one
reviewed place and a test asserts the table covers precisely the registered
rules.

Confidence is stamped centrally in the scanner (not inside each `check`),
because rule functions build findings from module-level `Rule` objects that do
not carry registry metadata. Confidence is part of the report and SARIF output
but deliberately **not** part of the finding fingerprint.

Rule-authoring discipline: every rule ships with both a secure and a
vulnerable fixture, fires only on an *explicit* misconfiguration, and stays
silent both on the secure value and on an omitted insecure default (so
brownfield code that never set the field is not flagged).

## Determinism invariants

Reproducible output is a hard requirement - it is what makes the baseline and
drift-test workflows possible. The invariants:

- **Sorted everywhere.** Files are discovered in sorted order; findings are
  sorted by `(path, rule_id, location)`; SARIF uses `sort_keys=True` and a
  fixed, sorted rule catalogue so `ruleIndex` is stable; `render_stats` sorts
  every group.
- **No wall-clock, no randomness.** No renderer or rule reads the clock or any
  random source. Nothing in the output varies run to run.
- **POSIX, relative paths only.** Display paths are relative to the scan target
  with `/` separators, so a report generated on Windows equals one generated on
  Linux and never embeds a local absolute path.
- **Additive model evolution.** New fields (confidence, CWE, CIS, and the
  resolved source line) are added with defaults and kept out of the
  fingerprint `(rule_id, path, location)`, so old baselines keep matching -
  a committed 1.0.0 baseline is regression-tested against exactly this.

These are enforced by `tests/test_determinism.py` (byte-identical renders
per format), `tests/test_stress.py` (byte-identical + sub-quadratic on a
200-300 file synthetic tree), and `tests/test_examples.py` (the committed
`sample-report.md` / `sample.sarif` must equal a fresh render).

## Safety invariants

- **Read-only.** IaCScanner opens scanned files only for reading and writes only to
  the `--out` / `--write-baseline` file you name.
- **Offline.** No sockets, no cloud SDKs, no telemetry, no credentials.
- **Bounded to the scan root.** Discovery resolves every path with
  `os.path.realpath` and requires it to stay within the root, pruning POSIX
  symlinks and Windows NTFS junctions alike, with a `seen`-set loop guard.
- **Safe parsing.** YAML uses SafeLoader construction only (`safe_load_all`
  for scanning; the line resolver's SafeLoader subclass merely records each
  mapping's line); HCL uses python-hcl2's grammar (no `eval`/`exec`);
  malformed or deeply-nested input degrades to a `TL000` finding instead of
  crashing, and any failure inside the line resolver omits the line rather
  than raising.

See the README's "Threat model" section for the full statement of what IaCScanner
does and does not defend against.
