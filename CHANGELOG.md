# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

Entries at and below `[1.2.0]` were written while the project was named
**Themis** and are left verbatim: they describe releases that really did ship
under that name, with those module paths. See *Unreleased* for the rename.

## [Unreleased]

### Security

- **`.gitleaks.toml` no longer allowlists whole directory trees.** The
  allowlist matched `^examples/` and `^tests/` by path, so a real credential
  committed anywhere under either tree would have passed this repository's own
  secret gate - the same config the CI gitleaks job consumes. Both path
  entries are removed; the allowlist is now value-scoped only (the two
  published fake literals), so `tests/` and `examples/` are scanned as
  strictly as `src/`. A full-history scan under the narrowed config reports no
  leaks.

### Fixed

- README's fingerprint stability contract described the pre-schema-2 **triple**
  `(rule_id, path, location)` and a `TL000`-`TL028` id range. The shipped
  fingerprint is the **quadruple** `(rule_id, path, location, sub_key)` and the
  shipped range is `TL000`-`TL032` (the `TL000` parse finding plus 32 rules).
  The same stale range in `baseline.py`'s module docstring (`TL000`-`TL018`)
  is corrected too.
- Quickstart commands were Windows-only (`.venv/Scripts/python.exe -m ...`).
  They now use the `iacscanner` console script, and the `python -m iacscanner`
  equivalence is stated before the examples instead of after them.

### Changed

- CI trigger comments state the technical rationale for the scoped triggers
  and for `workflow_dispatch` only.

- **Renamed the project from Themis to IaCScanner.** Everything that is
  identity moved: distribution name, import path (`themis.*` ->
  `iacscanner.*`), console script, `--version` string, text/markdown/JSON
  report headers, and the SARIF `tool.driver.name` / `informationUri`.
  `examples/sample-report.md` and `examples/sample.sarif` were regenerated;
  the diff is the tool-name strings and nothing else.

### Unchanged (deliberately)

- The auto-discovered policy filename `.themis.yaml`, the inline
  `# themis:ignore` directive, and the baseline header
  `"tool": "themis-baseline"` keep their old spelling. They are on-disk
  formats, not identity: renaming the policy filename would silently ignore an
  existing policy, renaming the ignore directive would resurrect every
  suppressed finding, and renaming the baseline tool string would make
  `load_baseline` reject every baseline ever written. Accepting both spellings
  is a feature with tests, listed on the roadmap, not part of a rename.
- Rule ids and finding fingerprints. A baseline written by Themis 1.0.0 still
  suppresses exactly what it did before; `tests/data/baseline-1.0.0.json`
  regression-tests that across the rename.

### Added

- `docs/PRD.md` and `docs/TDD.md`: the problem statement, the scope
  boundaries, and the architecture as built (data model, rule contract,
  failure modes, rollback).

## [1.2.0] - 2026-07-31

Dockerfile support. A stdlib-only multi-stage Dockerfile parser, four new
rules (TL029-TL032) that walk only the **final-image stage chain** - so
builder-stage `USER root`, floating toolchain tags, build-time ENV values
and builder `EXPOSE` lines never fire - and a derandomized Hypothesis
robustness suite mechanising the never-crashes threat model. The registry
grows from 28 to 32 rules; every existing baseline, fingerprint, fixture
and output contract is unchanged (the 1.0.0 baseline replay still reports
`39 finding(s) suppressed, 0 new` and exits 0, and the committed
`examples/sample.sarif` diff is exactly the four new reportingDescriptors
plus the tool version string).

### Added

- **Dockerfile discovery and parsing.** `Dockerfile`, `Containerfile`,
  `*.dockerfile`, and `Dockerfile.<variant>` / `Containerfile.<variant>`
  names (the `docker build -f Dockerfile.prod` convention) are discovered
  and parsed by a new stdlib-only parser (`themis.docker`): frozen
  dataclasses with 1-based source lines, multi-stage `FROM ... AS` chains,
  pre-`FROM` `ARG` defaults substituted into `FROM ${VAR}`, the
  `# escape=` directive, Docker-faithful line continuations (escape and
  newline removed, **no separator inserted**, so split arguments
  reassemble byte-for-byte), and BuildKit **heredocs** on RUN/COPY/ADD
  (`<<EOF`, `<<-EOF`, quoted delimiters, several per instruction,
  ONBUILD-wrapped forms) consumed as content - a `FROM` inside a heredoc
  body can never fabricate a phantom stage or a finding. The parser is
  total: hostile input degrades to fewer stages, never an exception.
  A variant name whose extension is another scanned kind keeps that kind
  (`Dockerfile.yaml` stays YAML).
- **Four Dockerfile rules, final-image scoped.** Each rule walks the final
  stage plus the internal stages it extends through `FROM <stage>`
  references (case-insensitive, like Docker) and attributes inherited
  findings with an `(inherited from stage '...')` suffix and a stable
  `stage[<label>].<CMD>[<n>]` anchor that resolves to a source line:
  **TL029** final image runs as root (high; silent when USER is omitted -
  the base default is unknown), **TL030** secret-looking literal ENV baked
  into the final image (high; the secret word must end the variable name,
  path-pointer and `$REF` values are silent), **TL031** final image built
  from a mutable/untagged external base (low; digest pins, `scratch`,
  stage refs and unresolved `${VAR}` are silent), **TL032** final image
  exposes SSH port 22/tcp (medium). Builder-stage-only decoys are covered
  by tests and by the new `examples/vulnerable-docker/` and
  `examples/secure-docker/` fixture pair (the secure Dockerfile keeps a
  deliberately root-running, `:latest`-based **builder** stage and scans
  100% clean).
- **Property-based robustness suite** (`tests/test_property_robustness.py`,
  new `hypothesis` dev dependency): totality, determinism, well-formedness
  and SARIF 2.1.0 validity of the Dockerfile parser, the TL029-TL032 pack,
  line attachment, suppression parsing and whole on-disk scans under
  adversarial text. Derandomized with no example database so the gate is
  reproducible on every machine.

### Fixed

- Adversarial review of the unreleased feature branch found BuildKit
  heredoc bodies being parsed as instructions (a `COPY <<EOF` block could
  fire all four Dockerfile rules on a clean image) and continuation
  joining inserting a space where Docker inserts nothing (a pinned tag
  split across lines misreported as untagged; a split ENV secret was
  missed). Both are fixed and regression-tested; the fixes landed before
  the feature was released, so no released behavior changed.

## [1.1.0] - 2026-07-30

Precise source lines. Every finding's structural anchor is now resolved to
the 1-based line of the structure it names, surfaced in every output format
and - crucially - kept **out** of the baseline fingerprint, so every
existing baseline file keeps working unchanged.

### Added

- **Structural-anchor-to-line resolver (`themis.lines`).** Terraform
  `type.name` / `variable.name` addresses map to their block start line
  (read from the python-hcl2 lark parse tree's position metadata);
  Kubernetes `Kind/name`, container, and volume anchors and workflow
  `jobs.<job>.steps[<i>]` anchors map to their YAML node lines (captured by
  a mark-recording `yaml.SafeLoader` subclass that changes nothing about
  what is constructed except remembering each mapping's line); `line N`
  text anchors (TL018, any file kind including JSON) parse directly.
  Resolution never guesses: an anchor produced by two structures on
  different lines (e.g. duplicate Terraform addresses or duplicate
  `Kind/name` documents) is ambiguous and the line is omitted, and any
  parse or traversal failure on hostile input omits lines rather than
  crashing - the scan-never-crashes promise extends to the resolver, with
  new adversarial tests (recursive/reused YAML aliases, deep nesting,
  megabyte single-line files, colliding anchor names).
- **Lines in every output.** Text reports gain a `LINE` column, JSON
  findings a `line` field (integer or null), Markdown a `Line` column, and
  SARIF results a `physicalLocation.region.startLine` - emitted only when
  the line is known (always >= 1), so GitHub code-scanning annotations land
  on the exact source line. All output remains deterministic and
  byte-identical across runs; unresolved lines render as `-` / `null` /
  an omitted region.
- **Cross-release baseline regression guard.** A committed
  `tests/data/baseline-1.0.0.json` (generated by themis 1.0.0 before line
  resolution existed) is verified to still suppress every finding on the
  vulnerable fixtures: the fingerprint stays exactly
  `(rule_id, path, location)` and line data never enters it.

### Fixed

- A Kubernetes workload document with a non-mapping `metadata` (hostile
  input) crashed the scan with an `AttributeError`; it now falls back to
  the `Kind/unnamed` label, honouring the threat-model promise that scans
  never crash on malformed input.
- README test count was stale (claimed 288; the 1.0.0 suite had already
  grown past that).

## [1.0.0] - 2026-07-09

The 1.0 release turns Themis from a hardened file-scoped linter into a
reference-resolving analysis engine you can wire into CI. Three headline
capabilities: a cross-file **resource graph**, **SARIF 2.1.0** output for
code-scanning UIs, and a declarative **policy + inline suppression** layer.
All existing CLI flags, exit codes, and baseline files keep working; the
finding fingerprint `(rule_id, path, location)` is unchanged, so baselines
recorded with 0.x still apply. See `docs/MIGRATION.md` for the details.

### Added

- **Cross-file resource graph (`themis.graph`).** A read-only, deterministic
  index of every Terraform resource, `variable`, and `local` across the whole
  scan root, with a `resolve()` that follows `${var.x}` / `${local.y}` /
  `${type.name.attr}` chains on the raw string (regex extraction, not HCL
  evaluation), depth-limited with cycle detection. Unresolved, missing, or
  circular references return the literal unchanged - the false-positive
  firewall. Rules opt in via a new `check_ctx(sf, ctx)` hook; the scanner
  builds the immutable `ScanContext` once per scan.
- **SARIF 2.1.0 output** (`--format sarif`). Emits a valid SARIF log with the
  full rule catalogue as `reportingDescriptor`s (level mapped from severity),
  results carrying `ruleIndex`, POSIX `physicalLocation` URIs, and
  confidence/CWE/CIS properties. Deterministic: no timestamps, sorted keys,
  fixed rule ordering so `ruleIndex` is stable, byte-identical across runs.
- **Declarative policy** (`.themis.yaml`, auto-discovered beside the target or
  `--policy FILE`): `disable:` rules, `severity:` overrides, and `exclude:`
  path globs. Unknown rule ids, invalid severities, and malformed files raise
  **visible** stderr warnings - policy never silently hides a finding.
- **Inline suppressions**: a `# themis:ignore` (all rules) or
  `# themis:ignore TL005,TL010` (specific) comment in an HCL/YAML file
  suppresses findings in that file. Suppression markers inside string literals
  are ignored; the scan reports an `inline_suppressed_count`.
- **CWE + CIS metadata and a Confidence level per finding.** A curated
  `metadata.py` table maps every rule to its CWE id(s), CIS Controls v8
  control(s), and a default confidence (low/medium/high). Surfaced in text
  (CONF column), JSON (`confidence`/`cwe_ids`/`cis_controls`), Markdown
  (Confidence column + References line), and SARIF. New `--min-confidence`
  filter mirrors `--min-severity`.
- **Nine new rules**, each CWE/CIS-cited and firing only on an explicit
  misconfiguration (silent on the secure value and on the omitted insecure
  default, so brownfield code is not flooded): **TL020** KMS key rotation
  disabled, **TL021** ECR scan-on-push disabled, **TL022** EFS not encrypted,
  **TL023** IMDSv2 not enforced (`http_tokens = "optional"`), **TL024**
  DynamoDB point-in-time recovery disabled, **TL025** RDS automated backups
  disabled (`backup_retention_period = 0`), **TL026** container/pod runs as
  root by UID (`runAsUser`/`fsGroup: 0`), **TL027** pod mounts the host
  filesystem or namespaces (`hostPath`/`hostPID`/`hostIPC`), **TL028** action
  pinned to a mutable branch (`@main`/`@master`, not a tag or SHA). The
  registry is now 28 rules (TL001-TL028) plus the TL000 parse pseudo-rule.
- Rule **TL019** (high): `aws_db_instance` / `aws_rds_cluster_instance` with
  `publicly_accessible = true`.
- `--stats`: a compact, deterministically-ordered scan summary (files by kind,
  findings by severity/confidence, counts by rule) written to stderr so it
  never contaminates a `--format json`/`sarif` report on stdout.
- Committed showcase artifacts `examples/sample-report.md` (Markdown) and
  `examples/sample.sarif`, regenerated from `examples/vulnerable`, with a
  drift test that fails if either goes stale.
- `docs/ARCHITECTURE.md` (pipeline + determinism invariants) and
  `docs/MIGRATION.md` (0.x -> 1.0).

### Changed

- **Cross-file accuracy for the S3 rules (finding-affecting, not CLI).**
  `TL002` (public access block), `TL007` (server-side encryption) and `TL008`
  (versioning/logging) now pair a bucket with its companion resources through
  the resource graph even when they live in different files, removing the
  old "file-scoped heuristic" false positives. A bucket whose only
  public-access-block sits in a separate file is no longer flagged; a
  genuinely missing companion still fires. Finding messages/locations for
  these three rules changed accordingly (reported on the bucket).
- Tooling: ruff (E/F/W/I/UP/B/C4/SIM) and mypy `--strict` are clean and run in
  CI alongside the determinism harness and the example-drift guard.

### Security

- Discovery no longer follows symlinks or reparse points. Every candidate
  directory/file is resolved with `os.path.realpath` and required to lie
  within the scan root (boundary-aware prefix check), and a `seen` set of
  visited real paths prevents loops. This prunes POSIX symlinks **and Windows
  NTFS directory junctions** (which `os.walk`/`is_symlink` do not flag),
  closing a gap on Python 3.10-3.12 where `rglob` followed symlinked
  directories by default. Behaviour is now identical across 3.10-3.13.
- README documents an explicit threat model: no code execution from input, no
  network/credentials, bounded-to-root discovery, graceful handling of
  malformed/deeply-nested parses and YAML anchor reuse, and linear-time
  (ReDoS-free) rule regexes.
- Pre-release adversarial review hardening of the new subsystems, each with a
  regression test: the resource graph no longer treats a `module`/`data`/
  `each`/`count` reference as a resource address (so a bucket whose companion
  binds through a module output or data source is not falsely flagged - the
  false-positive firewall holds); inline `# themis:ignore` detection is now
  escape-aware (a marker after a `\"`-escaped quote stays inside the string and
  cannot silently hide a finding); a typo'd inline rule id warns and suppresses
  nothing instead of silently widening to ignore-all; policy `exclude` globs
  use case-sensitive matching so the same policy hides the same findings on
  Windows and Linux; and policy discovery is confined to the scan target (no
  current-directory fallback) with the applied policy path printed to stderr.

## [0.2.0] - 2026-07-07

### Added

- Baseline workflow for CI adoption on legacy trees:
  `themis scan PATH --write-baseline baseline.json` records the
  fingerprints of all currently reported findings, and
  `themis scan PATH --baseline baseline.json` suppresses exactly those
  findings, reports only NEW ones, and gates the exit code on new
  findings only. Combining both flags refreshes a baseline in one run.
- Documented fingerprint stability contract: a fingerprint is the triple
  (rule_id, path, location); message and severity are deliberately
  excluded so wording/severity tuning never invalidates a baseline.
  Baseline files are deterministic (sorted, de-duplicated JSON) and
  diff cleanly in git.
- Malformed, missing, or unwritable baseline files exit 2 with a clear
  error; parse errors keep exit code 2 regardless of any baseline.
- 32 new tests (142 total): fingerprint semantics, write/load
  round-trip, determinism, suppression, new-finding detection when a
  tree worsens, min-severity interaction, refresh flow, malformed
  baseline handling, and CLI end-to-end subprocess runs.
- gitleaks secret-scanning job in CI (gitleaks/gitleaks-action@v2).
- `.gitleaks.toml` allowlist covering only the documented synthetic
  example/test secrets (scoped to `examples/`, `tests/`, and the
  specific fake values); no detection rule is disabled.

## [0.1.0] - 2026-07-06

### Added

- Initial release of Themis, a defensive, local, read-only IaC
  misconfiguration scanner.
- 18 built-in rules (TL001-TL018) covering AWS-style Terraform,
  Kubernetes manifests, GitHub Actions workflows, and generic
  hardcoded-credential patterns, plus the TL000 parse-warning pseudo-rule.
- Parsers: Terraform HCL (python-hcl2), YAML (yaml.safe_load_all only),
  JSON (stdlib). Per-file parse errors become warning findings instead
  of crashes.
- Severity-weighted risk scoring (0-100) with letter grades A-F and a
  documented formula, per file and overall.
- Output formats: plain-text table, JSON, and Markdown, with optional
  --out FILE.
- CLI: `themis scan PATH` and `themis rules`, also runnable as
  `python -m themis`. Exit codes: 0 clean, 1 findings at/above
  --fail-on (default high), 2 usage or parse errors.
- Paired vulnerable/secure example fixtures (all synthetic data) and a
  committed generated sample report.
- Test suite covering every rule against both fixture sets, scoring
  math, parse-error handling, severity filtering, exit codes, JSON
  validity, and an end-to-end CLI run.
