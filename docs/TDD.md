# IaCScanner — technical design

Derived from the code at v1.2.0. Where it and the README disagreed while this
was being written, the code won and the README was corrected — the test count,
and the claim that only `--min-severity` applies before baseline writing, since
`--min-confidence` does too.

The pipeline diagram and the module table live in
[ARCHITECTURE.md](ARCHITECTURE.md); this document covers the decisions behind
them. Requirements: [PRD.md](PRD.md).

## A scan is a pure function, and a resolver that can only subtract

**A scan is a pure function of file bytes, wrapped in a thin process shell.**
`scanner.scan(target) -> ScanResult` discovers files, parses each into a
`ScanFile`, builds one immutable `ScanContext` over all of them, runs every
applicable `Rule`, stamps confidence, applies inline suppressions, resolves
source lines, and sorts. Nothing in that path reads the clock, a random source,
an environment variable, or a socket. Everything that *is* a process concern —
argument parsing, the policy file, severity and confidence filters, the baseline,
choosing a renderer, exit codes — lives in `cli.py`, downstream of `ScanResult`.

That split is why the same `ScanResult` can be rendered four ways and compared
byte-for-byte in tests, why the baseline and drift-test workflows are possible at
all, and why the library is usable without the CLI.

**The unresolved-as-literal firewall in `graph.py`.** Cross-file reference
resolution exists to remove false positives — a bucket and its
`aws_s3_bucket_public_access_block` in different files. Every failure path
(missing variable, cycle, depth cap, function call, a reserved head like `data.`
or `module.`) returns the value *unchanged*, as the literal `${...}`.

A resolver that can only ever return a real literal or the original text can only
ever make a rule *stop* firing. It can never manufacture a finding.

## Filesystem scope is the real trust boundary

There is no access control at all — no accounts, no roles, no server, no
database, no network listener — and anyone who can run the binary can already
read the files it reads. What does need enforcing is containment, in
`parsers.discover`.

Before descending into a directory or accepting a file, its `os.path.realpath`
must lie within `realpath(scan_root)`, checked with a boundary-aware `os.sep`
prefix test (`_within`) so that `/a/root` does not contain `/a/root-sibling`.

That single check catches POSIX symlinks, **Windows NTFS directory junctions**
(`mklink /J`, which needs no admin rights and which `os.walk` and `is_symlink` do
*not* flag), and any other reparse point. A hostile repository cannot make the
scanner read or report a file outside the target.

A `seen` set of visited directory real paths is the loop guard: a
self-referential junction is pruned the moment its real path, or an ancestor's,
repeats, so runaway recursion is structurally impossible. Symlinked *files*
inside the root are skipped outright as aliases.

The realpath approach is deliberately independent of link type and of Python
version. `os.walk(followlinks=False)` declines POSIX symlinks but not junctions,
and `rglob` only stopped following symlinks by default in 3.13. One check covers
all of them everywhere.

The second boundary is parsing. YAML uses SafeLoader construction only —
`yaml.safe_load_all` for scanning, and a `SafeLoader` subclass in the line
resolver whose sole change is recording each mapping's source line, so still no
object instantiation. HCL goes through `python-hcl2`'s Lark grammar, and the code
never imports `hcl2.query`, so it never reaches that expression evaluator. JSON
is stdlib. **No input path reaches `eval`, `exec` or `yaml.load`.**

## The dataclasses, and the field that matters

No database. The model is five frozen-or-near-frozen dataclasses in `models.py`;
the only persisted artefacts are the two on-disk formats below.

| Type | Fields | Notes |
| --- | --- | --- |
| `Severity` | `LOW MEDIUM HIGH CRITICAL` | `str` enum with `.rank` (ordering) and `.weight` (3/7/15/25). |
| `Confidence` | `LOW MEDIUM HIGH` | Deliberately separate from severity: *how likely is this real* is not *how bad if it is*. Filterable independently via `--min-confidence`. |
| `ScanFile` | `path, kind, data, text, error` | `path` is **always** relative to the scan target with POSIX separators, never absolute. `error` non-`None` means the file failed to parse; `data` is then `None` and `text` may be empty. |
| `Finding` | `rule_id, severity, path, location, message, confidence, line, sub_key` | Frozen. `line: int \| None` is `field(compare=False)` — display metadata, never identity. |
| `Rule` | `id, title, severity, description, rationale, remediation, kinds, check, check_ctx, cwe_ids, cis_controls, default_confidence` | Frozen. `check` and `check_ctx` are `compare=False`. Exactly one of them is set, except for `TL000`, which has neither. |

The field that matters is `sub_key`. A finding's identity is
`(rule_id, path, location, sub_key)`, and `sub_key` distinguishes findings a rule
emits for the *same* location — the port (`"SSH"`), the property
(`"versioning"`), the host namespace (`"hostPID"`). It is empty for rules that
emit at most one finding per location. It exists because of a measured defect,
described in the failure-mode table. It must stay structural and stable, and
never a slice of the message, because message wording is deliberately outside
identity so it can be retuned.

Two fields are legacy-nullable, and both reach real users. `Finding.line` is
`None` for any anchor the resolver could not map unambiguously, so consumers of
the JSON report must handle `"line": null`; the SARIF renderer omits `region`
entirely rather than emitting a guess. And a baseline entry written under schema
1 has **no** `sub_key` — `load_baseline` substitutes the sentinel
`ANY_SUB_KEY = "\x00any"`, a value no rule can produce, and `split_findings`
treats it as matching every sibling at that location. That is the pre-`sub_key`
meaning, preserved on purpose.

Confidence is stamped centrally, in `scanner.scan`, from `metadata.py`, not
inside each `check`. Rule functions build findings from module-level `Rule`
objects constructed before the registry attached metadata, so a rule-local stamp
would read a default and be wrong. One source of truth, and a test asserts the
metadata table covers exactly the registered rule ids.

## Interfaces

```python
scanner.scan(target: Path) -> ScanResult
graph.ScanContext.build(files: tuple[ScanFile, ...]) -> ScanContext
graph.ResourceGraph.resolve(value: Any) -> Any            # literal, or input unchanged
graph.ResourceGraph.resolve_reference(value) -> ResourceRef | None
baseline.fingerprint(f: Finding) -> (str, str, str, str)
baseline.write_baseline(path, findings) -> None
baseline.load_baseline(path) -> set[Fingerprint]          # raises BaselineError only
baseline.split_findings(findings, baseline) -> (new, suppressed)
policy.load_policy(path) -> (Policy, list[str])           # never raises
policy.apply_policy(findings, policy) -> (kept, suppressed_count)
suppress.parse_suppressions_with_warnings(text) -> (Suppression, list[str])
report.render_text | render_json | render_markdown | render_stats
sarif.render_sarif(result, findings) -> str
```

They share one contract: **total on hostile input**. `load_policy` returns an
empty policy plus warnings rather than raising. `parse_file` returns a `ScanFile`
with `error` set rather than raising. `attach_lines` omits a line rather than
raising. `load_baseline` is the deliberate exception — it raises `BaselineError`,
because a broken gate file must fail the run rather than be silently treated as
empty.

A rule supplies `check(sf) -> list[Finding]`, or `check_ctx(sf, ctx)` if it needs
the whole scan. `Rule.finding()` builds the `Finding`, so no check has to know
about confidence or fingerprint bookkeeping. The authoring discipline, enforced
by tests: fire on the vulnerable fixture, stay silent on the hardened one, and
fire only on an **explicit** misconfiguration — never on an omitted field, or
every brownfield repo lights up on defaults nobody chose.

The CLI is two subcommands, non-interactive, no prompts, no TTY detection:
`iacscanner scan PATH [--format text|json|markdown|sarif] [--min-severity]
[--min-confidence] [--fail-on] [--policy FILE] [--baseline FILE]
[--write-baseline FILE] [--out FILE] [--stats]`, and `iacscanner rules`.

The report goes to stdout, or to `--out`. *Everything else* — policy notices,
suppression counts, baseline counts, warnings, `--stats` — goes to stderr, which
is what makes `iacscanner scan x --format json > r.json` produce a valid JSON
document even when the scan had six warnings to report.

Exit codes: `0` clean, `1` a reported finding at or above `--fail-on` (default
`high`), `2` usage error, missing path, malformed or unwritable baseline, or any
parse failure. **2 takes precedence over 1** — an unreadable tree must never be
reported as a passing one. A successful `--write-baseline` run exits 0, since
everything it recorded is accepted by definition, but parse errors still exit 2
even then.

Ordering inside `_run_scan` is a contract rather than an accident: inline
suppression (inside `scan`) → policy → `--min-severity`/`--min-confidence` →
`--write-baseline` → `--baseline` split → render. `--write-baseline` runs
*before* the baseline split, so `--baseline X --write-baseline X` refreshes in
one pass — fixed findings drop out, new ones are accepted.

## Format versioning

No database migrations. Two on-disk formats written into files the tool does not
control, with the same one-way-door property.

| Format | Version | Change | Reversible? | Compatibility rule |
| --- | --- | --- | --- | --- |
| Baseline JSON | 1 | `(rule_id, path, location)` | — | original |
| Baseline JSON | 2 | added `sub_key` | **No** — v2 files are rejected by any release that predates schema 2 | v1 files are still **accepted** and keep their original coarser meaning via `ANY_SUB_KEY`, never silently narrowed |
| Policy YAML | unversioned | `disable` / `severity` / `exclude` | n/a | unknown keys warn and are ignored; the file is additive-only by construction |

Reading a v1 baseline *narrowly* would have been the tempting choice, and it is
more correct. It was rejected, because narrowing resurfaces findings a user has
already reviewed and accepted — exactly the wall-of-findings failure the baseline
exists to prevent. Correctness that surprises a user into turning the gate off is
not correctness.

Three names are frozen at their pre-rename spelling — `.themis.yaml`,
`# themis:ignore`, and `"tool": "themis-baseline"` — because they are file
formats rather than identity. `load_baseline` *validates* the tool string, so
renaming it would hard-fail every baseline ever written.

## What breaks, and how it surfaces

| What breaks | Who notices | How we detect it | How we undo it |
| --- | --- | --- | --- |
| A scanned file has a syntax error | the user | one `TL000` finding, exit 2; the scan completes for every other file | fix the file; nothing to undo, the failure is contained by design |
| Deeply nested YAML/JSON/HCL exhausts the recursion limit | the user | `parse_file` catches `Exception` broadly → `TL000`, exit 2 | contained; covered by `test_property_robustness.py` |
| A `# themis:ignore` rule id is typo'd (`TL01`, `TL9999`) | the user | `warning:` on stderr, and it suppresses **nothing** | fails closed on purpose — a typo must never widen to ignore-all |
| A policy file is malformed | the user | `warning:` on stderr per problem; the policy is ignored, the scan still runs | a scan that quietly gets quieter is worse than a noisy one |
| A baseline file is malformed | CI | `BaselineError` → `error:` on stderr, exit 2 | fails closed: a broken gate file must never read as an empty baseline |
| A hostile symlink or junction points outside the tree | nobody, silently | it cannot happen — realpath containment plus the `seen` loop guard prune it before any read | |
| **Siblings sharing a fingerprint** — two CRITICALs on one security group (world-open SSH, world-open RDP) | **nobody** | it *did* happen: one baselined entry suppressed the other, including a newly added one, so the gate stayed green while the tree got worse | fixed by `sub_key` in schema 2; regenerate the baseline to get the precise identity |
| A committed sample drifts from what the code renders | CI | `tests/test_examples.py` diffs `sample-report.md` / `sample.sarif` against a fresh render | regenerate with the two documented commands; this fired, correctly, during the rename |
| A new `ruff` or `mypy` release adds a check | CI, on a random day | red CI on an unchanged commit | **Live gap.** The `dev` extra pins neither, so a new linter release can move CI's verdict with no code change. Recorded here rather than fixed inside a documentation-only change. |

## Undoing a version

The code is trivially reversible: no server, no database, no deployment.
`pip install "iacscanner==<previous>"`, or `git revert` the commit. Seconds.
`.github/workflows/ci.yml` is the only CI surface and it is version-controlled
with everything else.

Two things are not reversible, and both are on-disk state.

**A schema-2 baseline cannot be read by a pre-schema-2 release.** Downgrade after
writing one and every run exits 2 with `unsupported schema_version 2`. The undo
is to regenerate the baseline with the downgraded version, which loses `sub_key`
precision — exactly the defect schema 2 fixed. Acceptable because it fails
**loudly and closed**: nothing is silently mis-suppressed, the operator is told
precisely what is wrong, and the fix is one documented command.

**A pip-installed console script changed name in the rename.** Rolling the rename
back means reinstalling, since `python -m iacscanner` and `iacscanner` would stop
resolving. This is why the three on-disk names were frozen: the *files* users
wrote survive a rollback in either direction untouched.

And one thing can never be undone at all — a false negative already believed.
There is no technical rollback for a scan that said "clean" about a tree that was
not. That asymmetry is why unresolved references are returned as literals, why
rules do not fire on omitted fields, and why the README states its coverage
limits instead of implying completeness.

## 417 tests, and the two skips that differ by platform

417 tests. `ruff check .` clean, and `mypy src/iacscanner` clean under
`strict = true` from `pyproject.toml`. **415 passed, 2 skipped** on either
platform — and the two skips are not the same two. The real-symlink tests skip on
Windows without the symlink-creation privilege; the real-NTFS-junction tests skip
anywhere that is not Windows.

**Positive — legitimate use still works, proving we did not over-flag.**
`test_rules_fixtures.py` asserts every one of the 32 rules is *silent* on
`examples/secure*`, parametrised per rule so a new rule cannot be merged with only
a vulnerable fixture. `test_graph.py` and `test_graph_rules.py` assert that a
bucket whose public-access block lives in another file does not fire TL002.

**Negative — the thing we prevent is prevented.** `test_rules_fixtures.py`
asserts every rule *does* fire on `examples/vulnerable*`. `test_parsers.py`
asserts that a directory whose real path escapes the scan root is pruned and that
a self-referential one does not loop — proved twice over, once with POSIX
symlinks and once with a **real** `mklink /J` NTFS junction
(`test_discover_real_junction_does_not_escape_root`,
`test_discover_real_self_junction_does_not_loop`). The redundancy is deliberate:
the junction pair needs no privilege and runs on Windows, where the symlink pair
skips, and the symlink pair runs on Linux CI, where the junction pair skips. On
whichever platform you are, the containment claim is exercised by a real link
rather than a mock. `test_suppress.py` asserts a `# themis:ignore` marker inside
a string literal is not honoured and that a typo'd id suppresses nothing and
warns. `test_policy.py` asserts unknown keys, unknown rule ids and invalid
severities warn and are ignored rather than silently applied.

**Boundary — legacy, null, missing.** `tests/data/baseline-1.0.0.json` is a
pinned schema-1 baseline, written by the 1.0.0 release before line resolution or
`sub_key` existed, and it must still suppress everything the current code finds:
`39 suppressed, 0 new`, exit 0. That is the single most valuable test in the
suite — the compatibility promise, mechanised — and it survived three feature
rounds and a rename. `test_baseline.py` asserts malformed baselines (wrong tool
string, unsupported version, non-list findings, non-string fields) each raise
`BaselineError`. `test_lines.py` asserts ambiguous and unresolvable anchors yield
`line=None` rather than a guess.

**Whole-system invariants.** `test_determinism.py` for byte-identical renders per
format across runs. `test_stress.py` for byte-identical and sub-quadratic
behaviour on a 200–300 file synthetic tree. `test_examples.py` for the committed
samples equalling a fresh render. And `test_property_robustness.py`, derandomised
Hypothesis feeding adversarial text through the Dockerfile parser, rules, line
attachment, suppression, SARIF rendering and whole scans — its assertion is
*never raises*, which is the threat model expressed as a test.

## From a flat linter to a cross-file graph

**0.x** — models, parsers, a flat rule list, text output. A file-scoped linter
with a self-documented weakness: TL002, TL007 and TL008 could not see across
files and produced false positives.

**1.0** — the `ResourceGraph` and `resolve()`, killing that weakness without a
noisy rule; SARIF 2.1.0; CWE, CIS and confidence metadata; the policy file;
inline suppressions; the baseline workflow.

**1.1** — `lines.py`, resolving structural anchors to source lines, added as
display metadata only and deliberately outside the fingerprint. The pinned 1.0.0
baseline replay is what proved that claim.

**1.2** — the stdlib-only multi-stage Dockerfile parser and TL029–TL032 with
final-image stage attribution, plus the Hypothesis suite. Adversarial review
caught three real defects before release: BuildKit heredoc bodies fabricating
phantom stages (2 false HIGHs on a clean image), continuations joined with an
inserted separator, and `Dockerfile.<variant>` names never discovered.

**Post-1.2** — `sub_key` (the fingerprint-collision fix, baseline schema 2), CI
job timeouts, and the Themis → IaCScanner rename with these documents.

## Why there is no App Flow and no Design Brief

Both are judgements rather than oversights, so they are written down here.

There is no App Flow because there are no screens and no states to move between.
The whole surface is a two-verb argparse CLI — `scan`, `rules` — that runs once,
writes to stdout or `--out`, and exits with a code. Its complete behaviour is a
table of flags, four exit codes and four renderers, all specified exactly in
*Interfaces* above and pinned by the byte-for-byte drift tests over
`examples/sample-report.md` and `examples/sample.sarif`. A flow document would
restate that table in prose and then drift out of step with the tests, which is
worse than not having one.

There is no Design Brief for the same reason in a different form. The output is
plain ASCII on a terminal, deliberately: no colour, no progress spinner, no
Unicode box drawing, because it has to survive a pipe, a CI log and an `--out`
file byte-identically. That constraint is one sentence long and is already in the
PRD. A separate brief would be a page of styling decisions for a program that has
made one.

If either surface ever grows — a TUI, a watch mode, an HTML report — the matching
document gets written before the code, not after.

## Known gaps

**Unpinned `ruff` and `mypy` in the `dev` extra** is a live gap: a new linter
release can fail CI on an unchanged commit. Pinning them is a one-line change to
`pyproject.toml` that will move CI's verdict, so it belongs in its own commit
with its own CI run rather than inside a documentation change.

**Line-precise suppression** would require moving `attach_lines` ahead of
suppression in `scanner.scan`. Cheap to do, but it changes what a suppression
*means*, so it needs a compatibility story first.

**Whether `resolve()`'s depth cap of 12** is ever hit by real Terraform, or is
simply a safety net that never fires. Nobody has measured it.
