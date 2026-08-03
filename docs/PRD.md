# IaCScanner — product requirements

Written after the code, at v1.2.0, so it describes decisions that were actually
made and paid for rather than intentions. Where the code and an earlier claim
disagreed, the code won and the claim was corrected.
[TDD.md](TDD.md) · [ARCHITECTURE.md](ARCHITECTURE.md)

## Infrastructure-as-Code fails open

A Terraform bucket with `acl = "public-read"`. A Kubernetes pod with
`privileged: true`. A `pull_request_target` workflow that checks out the PR head.
Each is one plausible-looking line, each is exploitable, and none of them break
anything in review or in CI.

The mature answer is Checkov, tfsec or Trivy, and for a production pipeline that
remains the right answer. Two things those tools did not give the author, in his
situation:

**Something safe to point at a repository he did not trust.** The natural moment
to want a scanner is right after cloning unfamiliar infrastructure code — which
is exactly the moment when running a large tool with a plugin system, a
package-download step and cloud SDKs on the same machine is least attractive.

**Something that could be understood end to end.** A scanner is a trust-bearing
artefact: it decides what a reviewer is told about a file. A scanner nobody in
the room can read is a scanner nobody can audit.

## The wall of findings

A second problem showed up the moment the first version was pointed at an
existing tree. A new scanner on old code produces a wall of findings, all of them
historical, and **the wall is why the scanner gets turned off**.

Whatever shipped had to have an answer to that on day one rather than as a later
feature. That answer is the baseline: `--write-baseline` accepts the current
state, and `--baseline` thereafter fails CI only on genuinely new findings.

## The incident: the gate stayed green while the tree got worse

Which brings up the thing this project most needed to learn.

Until baseline schema 2, a finding's identity was `(rule_id, path, location)`.
Measured on `examples/vulnerable`, 39 findings collapsed into 37 fingerprints.
One collision was two CRITICALs on a single security group — world-open SSH and
world-open RDP. Baselining the first therefore suppressed the second, **including
a newly introduced one**.

That is the worst failure mode a gate has: it goes on reporting green while the
thing it guards degrades.

Fixed by adding a structural `sub_key` to the fingerprint — the port, the
property, the container. Schema-1 baselines are still honoured with their
original, coarser meaning rather than silently narrowed, because narrowing would
resurface findings a user had already reviewed and accepted.

## Requirements

**Must**

- Read-only. Open scanned files for reading; write only to a `--out` or
  `--write-baseline` path the user named.
- Offline. No sockets, no telemetry, no cloud SDK, no credential lookup.
- Never crash on input. A malformed, adversarial or absurdly nested file degrades
  to a `TL000` finding and exit 2.
- Bounded to the scan root. A symlink or NTFS junction inside the target must not
  make the tool read or report a file outside it.
- Deterministic output in every format.
- Stable finding identity, so baselines keep working across releases.
- A `--fail-on` threshold and meaningful exit codes, so it can gate CI.

**Should**

- SARIF 2.1.0 with source lines, for GitHub code scanning.
- CWE and CIS Controls v8 references, plus a **confidence** level separate from
  severity — "how likely is this real" is a different question from "how bad is
  it if it is".
- Cross-file reference resolution, so a bucket and its public-access block in
  different files are not a false positive.
- Two ways to accept a finding: a committed `.themis.yaml` policy for standing
  configuration, and an inline comment for a one-off.

**Not built.** The scanner does not evaluate HCL expressions, `for_each`/`count`,
modules or remote state. It never queries a cloud provider for live state. It
does not auto-fix or rewrite a scanned file, ever. And it ships no plugin system
for third-party rules.

## Read-only is the product

**No writing to scanned files.** No `--fix`, no formatting, no in-place edits. A
tool that is trusted *because* it is read-only cannot have a write mode bolted on
later; the guarantee is the product.

Five other things sit outside the boundary.

**Being a production scanner.** Coverage is 32 rules, mostly AWS-shaped
Terraform. Checkov has thousands. The README names the alternatives rather than
competing with them.

**Sandboxing hostile input of unbounded size.** The whole file is read into
memory and there is no size or time cap. Resource use is proportional to input,
and that is stated in the threat model rather than quietly hoped for.

**Parser-level DoS resistance for Terraform.** That ultimately belongs to
`python-hcl2` and `lark`. This tool contains the recursion error and rejects the
file; it does not sandbox the parser.

**Line-precise suppression.** Suppression is file-scoped. Findings are suppressed
before source lines are resolved — `scanner.scan` suppresses, then calls
`attach_lines` — so line-precise suppression is a pipeline change rather than a
flag. The policy file covers the cases that mattered.

**Secrets behind `var.*` / `local.*`.** TL018 flags literal values only. Flagging
a variable *reference* as a hardcoded secret is a false positive by construction.

## What a scan proves

- [x] `pip install -e .` then `iacscanner scan <dir>` works with **two** runtime
      dependencies (`python-hcl2`, `pyyaml`) — no daemon, no binary toolchain, no
      admin rights.
- [x] A scan of an untrusted tree makes **zero network calls** and reads **zero
      credentials**, verifiable by inspection: no `socket`, no `requests`, no
      cloud SDK anywhere in `src/`.
- [x] Every rule fires on a vulnerable fixture **and stays silent on the hardened
      counterpart**, proven by a test rather than by eyeball
      (`tests/test_rules_fixtures.py`; `examples/secure*` scans clean, exit 0).
- [x] Two runs over the same bytes produce **byte-identical** reports in every
      format — no timestamps, no run ids, no absolute paths, no ordering wobble
      (`tests/test_determinism.py`, `tests/test_stress.py`).
- [x] A hostile input never crashes the process; it becomes one `TL000` finding
      and exit code 2 (`tests/test_property_robustness.py`, Hypothesis,
      derandomised).
- [x] Adopting the scanner on an existing tree requires fixing nothing first.
- [x] A baseline written by an older release still suppresses exactly what it
      used to. `tests/data/baseline-1.0.0.json` is pinned and replayed —
      `39 finding(s) suppressed, 0 new`, exit 0 — and it survived the 1.0 → 1.1 →
      1.2 feature rounds and the Themis → IaCScanner rename.
- [x] Output uploads to GitHub code scanning as SARIF 2.1.0, with each annotation
      on the correct source line.

## Who it is for

The author, on his own repositories: the only person with the problem when the
project started, and the only user today - working with no Docker daemon and no
cloud credentials on the development machine, where a scanner that needs either
would simply never run.

And a reader assessing the author's engineering — an interviewer, a tutor, a
reviewer. This person never runs the tool. They read `rules/terraform.py`,
`baseline.py` and the tests, and form a judgement. They are a real user of this
repository, and the documentation is written for them too.

It is explicitly not for a team securing production infrastructure. The README
says so in its second paragraph, and that sentence is load-bearing rather than
modest.

## Reports leak what they describe

There is no personal data of the tool's own: no accounts, no database, no config
beyond a file the user writes, no network path off the machine. It does read
whatever the user points it at, which may be sensitive.

Only whoever can already read the scanned files and the report can see any of it,
and the relevant leak is *the report itself*, since findings quote short excerpts
of file content. Two mitigations are in the code: TL018 masks secret-looking
values to a short prefix, and every display path is relative to the scan target
with POSIX separators, so a committed report never embeds a local directory
layout or a username. Reports must be treated with the same care as the files
they describe, which the README says explicitly.

Access revocation has nothing to attach to — no accounts, no roles, no server —
so the useful question is the nearest real analogue, which is **removing a
suppression**. The design decision there is that removal must be *loud*. A
deleted `# themis:ignore` line resurfaces its findings. A malformed policy warns
on stderr and is ignored rather than silently applied. A typo'd rule id in a
suppression comment suppresses **nothing** and warns, instead of widening to
ignore-all. Every suppression path fails towards reporting more, never less.

The worst outcome, if any of this is wrong, is a false negative that lets someone
believe a tree is clean when it is not. That is why the honest scoping in the
README is a safety feature rather than marketing copy, why the `sub_key` defect
above was treated as serious, and why unresolved references are never guessed.

## What was ruled out, and what ruled it out

| Ruled out | What ruled it out |
| --- | --- |
| Wrap Checkov / tfsec / Trivy behind a nicer CLI | Inherits their install weight and their network/plugin surface, which is precisely what this tool exists to avoid — and it would demonstrate nothing. The README recommends them for production instead. |
| Evaluate HCL properly (`terraform plan`, module expansion, functions) | Needs the Terraform binary, usually credentials, usually network. It would trade the offline guarantee — the whole point — for accuracy on a minority of files. The regex resolver with an unresolved-as-literal firewall keeps the guarantee and can only ever *reduce* false positives. |
| Enrich findings from live cloud APIs | Requires credentials. Non-starter. |
| Include the message text in the finding fingerprint | Would freeze every message wording forever; retuning a sentence would invalidate every user's baseline. |
| Include the resolved source line in the fingerprint | Adding a blank line above a finding would resurface it as new. Lines are display metadata and marked `compare=False` on the dataclass. |
| Put a timestamp or run id in reports | Kills byte-identical output, and with it both the baseline workflow and the committed-sample drift tests. Reports would stop diffing cleanly in git. |
| Rename `.themis.yaml` / `# themis:ignore` / `"tool": "themis-baseline"` during the 2026-08 rename | Those are on-disk formats in working trees the tool does not control, not identity. Renaming would silently ignore an existing policy, resurrect every suppressed finding, and hard-fail every existing baseline. Frozen deliberately; accepting both spellings is on the roadmap as a tested feature. |
| Silently ignore a malformed policy file | A scan that quietly gets quieter is worse than one that fails. Every malformed key, unknown rule id and invalid severity emits a visible `warning:` on stderr. |
| Flag values omitted from a resource (insecure-by-default fields) | Would light up every brownfield repo on fields nobody chose. Rules fire only on an *explicit* misconfiguration. |

## Roadmap, not unknowns

Should `.iacscanner.yaml` and `# iacscanner:ignore` be accepted alongside the
frozen `.themis.*` spellings? Decided: yes, but as a feature with tests, not as
part of the rename.

Is per-rule `security-severity` tuning through the policy file worth the extra
surface, given that severity overrides already exist?
