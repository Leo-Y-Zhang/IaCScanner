"""Deterministic, stdlib-only Dockerfile model and parser.

Total by construction: ``parse_dockerfile`` accepts arbitrary attacker-
controlled text and never raises. Lines it cannot read as instructions are
skipped (leniency is the false-positive firewall here - garbage produces no
stages, and no stages means no findings). The model is frozen dataclasses
with source line numbers, so rules and the line resolver share one parse.

Multi-stage structure is first-class: each ``FROM`` starts a :class:`Stage`,
``ARG`` defaults before the first ``FROM`` are collected for ``FROM ${VAR}``
substitution, and helpers expose the stable structural anchors
(``stage[<label>].<CMD>[<n>]``) used in finding locations.

Parser behavior intentionally mirrors Docker where it matters for analysis:

* the ``# escape=`` parser directive switches the continuation character;
* a line whose trailing run of escape characters has odd length continues
  onto the next line (``\\\\`` is an escaped backslash, not a continuation);
* continued lines are joined the way Docker joins them - the escape
  character and the newline are removed and NO separator is inserted - so
  arguments split across lines reassemble byte-for-byte;
* comment and blank lines inside a continuation are skipped;
* BuildKit heredoc bodies on RUN/COPY/ADD (``<<EOF``, ``<<-EOF``, quoted
  delimiters, several per instruction, ONBUILD-wrapped forms) are consumed
  as content, never as instructions; an unterminated heredoc swallows the
  rest of the file (silence, not findings). Only the attached ``<<NAME``
  spelling is recognised, at word start, so shell shifts like
  ``$((1<<8))`` are not mistaken for heredocs;
* instruction keywords are case-insensitive;
* stage name references are case-insensitive.
"""
from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass

_DIRECTIVE_RE = re.compile(r"^\s*#\s*([A-Za-z][A-Za-z0-9]*)\s*=\s*(\S+)\s*$")
_INSTRUCTION_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_]*)(?:\s+(.*))?$", re.DOTALL)
_SUB_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)")
# One ENV token: runs of quoted/unquoted chunks, so ENV MSG="a b" stays one token.
_ENV_TOKEN_RE = re.compile(r"(?:[^\s\"']|\"[^\"]*\"|'[^']*')+")
# A BuildKit heredoc marker at word start: <<EOF, <<-EOF, <<"EOF", <<'EOF'.
_HEREDOC_RE = re.compile(
    r"(?:^|\s)<<(-?)(?:\"([A-Za-z0-9_.-]+)\"|'([A-Za-z0-9_.-]+)'|([A-Za-z0-9_.-]+))"
)
_HEREDOC_CMDS = frozenset({"RUN", "COPY", "ADD"})
# Variant names (Dockerfile.prod) stay Dockerfiles unless the extension
# already belongs to another scanned kind (so Dockerfile.yaml stays YAML).
_OTHER_KIND_SUFFIXES = (".tf", ".yaml", ".yml", ".json")


def is_dockerfile_name(name: str) -> bool:
    """True when *name* is conventionally a Dockerfile (or Containerfile).

    Accepts the exact names, the ``*.dockerfile`` extension, and the
    ``docker build -f Dockerfile.<variant>`` convention (``Dockerfile.prod``,
    ``Containerfile.dev``) - except when the trailing extension names
    another scanned kind, which keeps that kind.
    """
    low = name.lower()
    if low in ("dockerfile", "containerfile") or low.endswith(".dockerfile"):
        return True
    stem = low.split(".", 1)[0]
    if "." in low and stem in ("dockerfile", "containerfile"):
        return not low.endswith(_OTHER_KIND_SUFFIXES)
    return False


@dataclass(frozen=True)
class Instruction:
    """One instruction: upper-cased keyword, raw argument text, 1-based start line.

    Continued lines are joined the way Docker joins them: the escape
    character and the newline are removed and nothing is inserted, so a
    ``FROM`` ref or ``ENV`` value split across lines reassembles exactly.
    Trailing whitespace per physical line is dropped; token boundaries are
    unaffected.
    """

    cmd: str
    args: str
    line: int


@dataclass(frozen=True)
class Stage:
    """One build stage: the ``FROM`` header plus the instructions after it."""

    index: int
    name: str | None
    base: str
    line: int
    instructions: tuple[Instruction, ...]


@dataclass(frozen=True)
class DockerfileModel:
    """A parsed Dockerfile: its stages plus pre-FROM ARG defaults."""

    stages: tuple[Stage, ...]
    global_args: tuple[tuple[str, str], ...]


def stage_label(stage: Stage) -> str:
    """The stable label used in anchors: the stage name, else its index."""
    return stage.name if stage.name is not None else str(stage.index)


def from_anchor(stage: Stage) -> str:
    """Structural anchor for a stage's FROM header."""
    return f"stage[{stage_label(stage)}].FROM"


def instruction_anchors(stage: Stage) -> tuple[str, ...]:
    """Anchors aligned with ``stage.instructions``: ``stage[<label>].<CMD>[<n>]``.

    ``<n>`` counts occurrences of the same keyword within the stage, so the
    anchor survives unrelated edits elsewhere in the file. Rules and the line
    resolver both use this single implementation, so anchors cannot drift.
    """
    counts: dict[str, int] = {}
    label = stage_label(stage)
    anchors: list[str] = []
    for instruction in stage.instructions:
        n = counts.get(instruction.cmd, 0)
        counts[instruction.cmd] = n + 1
        anchors.append(f"stage[{label}].{instruction.cmd}[{n}]")
    return tuple(anchors)


def substitute(value: str, args: Mapping[str, str]) -> str | None:
    """Resolve ``$VAR``/``${VAR}`` in *value* from *args*, or None if unresolved.

    Anything fancier than a plain reference (``${VAR:-default}``, unknown
    names, values that themselves contain ``$``) resolves to None: unresolved
    means silent, never a guessed finding.
    """
    if "$" not in value:
        return value
    unresolved = "\x00"

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return args.get(name, unresolved)

    resolved = _SUB_RE.sub(_replace, value)
    if unresolved in resolved or "$" in resolved:
        return None
    return resolved


def env_pairs(args: str) -> tuple[tuple[str, str], ...]:
    """The (key, value) assignments of an ENV instruction's argument text.

    Handles both forms: ``ENV key=value key2="v 2"`` and the legacy
    ``ENV key value with spaces``. Values keep one level of matching quotes
    stripped. Malformed input yields fewer pairs, never an error.
    """
    text = args.strip()
    if not text:
        return ()
    first = text.split(None, 1)[0]
    if "=" not in first:
        rest = text[len(first):].strip()
        return ((first, _unquote(rest)),)
    pairs: list[tuple[str, str]] = []
    for token in _ENV_TOKEN_RE.findall(text):
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key:
            pairs.append((key, _unquote(value)))
    return tuple(pairs)


def parse_dockerfile(text: str) -> DockerfileModel:
    """Parse *text* into a :class:`DockerfileModel`. Never raises."""
    lines = text.splitlines()
    escape = _escape_char(lines)
    stages: list[Stage] = []
    current: _StageBuilder | None = None
    global_args: dict[str, str] = {}

    for cmd, args, line in _logical_lines(lines, escape):
        if cmd == "FROM":
            if current is not None:
                stages.append(current.build())
            base, name = _parse_from(args)
            current = _StageBuilder(index=len(stages), name=name, base=base, line=line)
        elif current is not None:
            current.instructions.append(Instruction(cmd=cmd, args=args, line=line))
        elif cmd == "ARG":
            # Pre-FROM ARG defaults feed `FROM ${VAR}` substitution.
            for token in args.split():
                name, sep, value = token.partition("=")
                if sep and name:
                    global_args[name] = _unquote(value)
    if current is not None:
        stages.append(current.build())
    return DockerfileModel(
        stages=tuple(stages), global_args=tuple(sorted(global_args.items()))
    )


class _StageBuilder:
    """Mutable accumulator for one stage while parsing."""

    def __init__(self, index: int, name: str | None, base: str, line: int) -> None:
        self.index = index
        self.name = name
        self.base = base
        self.line = line
        self.instructions: list[Instruction] = []

    def build(self) -> Stage:
        return Stage(
            index=self.index,
            name=self.name,
            base=self.base,
            line=self.line,
            instructions=tuple(self.instructions),
        )


def _escape_char(lines: list[str]) -> str:
    """The continuation character: ``\\`` unless a top ``# escape=`` says backtick.

    Directive parsing stops at the first line that is not a parser directive,
    matching Docker (which also treats later directive-looking comments as
    plain comments).
    """
    for line in lines:
        match = _DIRECTIVE_RE.match(line)
        if match is None:
            break
        if match.group(1).lower() == "escape":
            return "`" if match.group(2) == "`" else "\\"
    return "\\"


def _logical_lines(lines: list[str], escape: str) -> Iterator[tuple[str, str, int]]:
    """Yield (CMD, args, 1-based start line) for each instruction.

    After a RUN/COPY/ADD (or ONBUILD-wrapped) instruction that opens
    heredocs, the body lines up to each terminator are consumed as content:
    they are never instructions, and continuation/comment handling does not
    apply inside them (heredoc bodies are literal, as in BuildKit).
    """
    i = 0
    total = len(lines)
    while i < total:
        stripped = lines[i].strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue
        start = i + 1
        parts: list[str] = []
        continuing = True
        while i < total and continuing:
            segment = lines[i].rstrip()
            body = segment.lstrip()
            if parts and (not body or body.startswith("#")):
                i += 1  # comment or blank inside a continuation
                continue
            trailing = _trailing_escapes(segment, escape)
            continuing = trailing % 2 == 1
            if continuing:
                segment = segment[:-1]
            parts.append(segment)
            i += 1
        logical = "".join(parts).strip()
        match = _INSTRUCTION_RE.match(logical)
        if match is None:
            continue  # not an instruction; skip, never fail
        cmd = match.group(1).upper()
        args = (match.group(2) or "").strip()
        yield cmd, args, start
        for delimiter, strip_tabs in _heredocs(cmd, args):
            while i < total:
                candidate = lines[i]
                i += 1
                if strip_tabs:
                    candidate = candidate.lstrip("\t")
                if candidate == delimiter:
                    break


def _heredocs(cmd: str, args: str) -> tuple[tuple[str, bool], ...]:
    """The (delimiter, tab-strip) heredoc markers opened by an instruction.

    Docker defines heredocs only on RUN/COPY/ADD (plus their ONBUILD-wrapped
    forms); markers elsewhere are literal text. Only the attached spelling
    (``<<EOF`` / ``<<-EOF`` / quoted) at word start is recognised - a
    detached ``<< EOF`` falls back to plain parsing, and shell shifts like
    ``$((1<<8))`` never match.
    """
    if cmd == "ONBUILD":
        head, _, rest = args.partition(" ")
        if head.upper() not in _HEREDOC_CMDS:
            return ()
        args = rest
    elif cmd not in _HEREDOC_CMDS:
        return ()
    return tuple(
        (match.group(2) or match.group(3) or match.group(4) or "", match.group(1) == "-")
        for match in _HEREDOC_RE.finditer(args)
    )


def _trailing_escapes(segment: str, escape: str) -> int:
    """How many *escape* characters end *segment* (odd = continuation)."""
    count = 0
    while count < len(segment) and segment[-1 - count] == escape:
        count += 1
    return count


def _parse_from(args: str) -> tuple[str, str | None]:
    """The (base image/stage ref, AS-name) of a FROM argument string."""
    tokens = args.split()
    position = 0
    while position < len(tokens) and tokens[position].startswith("--"):
        position += 1  # flags such as --platform=...
    base = tokens[position] if position < len(tokens) else ""
    name = None
    if position + 2 < len(tokens) and tokens[position + 1].upper() == "AS":
        name = tokens[position + 2]
    return base, name


def _unquote(value: str) -> str:
    """Strip one level of matching single or double quotes."""
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value
