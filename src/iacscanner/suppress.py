"""Inline ``themis:ignore`` suppressions parsed from a file's raw text.

A line comment suppresses findings in that file without editing any config:

    resource "aws_s3_bucket" "logs" {   # themis:ignore TL001,TL002  -- reviewed: intentional
      acl = "public-read"
    }
    password = "REDACTED"               # themis:ignore  (suppresses every rule in this file)

Scope is the whole file (the parsers do not track line numbers for structured findings, so
line-precise suppression is not offered -- use the policy for finer control). The comment is
only honoured as a real comment: a ``#`` that falls inside a quoted string is ignored (with
escape awareness, so ``"a\\"#x"`` keeps the ``#`` inside the string), and a rule-id-shaped
token that is not a valid ``TLnnn`` id (a typo like ``TL01``/``TL9999``) is reported as a
warning and suppresses nothing, rather than silently widening to ignore-ALL.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_IGNORE_RE = re.compile(r"#\s*themis[:-]ignore\b([^\n]*)", re.IGNORECASE)
_RULE_ID_RE = re.compile(r"\bTL\d{3}\b")
# A rule-id-shaped token (``TL`` + digits, any count). Valid ids are the 3-digit subset; the
# rest are typos we warn about instead of treating a whole comment as bare "ignore all".
_TLISH_RE = re.compile(r"\bTL\d+\b")


@dataclass(frozen=True)
class Suppression:
    """The inline suppressions declared in one file."""

    all_rules: bool
    rule_ids: frozenset[str]

    def suppresses(self, rule_id: str) -> bool:
        return self.all_rules or rule_id in self.rule_ids


NONE = Suppression(all_rules=False, rule_ids=frozenset())


def _is_real_comment(line: str, hash_pos: int) -> bool:
    """True if the ``#`` at *hash_pos* starts a comment rather than sitting in a string.

    Escape-aware: a backslash-escaped quote (``\\"``) does not open or close a string, so a
    marker buried in a value like ``"abc\\"#themis:ignore TL010"`` is correctly seen as being
    inside the string and is not honoured as a directive.
    """
    quote: str | None = None
    i = 0
    while i < hash_pos:
        ch = line[i]
        if ch == "\\" and quote is not None:
            i += 2  # skip the escaped character inside a string
            continue
        if quote is None:
            if ch == '"' or ch == "'":
                quote = ch
        elif ch == quote:
            quote = None
        i += 1
    return quote is None


def parse_suppressions_with_warnings(text: str) -> tuple[Suppression, list[str]]:
    """Collect the file-scoped inline suppressions in *text* plus any typo warnings.

    Warnings are generic fragments (no file path); the caller prefixes the file name."""
    all_rules = False
    rule_ids: set[str] = set()
    warnings: list[str] = []
    for line in text.splitlines():
        for match in _IGNORE_RE.finditer(line):
            if not _is_real_comment(line, match.start()):
                continue  # the '#' is inside a string literal, not a comment
            tail = match.group(1)
            ids = _RULE_ID_RE.findall(tail)
            malformed = [t for t in _TLISH_RE.findall(tail) if not _RULE_ID_RE.fullmatch(t)]
            for token in malformed:
                warnings.append(
                    f"inline 'themis:ignore {token}' is not a valid rule id (expected TLnnn); ignored"
                )
            if ids:
                rule_ids.update(ids)
            elif not malformed:
                # A bare `# themis:ignore` (no rule-id-shaped token at all) means ignore-all.
                # A typo'd token means suppress nothing (fail closed) -- never silently widen.
                all_rules = True
    return Suppression(all_rules=all_rules, rule_ids=frozenset(rule_ids)), warnings


def parse_suppressions(text: str) -> Suppression:
    """Collect the file-scoped inline suppressions declared in *text*."""
    suppression, _ = parse_suppressions_with_warnings(text)
    return suppression
