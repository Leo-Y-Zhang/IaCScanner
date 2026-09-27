"""Shared helpers for reading python-hcl2 output in Terraform rules."""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from iacscanner.models import ScanFile
from iacscanner.parsers import parse_hcl

_HEREDOC_RE = re.compile(r"<<-?(\w+)\n(.*)\n\s*\1\s*$", re.S)
# A whole-value `jsonencode(<expression>)` call, as python-hcl2 serializes it.
_JSONENCODE_RE = re.compile(r"^\$\{jsonencode\((.*)\)\}$", re.S)


def resources(sf: ScanFile, *types: str) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (resource_type, name, body) for resources in *sf*.

    When *types* is given, only those resource types are yielded.
    """
    data = sf.data if isinstance(sf.data, dict) else {}
    for block in data.get("resource") or []:
        if not isinstance(block, dict):
            continue
        for rtype, entries in block.items():
            if types and rtype not in types:
                continue
            if not isinstance(entries, dict):
                continue
            for name, body in entries.items():
                if isinstance(body, dict):
                    yield rtype, name, body


def data_sources(sf: ScanFile, *types: str) -> Iterator[tuple[str, str, dict[str, Any]]]:
    """Yield (data_source_type, name, body) for ``data`` blocks in *sf*."""
    data = sf.data if isinstance(sf.data, dict) else {}
    for block in data.get("data") or []:
        if not isinstance(block, dict):
            continue
        for dtype, entries in block.items():
            if types and dtype not in types:
                continue
            if not isinstance(entries, dict):
                continue
            for name, body in entries.items():
                if isinstance(body, dict):
                    yield dtype, name, body


def variables(sf: ScanFile) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (name, body) for every variable block in *sf*."""
    data = sf.data if isinstance(sf.data, dict) else {}
    for block in data.get("variable") or []:
        if not isinstance(block, dict):
            continue
        for name, body in block.items():
            if isinstance(body, dict):
                yield name, body


def is_reference(value: Any) -> bool:
    """True when *value* is an HCL expression rather than a literal string."""
    return isinstance(value, str) and value.startswith("${")


def blocks(body: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """Return the nested blocks stored under *key* as a list of dicts."""
    raw = body.get(key)
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    return []


def dynamic_contents(body: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """The ``content`` blocks of every ``dynamic "<key>"`` block in *body*.

    A ``dynamic`` block whose ``for_each`` is a literal empty collection
    generates nothing and is skipped. Content attributes that reference the
    iterator stay ``${...}`` strings, which rules treat as unresolved.
    """
    contents: list[dict[str, Any]] = []
    for dynamic in blocks(body, "dynamic"):
        for spec in blocks(dynamic, key):
            if spec.get("for_each") in ([], {}):
                continue
            contents.extend(blocks(spec, "content"))
    return contents


def heredoc_body(value: str) -> str:
    """Strip ``<<MARKER`` / ``MARKER`` wrappers from a heredoc string."""
    match = _HEREDOC_RE.match(value)
    return match.group(2) if match else value


def _policy_value(raw: str) -> Any:
    """Decode a policy attribute: a JSON string/heredoc or a ``jsonencode({...})`` call.

    Anything else (a reference, a template, malformed JSON) yields None.
    """
    match = _JSONENCODE_RE.match(raw)
    if match is not None:
        # Re-read the call's argument as an HCL expression. A literal object
        # comes back as a dict whose unresolved parts stay ${...} strings; a
        # reference such as jsonencode(local.p) comes back as a string.
        try:
            return parse_hcl(f"value = {match.group(1)}\n").get("value")
        except Exception:  # an expression python-hcl2 cannot re-read: unresolved
            return None
    try:
        return json.loads(heredoc_body(raw))
    except ValueError:
        return None


def _policy_document_source(body: dict[str, Any]) -> dict[str, Any]:
    """An ``aws_iam_policy_document`` data source rendered as IAM policy JSON."""
    statements = []
    for stmt in blocks(body, "statement"):
        principal: dict[str, list[Any]] = {}
        for block in blocks(stmt, "principals"):
            principal.setdefault(str(block.get("type")), []).extend(as_list(block.get("identifiers")))
        statement: dict[str, Any] = {
            "Effect": stmt.get("effect", "Allow"),  # the data source defaults to Allow
            "Action": stmt.get("actions"),
        }
        if principal:
            statement["Principal"] = principal
        statements.append(statement)
    return {"Statement": statements}


def policy_documents(sf: ScanFile) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (location, parsed_policy) for IAM policy documents.

    Covers ``policy``/``assume_role_policy`` attributes holding a JSON string,
    a heredoc or a ``jsonencode({...})`` literal, and ``aws_iam_policy_document``
    data sources (as ``data.aws_iam_policy_document.<name>``).
    """
    for rtype, name, body in resources(sf):
        for attr in ("policy", "assume_role_policy"):
            raw = body.get(attr)
            if not isinstance(raw, str):
                continue
            doc = _policy_value(raw)
            if isinstance(doc, dict):
                yield f"{rtype}.{name}", doc
    for dtype, name, body in data_sources(sf, "aws_iam_policy_document"):
        yield f"data.{dtype}.{name}", _policy_document_source(body)


def allow_statements(doc: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield the Allow statements of a parsed IAM policy document."""
    raw = doc.get("Statement", [])
    statements = [raw] if isinstance(raw, dict) else raw if isinstance(raw, list) else []
    for stmt in statements:
        if isinstance(stmt, dict) and stmt.get("Effect") == "Allow":
            yield stmt


def as_list(value: Any) -> list[Any]:
    """Normalize a scalar-or-list attribute into a list."""
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
