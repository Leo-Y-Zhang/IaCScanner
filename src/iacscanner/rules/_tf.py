"""Shared helpers for reading python-hcl2 output in Terraform rules."""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from typing import Any

from iacscanner.models import ScanFile

_HEREDOC_RE = re.compile(r"<<-?(\w+)\n(.*)\n\s*\1\s*$", re.S)


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


def heredoc_body(value: str) -> str:
    """Strip ``<<MARKER`` / ``MARKER`` wrappers from a heredoc string."""
    match = _HEREDOC_RE.match(value)
    return match.group(2) if match else value


def policy_documents(sf: ScanFile) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (location, parsed_policy) for JSON IAM policy documents."""
    for rtype, name, body in resources(sf):
        for attr in ("policy", "assume_role_policy"):
            raw = body.get(attr)
            if not isinstance(raw, str):
                continue
            try:
                doc = json.loads(heredoc_body(raw))
            except ValueError:
                continue
            if isinstance(doc, dict):
                yield f"{rtype}.{name}", doc


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
