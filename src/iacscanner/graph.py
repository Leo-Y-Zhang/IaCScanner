"""Cross-file Terraform resource graph + reference resolver + immutable scan context.

The scanner builds ONE :class:`ScanContext` per scan and threads it to graph-aware rules,
so a rule can ask "is there a companion resource anywhere in the scan root?" instead of
guessing per file. The resolver follows ``${var.x}`` / ``${local.y}`` chains on the raw HCL
string (regex extraction, never HCL evaluation) with cycle detection and a depth cap, and
recognises ``${type.name.attr}`` resource-address references.

The load-bearing rule: anything that cannot be resolved -- a missing reference, a data
source, a function call, a cycle, or too-deep nesting -- is returned UNCHANGED (the literal
``${...}``). Unresolved never becomes a confident value, so the resolver can only ever
REDUCE false positives, never invent one. Everything here is read-only and deterministic
(files are visited in the scanner's sorted order; first definition wins).
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from iacscanner.models import KIND_TERRAFORM, ScanFile
from iacscanner.rules import _tf

# One ${...} interpolation with no nested braces (nested/complex exprs are left unresolved).
_INTERP_RE = re.compile(r"\$\{([^${}]*)\}")
_IDENT = r"[A-Za-z_][A-Za-z0-9_-]*"
# A whole-value single resource-address reference: ${type.name.attr...}
_RESOURCE_REF_RE = re.compile(rf"^\$\{{\s*({_IDENT})\.({_IDENT})\.{_IDENT}[\w.\[\]]*\s*\}}$")
# Reserved leading namespaces that are NOT resource types. A ${a.b.c} whose head is one of
# these (a module output, data source, for_each/count expansion, path/terraform meta) is NOT
# a resource address; treating it as one would defeat the unresolved-reference firewall and
# manufacture a false "does not cover this bucket" -> so it must resolve to None instead.
_RESERVED_HEADS = frozenset(
    {"var", "local", "module", "data", "each", "count", "path", "terraform", "self"}
)
_MAX_DEPTH = 12


@dataclass(frozen=True)
class ResourceRef:
    """A resolved Terraform resource address, ``type.name``."""

    type: str
    name: str


def _head(path: str) -> str:
    """First path segment: ``bucket_name`` from ``bucket_name.id`` or ``bucket_name[0]``."""
    return path.split(".")[0].split("[")[0]


class ResourceGraph:
    """Read-only index of every Terraform resource, variable and local across all files."""

    def __init__(self, files: tuple[ScanFile, ...]) -> None:
        self._tf_files = tuple(
            f for f in files if f.kind == KIND_TERRAFORM and isinstance(f.data, dict)
        )
        self._variables: dict[str, Any] = {}
        self._locals: dict[str, Any] = {}
        for sf in self._tf_files:  # deterministic: files arrive sorted; first definition wins
            for name, body in _tf.variables(sf):
                self._variables.setdefault(name, body.get("default"))
            for block in sf.data.get("locals") or []:
                if isinstance(block, dict):
                    for name, value in block.items():
                        self._locals.setdefault(name, value)

    def resources(self, *types: str) -> Iterator[tuple[ScanFile, str, str, dict[str, Any]]]:
        """Yield (file, resource_type, name, body) across ALL terraform files."""
        for sf in self._tf_files:
            for rtype, name, body in _tf.resources(sf, *types):
                yield sf, rtype, name, body

    def has_resource(self, *types: str) -> bool:
        return any(True for _ in self.resources(*types))

    def resolve(self, value: Any, _depth: int = 0, _seen: frozenset[str] | None = None) -> Any:
        """Best-effort substitution of ``${var.x}`` / ``${local.y}`` references to literals.

        Non-strings and values with no interpolation are returned unchanged. Unresolvable
        or circular references are left as their literal ``${...}`` text."""
        if not isinstance(value, str) or "${" not in value or _depth >= _MAX_DEPTH:
            return value
        seen = _seen if _seen is not None else frozenset()

        def _sub(match: re.Match[str]) -> str:
            expr = match.group(1).strip()
            if expr in seen:
                return match.group(0)  # cycle: leave the literal
            target = self._lookup(expr)
            if target is None:
                return match.group(0)  # missing / not a var-or-local: leave the literal
            resolved = self.resolve(target, _depth + 1, seen | {expr})
            return resolved if isinstance(resolved, str) else match.group(0)

        return _INTERP_RE.sub(_sub, value)

    def _lookup(self, expr: str) -> Any:
        if expr.startswith("var."):
            return self._variables.get(_head(expr[4:]))
        if expr.startswith("local."):
            return self._locals.get(_head(expr[6:]))
        return None

    def resolve_reference(self, value: Any) -> ResourceRef | None:
        """If *value* is a single ``${type.name.attr}`` resource reference, return its
        ``type.name`` address; otherwise None."""
        if isinstance(value, str):
            match = _RESOURCE_REF_RE.match(value.strip())
            if match and match.group(1) not in _RESERVED_HEADS:
                return ResourceRef(match.group(1), match.group(2))
        return None


@dataclass(frozen=True)
class ScanContext:
    """Immutable, built-once-per-scan view threaded to graph-aware rules."""

    files: tuple[ScanFile, ...]
    graph: ResourceGraph

    @classmethod
    def build(cls, files: tuple[ScanFile, ...]) -> ScanContext:
        return cls(files, ResourceGraph(files))
