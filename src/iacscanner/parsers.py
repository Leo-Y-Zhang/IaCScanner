"""Read-only file discovery and parsing.

Nothing here executes code, follows URLs, or writes anywhere. Terraform is
parsed with python-hcl2, YAML strictly with ``yaml.safe_load_all``, JSON
with the standard library, and Dockerfiles (``Dockerfile``,
``Containerfile``, ``*.dockerfile``, and ``Dockerfile.<variant>`` /
``Containerfile.<variant>`` names whose extension is not another scanned
kind) with the stdlib-only parser in ``iacscanner.docker``. A file that fails
to parse yields a ScanFile carrying an ``error`` summary instead of raising.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import hcl2
import yaml
from hcl2 import SerializationOptions

from iacscanner.docker import is_dockerfile_name, parse_dockerfile
from iacscanner.models import (
    KIND_DOCKERFILE,
    KIND_GITHUB_ACTIONS,
    KIND_JSON,
    KIND_KUBERNETES,
    KIND_TERRAFORM,
    KIND_YAML,
    ScanFile,
)

SCAN_SUFFIXES = (".tf", ".yaml", ".yml", ".json")
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".terraform", ".pytest_cache"}

# Backwards-compatible python-hcl2 output: plain keys/values, blocks as
# lists of dicts, no metadata markers.
_HCL2_OPTIONS = SerializationOptions(
    with_comments=False,
    explicit_blocks=False,
    preserve_heredocs=True,
    strip_string_quotes=True,
)


def _within(child_real: str, root_real: str) -> bool:
    """True if *child_real* is *root_real* itself or a path beneath it.

    Both arguments must already be canonical real paths. The check is a
    boundary-aware prefix test (``os.sep`` separated), so ``/a/root`` does
    not spuriously contain ``/a/root-sibling``.
    """
    if child_real == root_real:
        return True
    prefix = root_real if root_real.endswith(os.sep) else root_real + os.sep
    return child_real.startswith(prefix)


def discover(target: Path) -> list[Path]:
    """Return scannable files under *target*, sorted for determinism.

    Discovery is bounded to the *real* subtree of *target*. Before IaCScanner
    descends into a directory or accepts a file, its ``os.path.realpath``
    is resolved and required to lie within ``realpath(target)`` (a
    boundary-aware prefix check). Anything whose real path escapes the
    root - a POSIX symlink, a Windows NTFS directory junction created with
    ``mklink /J`` (which needs no admin and which ``os.walk``/``is_symlink``
    do *not* flag as a link), or any other reparse point - is pruned, so a
    hostile repository cannot make IaCScanner read or report files outside the
    scan root.

    A ``seen`` set of directory real paths provides loop protection: a
    self-referential junction or symlink that would otherwise send
    ``os.walk`` into runaway recursion is pruned the moment its real path
    (or an ancestor of it) has already been visited. This is independent
    of link type and of the Python version (``os.walk(followlinks=False)``
    already declines POSIX symlinks, but not junctions).
    """
    if target.is_file():
        return [target]
    root_real = os.path.realpath(target)
    found: list[Path] = []
    seen: set[str] = {root_real}
    for dirpath, dirnames, filenames in os.walk(target, followlinks=False):
        kept: list[str] = []
        for d in dirnames:
            if d.lower() in _SKIP_DIRS:
                continue
            child = os.path.join(dirpath, d)
            child_real = os.path.realpath(child)
            # Scope-escape guard: real path must stay within the root.
            # Covers symlinks, junctions, and any other reparse point.
            if not _within(child_real, root_real):
                continue
            # Loop guard: never descend into a directory (or an ancestor of
            # one) we have already visited, however the link was formed.
            if child_real in seen:
                continue
            seen.add(child_real)
            kept.append(d)
        dirnames[:] = kept
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in SCAN_SUFFIXES and not is_dockerfile_name(name):
                continue
            # Preserve the original POSIX-symlink handling: a symlinked file
            # is an alias, so skip it outright.
            if path.is_symlink():
                continue
            # File-level scope-escape guard: even a non-symlink file whose
            # real path is redirected out of the tree (e.g. it sits under a
            # junction os.walk descended before the guard, or a reparse
            # point) is skipped.
            if not _within(os.path.realpath(path), root_real):
                continue
            found.append(path)
    return sorted(found)


def parse_file(path: Path, display: str) -> ScanFile:
    """Parse *path* into a ScanFile; parse failures set ``error``."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return ScanFile(path=display, kind=KIND_YAML, data=None, text="", error=_summary(exc))

    suffix = path.suffix.lower()
    try:
        if is_dockerfile_name(path.name):
            return ScanFile(
                path=display, kind=KIND_DOCKERFILE, data=parse_dockerfile(text), text=text
            )
        if suffix == ".tf":
            data: Any = hcl2.loads(text, serialization_options=_HCL2_OPTIONS)
            return ScanFile(path=display, kind=KIND_TERRAFORM, data=data, text=text)
        if suffix == ".json":
            return ScanFile(path=display, kind=KIND_JSON, data=json.loads(text), text=text)
        docs = [doc for doc in yaml.safe_load_all(text) if doc is not None]
        return ScanFile(path=display, kind=_yaml_kind(docs), data=docs, text=text)
    except Exception as exc:  # parser-specific errors vary; never crash a scan
        return ScanFile(path=display, kind=KIND_YAML, data=None, text=text, error=_summary(exc))


def _yaml_kind(docs: list[Any]) -> str:
    """Classify YAML documents as Kubernetes, GitHub Actions, or generic."""
    dicts = [doc for doc in docs if isinstance(doc, dict)]
    if any("apiVersion" in doc and "kind" in doc for doc in dicts):
        return KIND_KUBERNETES
    if any("jobs" in doc for doc in dicts):
        return KIND_GITHUB_ACTIONS
    return KIND_YAML


def _summary(exc: Exception) -> str:
    """One-line, path-free description of a parse failure."""
    first_line = str(exc).splitlines()[0] if str(exc) else ""
    return f"{type(exc).__name__}: {first_line}"[:200]
