"""Structural-anchor-to-line resolution.

Maps each finding's structural anchor (its ``location``) to the 1-based
source line of the structure it names:

* Terraform ``type.name`` / ``variable.name`` addresses map to their block
  start line, read from the python-hcl2 lark parse tree (whose nodes carry
  position metadata).
* Kubernetes ``Kind/name`` (plus ``container``/``volume``) anchors and
  workflow ``jobs.<job>.steps[<i>]`` anchors map to their YAML node lines,
  captured by a mark-recording ``yaml.SafeLoader`` subclass.
* Dockerfile ``stage[<label>].<CMD>[<n>]`` anchors map to their instruction
  start lines, recorded by the ``iacscanner.docker`` parser itself.
* ``line N`` text anchors (TL018) parse directly from the anchor itself,
  which also covers JSON findings.

Resolution is display metadata only and never guesses:

* An anchor produced by two different structures on different lines (for
  example duplicate Terraform addresses) is ambiguous and stays line-less.
* Scanned files are attacker-controlled, so index construction never
  raises: any parse or traversal failure simply resolves nothing for that
  file. Only mapping construction is customised on the YAML loader, so any
  file the scanner parsed successfully parses identically here.
* The resolved line is NOT part of the baseline fingerprint
  ``(rule_id, path, location)``; existing baselines are unaffected.
"""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterable, Iterator, Sequence
from typing import Any

import hcl2
import yaml
from lark import Token, Tree

from iacscanner.docker import from_anchor, instruction_anchors, parse_dockerfile
from iacscanner.models import (
    KIND_DOCKERFILE,
    KIND_GITHUB_ACTIONS,
    KIND_KUBERNETES,
    KIND_TERRAFORM,
    Finding,
    ScanFile,
)
from iacscanner.rules.kubernetes import WORKLOAD_PATHS, workload_label

_LINE_ANCHOR_RE = re.compile(r"^line ([0-9]{1,9})$")


def attach_lines(files: Sequence[ScanFile], findings: Iterable[Finding]) -> list[Finding]:
    """Return *findings* with ``line`` filled in wherever the anchor resolves.

    Anchor indexes are built lazily and cached per file, so files without
    findings are never re-parsed. Findings whose anchor does not resolve
    are returned unchanged (``line`` stays ``None``).
    """
    by_path = {sf.path: sf for sf in files}
    indexes: dict[str, dict[str, int]] = {}
    resolved: list[Finding] = []
    for finding in findings:
        line = _resolve(finding, by_path.get(finding.path), indexes)
        resolved.append(dataclasses.replace(finding, line=line) if line is not None else finding)
    return resolved


def _resolve(
    finding: Finding, sf: ScanFile | None, indexes: dict[str, dict[str, int]]
) -> int | None:
    """The 1-based line for *finding*, or None when unknown or ambiguous."""
    match = _LINE_ANCHOR_RE.match(finding.location)
    if match:
        line = int(match.group(1))
        return line if line >= 1 else None
    if sf is None or sf.error is not None:
        return None
    if sf.path not in indexes:
        indexes[sf.path] = _anchor_index(sf)
    return indexes[sf.path].get(finding.location)


def _anchor_index(sf: ScanFile) -> dict[str, int]:
    """Map every structural anchor in *sf* to its unambiguous line."""
    if sf.kind == KIND_TERRAFORM:
        builder = _terraform_anchors
    elif sf.kind == KIND_KUBERNETES:
        builder = _kubernetes_anchors
    elif sf.kind == KIND_GITHUB_ACTIONS:
        builder = _workflow_anchors
    elif sf.kind == KIND_DOCKERFILE:
        builder = _dockerfile_anchors
    else:
        return {}
    candidates: dict[str, set[int]] = {}
    try:
        for anchor, line in builder(sf.text):
            candidates.setdefault(anchor, set()).add(line)
    except Exception:  # hostile/malformed input: omit lines, never crash a scan
        return {}
    # An anchor that appears on two different lines is ambiguous: omit it
    # entirely rather than guess which occurrence a finding refers to.
    return {anchor: next(iter(lines)) for anchor, lines in candidates.items() if len(lines) == 1}


# ----------------------------------------------------------------- Terraform


def _terraform_anchors(text: str) -> Iterator[tuple[str, int]]:
    """Yield (address, block_start_line) for top-level resource/variable blocks."""
    tree = hcl2.parses_to_tree(text)
    body = tree.children[0] if tree.children else None
    if not isinstance(body, Tree):
        return
    for node in body.children:
        if not isinstance(node, Tree) or node.data != "block":
            continue
        labels = _block_labels(node)
        if len(labels) >= 3 and labels[0] == "resource":
            yield f"{labels[1]}.{labels[2]}", int(node.meta.line)
        elif len(labels) >= 2 and labels[0] == "variable":
            yield f"variable.{labels[1]}", int(node.meta.line)


def _block_labels(block: Tree[Any]) -> list[str]:
    """The keyword and quoted labels of an HCL block header, in order.

    ``resource "aws_s3_bucket" "b" { ... }`` yields
    ``["resource", "aws_s3_bucket", "b"]``.
    """
    labels: list[str] = []
    for child in block.children:
        if isinstance(child, Token):  # the opening "{" ends the header
            break
        if not isinstance(child, Tree):
            continue
        if child.data == "identifier" and child.children:
            labels.append(str(child.children[0]))
        elif child.data == "string":
            parts = [
                str(part.children[0])
                for part in child.children
                if isinstance(part, Tree) and part.data == "string_part" and part.children
            ]
            labels.append("".join(parts))
    return labels


# ---------------------------------------------------------------------- YAML


class _MarkedMapping(dict[Any, Any]):
    """A YAML mapping that remembers the 1-based line of its source node."""

    line: int = 0


class _MarkedLoader(yaml.SafeLoader):
    """SafeLoader that constructs mappings as line-marked _MarkedMapping."""


def _construct_marked_mapping(
    loader: _MarkedLoader, node: yaml.MappingNode
) -> Iterator[_MarkedMapping]:
    mapping = _MarkedMapping()
    mapping.line = node.start_mark.line + 1
    # Two-phase construction (yield first, fill later), exactly like
    # SafeConstructor.construct_yaml_map, so recursive aliases keep working.
    yield mapping
    mapping.update(loader.construct_mapping(node))


_MarkedLoader.add_constructor("tag:yaml.org,2002:map", _construct_marked_mapping)


def _marked_documents(text: str) -> Iterator[_MarkedMapping]:
    """Yield each top-level mapping document of *text* with line marks."""
    for doc in yaml.load_all(text, Loader=_MarkedLoader):
        if isinstance(doc, _MarkedMapping):
            yield doc


def _kubernetes_anchors(text: str) -> Iterator[tuple[str, int]]:
    """Yield (anchor, line) mirroring the Kubernetes rules' anchor scheme."""
    for doc in _marked_documents(text):
        kind = doc.get("kind")
        if not isinstance(kind, str):
            continue
        path = WORKLOAD_PATHS.get(kind)
        if path is None:
            continue
        node: Any = doc
        for key in path:
            node = node.get(key, {}) if isinstance(node, dict) else {}
        spec = node.get("spec") if isinstance(node, dict) else None
        if not isinstance(spec, dict):
            continue
        label = workload_label(doc, kind)
        yield label, doc.line
        for key in ("containers", "initContainers"):
            for container in spec.get(key) or []:
                if isinstance(container, _MarkedMapping):
                    yield f"{label} container {container.get('name', '?')}", container.line
        for volume in spec.get("volumes") or []:
            if isinstance(volume, _MarkedMapping):
                yield f"{label} volume {volume.get('name', '?')}", volume.line


def _workflow_anchors(text: str) -> Iterator[tuple[str, int]]:
    """Yield (anchor, line) mirroring the GitHub Actions rules' anchor scheme."""
    for doc in _marked_documents(text):
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            continue
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for index, step in enumerate(job.get("steps") or []):
                if isinstance(step, _MarkedMapping):
                    yield f"jobs.{job_name}.steps[{index}]", step.line


# ---------------------------------------------------------------- Dockerfile


def _dockerfile_anchors(text: str) -> Iterator[tuple[str, int]]:
    """Yield (anchor, line) using the same anchor builder the rules use.

    Anchors and lines both come from ``iacscanner.docker``, so they cannot
    drift apart; duplicate stage names collapse into the ambiguity guard
    upstream (the line is omitted, never guessed).
    """
    for stage in parse_dockerfile(text).stages:
        yield from_anchor(stage), stage.line
        anchors = instruction_anchors(stage)
        for instruction, anchor in zip(stage.instructions, anchors, strict=True):
            yield anchor, instruction.line
