"""Dockerfile rules with final-image stage attribution: TL029-TL032.

The false-positive discipline here is MULTI-STAGE AWARENESS. A multi-stage
build discards every builder stage; only the last stage (plus any internal
stages it extends through ``FROM <stage>`` chains) ships. So each rule walks
the FINAL IMAGE CHAIN - the final stage and its internal ancestors - and
ignores builder stages entirely: ``USER root`` while compiling, a
``golang:latest`` toolchain image, or a build-time ENV token in a discarded
stage are normal practice and must never fire.

The other side of the discipline is the usual firewall: anything unresolved
(a ``$VAR`` user, an ``ARG``-parameterised base without a literal default, a
base ref that names a stage) stays silent, never guessed.
"""
from __future__ import annotations

import re

from iacscanner.docker import (
    DockerfileModel,
    Instruction,
    Stage,
    env_pairs,
    from_anchor,
    instruction_anchors,
    stage_label,
    substitute,
)
from iacscanner.models import KIND_DOCKERFILE, Finding, Rule, ScanFile, Severity

# Secret-looking ENV names: the secret word must END the name, so API_TOKEN
# matches but API_TOKEN_URL (a pointer, not a credential) does not.
_SECRET_NAME_RE = re.compile(
    r"(?:^|_)(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|SECRET_KEY|PRIVATE_KEY|CREDENTIALS?)$",
    re.IGNORECASE,
)


def _model(sf: ScanFile) -> DockerfileModel | None:
    return sf.data if isinstance(sf.data, DockerfileModel) else None


def _final_chain(model: DockerfileModel) -> tuple[tuple[Stage, ...], str | None]:
    """The stages whose configuration reaches the final image, oldest first,
    plus the resolved EXTERNAL base image ref the chain is built on.

    Follows ``FROM <internal stage>`` references backwards from the last
    stage (name matching is case-insensitive, like Docker's). The external
    base is None when it cannot be established: no stages, an unresolved
    ``${VAR}``, or a base that names a stage (a broken forward reference is
    a broken build, not an untagged image pull).
    """
    if not model.stages:
        return (), None
    args = dict(model.global_args)
    stage_names = {s.name.lower() for s in model.stages if s.name is not None}
    current = model.stages[-1]
    chain: list[Stage] = [current]
    visited = {current.index}
    external: str | None = None
    while True:
        resolved = substitute(current.base, args) if current.base else None
        if not resolved:
            break  # empty or unresolved base: external base unknown
        target: Stage | None = None
        for earlier in model.stages[: current.index]:
            if earlier.name is not None and earlier.name.lower() == resolved.lower():
                target = earlier  # the last matching earlier stage wins
        if target is not None:
            if target.index in visited:
                break  # defensive: duplicate-name loop in a broken file
            chain.insert(0, target)
            visited.add(target.index)
            current = target
            continue
        if resolved.lower() in stage_names or resolved.isdigit():
            break  # names a stage (or a bare index): not an external image
        external = resolved
        break
    return tuple(chain), external


def _timeline(chain: tuple[Stage, ...]) -> list[tuple[Stage, Instruction, str]]:
    """Every instruction that shapes the final image, in effective order,
    each paired with its stable structural anchor."""
    ordered: list[tuple[Stage, Instruction, str]] = []
    for stage in chain:
        anchors = instruction_anchors(stage)
        for instruction, anchor in zip(stage.instructions, anchors, strict=True):
            ordered.append((stage, instruction, anchor))
    return ordered


def _inherited(stage: Stage, chain: tuple[Stage, ...]) -> str:
    """Message suffix naming the ancestor stage an instruction came from."""
    if stage.index == chain[-1].index:
        return ""
    return f" (inherited from stage '{stage_label(stage)}')"


def _mask(value: str) -> str:
    """Show only a short prefix of a secret-looking value (TL018 convention)."""
    return value if len(value) <= 8 else value[:8] + "..."


def _check_tl029(sf: ScanFile) -> list[Finding]:
    model = _model(sf)
    if model is None or not model.stages:
        return []
    chain, _ = _final_chain(model)
    last_user: tuple[Stage, Instruction, str] | None = None
    for stage, instruction, anchor in _timeline(chain):
        if instruction.cmd == "USER":
            last_user = (stage, instruction, anchor)
    if last_user is None:
        return []  # no USER anywhere in the chain: base default unknown, never guess
    stage, instruction, anchor = last_user
    token = instruction.args.split()[0] if instruction.args.split() else ""
    if "$" in token:
        return []  # variable user: unresolved, silent
    user = token.split(":", 1)[0].strip("\"'")
    if user.lower() != "root" and user != "0":
        return []
    return [
        TL029.finding(
            sf,
            anchor,
            f"final image runs as root (USER {token}){_inherited(stage, chain)}",
        )
    ]


def _check_tl030(sf: ScanFile) -> list[Finding]:
    model = _model(sf)
    if model is None or not model.stages:
        return []
    chain, _ = _final_chain(model)
    findings: list[Finding] = []
    for stage, instruction, anchor in _timeline(chain):
        if instruction.cmd != "ENV":
            continue
        for key, value in env_pairs(instruction.args):
            if not value or "$" in value or value.startswith("/"):
                continue  # empty, a reference, or a path pointer - not a literal secret
            if _SECRET_NAME_RE.search(key) is None:
                continue
            findings.append(
                TL030.finding(
                    sf,
                    anchor,
                    f"final image bakes secret-looking environment variable '{key}' "
                    f"(value {_mask(value)}){_inherited(stage, chain)}",
                )
            )
    return findings


def _check_tl031(sf: ScanFile) -> list[Finding]:
    model = _model(sf)
    if model is None or not model.stages:
        return []
    chain, external = _final_chain(model)
    if external is None or "@" in external:
        return []  # unknown base, or digest-pinned (immutable regardless of tag)
    repository, tag = _split_tag(external)
    if not repository or repository.lower() == "scratch":
        return []
    if tag is not None and tag.lower() != "latest":
        return []
    root = chain[0]
    described = external if tag is not None else f"{external} (untagged)"
    via = "" if root.index == chain[-1].index else f" via build stage '{stage_label(root)}'"
    return [
        TL031.finding(
            sf,
            from_anchor(root),
            f"final image is built from mutable base '{described}'{via}",
        )
    ]


def _check_tl032(sf: ScanFile) -> list[Finding]:
    model = _model(sf)
    if model is None or not model.stages:
        return []
    chain, _ = _final_chain(model)
    findings: list[Finding] = []
    for stage, instruction, anchor in _timeline(chain):
        if instruction.cmd != "EXPOSE":
            continue
        for token in instruction.args.split():
            if "$" in token:
                continue  # variable port: unresolved, silent
            port, _, protocol = token.partition("/")
            if port == "22" and protocol.lower() in ("", "tcp"):
                findings.append(
                    TL032.finding(
                        sf,
                        anchor,
                        f"final image exposes SSH port 22 ({token}){_inherited(stage, chain)}",
                    )
                )
    return findings


def _split_tag(image: str) -> tuple[str, str | None]:
    """Split an image ref into (repository, tag), registry-port aware.

    A colon only counts as a tag separator after the last slash, so
    ``registry.example.com:5000/app`` is untagged while
    ``registry.example.com:5000/app:1.2`` is tagged ``1.2``.
    """
    slash = image.rfind("/")
    colon = image.rfind(":")
    if colon > slash:
        return image[:colon], image[colon + 1 :]
    return image, None


_DOCKER = (KIND_DOCKERFILE,)

TL029 = Rule(
    id="TL029",
    title="Final image runs as root",
    severity=Severity.HIGH,
    description="The last USER instruction that applies to the final image stage sets root or UID 0. Builder-stage USER directives are ignored (they never reach the shipped image), and an omitted USER stays silent because the base image's default is unknown.",
    rationale="A container that starts as root turns any application compromise into root inside the container and a far stronger position for runtime or kernel escapes; build stages routinely need root, so only the final image's effective user matters.",
    remediation="RUN adduser -S app && ...\nUSER app  # in the final stage; root in builder stages is fine",
    kinds=_DOCKER,
    check=_check_tl029,
)

TL030 = Rule(
    id="TL030",
    title="Secret baked into the final image environment",
    severity=Severity.HIGH,
    description="An ENV instruction that reaches the final image assigns a literal value to a secret-looking variable name (PASSWORD, TOKEN, SECRET, ...). Builder-stage ENV values are discarded with their stage and are not flagged.",
    rationale="ENV values persist in the image configuration and its layer history, so a baked secret ships to every registry and host that pulls the image - even when a later instruction overwrites the variable.",
    remediation="Pass secrets at runtime (orchestrator secret, --env-file) or use a BuildKit secret mount: RUN --mount=type=secret,id=token ...",
    kinds=_DOCKER,
    check=_check_tl030,
)

TL031 = Rule(
    id="TL031",
    title="Final image built from a mutable base tag",
    severity=Severity.LOW,
    description="The external base image the final stage ultimately builds on is untagged or tagged :latest. Builder-stage bases are not flagged, digest-pinned refs are immutable, and FROM references that resolve to another stage or stay unresolved are silent.",
    rationale="A mutable tag silently pulls whatever it points to next, so a compromised or breaking base lands in the shipped image with no diff to review and no way to reproduce yesterday's build.",
    remediation="FROM python:3.12.5-slim  # pin a version tag, or better an @sha256: digest",
    kinds=_DOCKER,
    check=_check_tl031,
)

TL032 = Rule(
    id="TL032",
    title="Final image exposes the SSH port",
    severity=Severity.MEDIUM,
    description="An EXPOSE instruction that applies to the final image declares port 22/tcp. Builder-stage EXPOSE directives are ignored.",
    rationale="Serving SSH from inside a container widens the attack surface and bypasses the orchestrator's access and audit model; CIS Docker guidance is not to run sshd in containers.",
    remediation="Remove EXPOSE 22 and use docker exec / kubectl exec for debugging instead of SSH.",
    kinds=_DOCKER,
    check=_check_tl032,
)

RULES: tuple[Rule, ...] = (TL029, TL030, TL031, TL032)
