"""Kubernetes manifest rules: TL011-TL015."""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from iacscanner.models import KIND_KUBERNETES, Finding, Rule, ScanFile, Severity

# Path from a workload document to its pod template; shared with the line
# resolver (iacscanner.lines), which mirrors this traversal to anchor lines.
WORKLOAD_PATHS = {
    "Pod": (),
    "Deployment": ("spec", "template"),
    "StatefulSet": ("spec", "template"),
    "DaemonSet": ("spec", "template"),
    "ReplicaSet": ("spec", "template"),
    "Job": ("spec", "template"),
    "CronJob": ("spec", "jobTemplate", "spec", "template"),
}


def workload_label(doc: dict[str, Any], kind: str) -> str:
    """The ``Kind/name`` anchor label of a workload document.

    A non-mapping ``metadata`` (hostile input) falls back to ``unnamed``
    instead of raising - scans must never crash on malformed manifests.
    """
    metadata = doc.get("metadata")
    name = metadata.get("name", "unnamed") if isinstance(metadata, dict) else "unnamed"
    return f"{kind}/{name}"


def _pod_specs(sf: ScanFile) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield (label, pod_spec) for every workload document in *sf*."""
    docs = sf.data if isinstance(sf.data, list) else []
    for doc in docs:
        if not isinstance(doc, dict):
            continue
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
        if isinstance(spec, dict):
            yield workload_label(doc, kind), spec


def _containers(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    for key in ("containers", "initContainers"):
        for container in spec.get(key) or []:
            if isinstance(container, dict):
                yield container


def _ctx(obj: dict[str, Any]) -> dict[str, Any]:
    ctx = obj.get("securityContext")
    return ctx if isinstance(ctx, dict) else {}


def _check_tl011(sf: ScanFile) -> list[Finding]:
    return [
        TL011.finding(sf, f"{label} container {c.get('name', '?')}", "container runs privileged")
        for label, spec in _pod_specs(sf)
        for c in _containers(spec)
        if _ctx(c).get("privileged") is True
    ]


def _check_tl012(sf: ScanFile) -> list[Finding]:
    findings = []
    for label, spec in _pod_specs(sf):
        pod_value = _ctx(spec).get("runAsNonRoot")
        for c in _containers(spec):
            value = _ctx(c).get("runAsNonRoot", pod_value)
            if value is not True:
                state = "set to false" if value is False else "not set"
                findings.append(
                    TL012.finding(sf, f"{label} container {c.get('name', '?')}", f"runAsNonRoot is {state}")
                )
    return findings


def _check_tl013(sf: ScanFile) -> list[Finding]:
    return [
        TL013.finding(sf, label, "pod uses hostNetwork: true")
        for label, spec in _pod_specs(sf)
        if spec.get("hostNetwork") is True
    ]


def _check_tl014(sf: ScanFile) -> list[Finding]:
    findings = []
    for label, spec in _pod_specs(sf):
        for c in _containers(spec):
            raw_resources = c.get("resources")
            resources = raw_resources if isinstance(raw_resources, dict) else {}
            raw_limits = resources.get("limits")
            limits = raw_limits if isinstance(raw_limits, dict) else {}
            missing = [key for key in ("cpu", "memory") if key not in limits]
            if missing:
                findings.append(
                    TL014.finding(
                        sf,
                        f"{label} container {c.get('name', '?')}",
                        "no resource limits for " + " and ".join(missing),
                    )
                )
    return findings


def _check_tl015(sf: ScanFile) -> list[Finding]:
    findings = []
    for label, spec in _pod_specs(sf):
        for c in _containers(spec):
            image = c.get("image")
            if not isinstance(image, str) or "@sha256:" in image:
                continue
            tail = image.rsplit("/", 1)[-1]
            if ":" not in tail:
                findings.append(
                    TL015.finding(sf, f"{label} container {c.get('name', '?')}", f"image '{image}' has no tag")
                )
            elif tail.endswith(":latest"):
                findings.append(
                    TL015.finding(sf, f"{label} container {c.get('name', '?')}", f"image '{image}' uses :latest")
                )
    return findings


def _check_tl026(sf: ScanFile) -> list[Finding]:
    findings = []
    for label, spec in _pod_specs(sf):
        pod_ctx = _ctx(spec)
        if pod_ctx.get("runAsUser") == 0:
            findings.append(TL026.finding(sf, label, "pod securityContext runAsUser is 0 (root)", sub_key="runAsUser"))
        if pod_ctx.get("fsGroup") == 0:
            findings.append(TL026.finding(sf, label, "pod securityContext fsGroup is 0 (root)", sub_key="fsGroup"))
        for c in _containers(spec):
            if _ctx(c).get("runAsUser") == 0:
                findings.append(
                    TL026.finding(sf, f"{label} container {c.get('name', '?')}", "container runAsUser is 0 (root)")
                )
    return findings


def _check_tl027(sf: ScanFile) -> list[Finding]:
    findings = []
    for label, spec in _pod_specs(sf):
        if spec.get("hostPID") is True:
            findings.append(TL027.finding(sf, label, "pod sets hostPID: true", sub_key="hostPID"))
        if spec.get("hostIPC") is True:
            findings.append(TL027.finding(sf, label, "pod sets hostIPC: true", sub_key="hostIPC"))
        for vol in spec.get("volumes") or []:
            if isinstance(vol, dict) and isinstance(vol.get("hostPath"), dict):
                path = vol["hostPath"].get("path", "?")
                findings.append(
                    TL027.finding(sf, f"{label} volume {vol.get('name', '?')}", f"mounts host path '{path}'")
                )
    return findings


_K8S = (KIND_KUBERNETES,)

TL011 = Rule(
    id="TL011",
    title="Container runs privileged",
    severity=Severity.CRITICAL,
    description="A container sets securityContext.privileged: true.",
    rationale="Privileged containers can access host devices and typically escape to the node.",
    remediation="securityContext:\n  privileged: false\n  allowPrivilegeEscalation: false",
    kinds=_K8S,
    check=_check_tl011,
)

TL012 = Rule(
    id="TL012",
    title="runAsNonRoot missing or false",
    severity=Severity.MEDIUM,
    description="Neither the pod nor the container securityContext enforces runAsNonRoot: true.",
    rationale="Root inside a container amplifies any container escape or file mount mistake.",
    remediation="securityContext:\n  runAsNonRoot: true",
    kinds=_K8S,
    check=_check_tl012,
)

TL013 = Rule(
    id="TL013",
    title="Pod uses the host network",
    severity=Severity.HIGH,
    description="A pod spec sets hostNetwork: true.",
    rationale="Host networking bypasses network policy and exposes node-local services to the pod.",
    remediation="hostNetwork: false  # or simply omit the field",
    kinds=_K8S,
    check=_check_tl013,
)

TL014 = Rule(
    id="TL014",
    title="Container has no resource limits",
    severity=Severity.LOW,
    description="A container does not set both cpu and memory limits.",
    rationale="Unbounded containers can starve the node, a denial-of-service and noisy-neighbor risk.",
    remediation="resources:\n  limits:\n    cpu: 500m\n    memory: 256Mi",
    kinds=_K8S,
    check=_check_tl014,
)

TL015 = Rule(
    id="TL015",
    title="Image is untagged or uses :latest",
    severity=Severity.LOW,
    description="A container image has no tag or uses the mutable :latest tag.",
    rationale="Mutable tags make deployments unreproducible and let unexpected images roll out.",
    remediation="image: nginx:1.27.1  # pin a version, or better, a digest",
    kinds=_K8S,
    check=_check_tl015,
)

TL026 = Rule(
    id="TL026",
    title="Container or pod runs as root by UID",
    severity=Severity.HIGH,
    description="A securityContext hardcodes runAsUser: 0 or fsGroup: 0.",
    rationale="A hardcoded UID 0 runs as root even when a policy sets runAsNonRoot, amplifying any container escape.",
    remediation="securityContext:\n  runAsUser: 1000\n  runAsNonRoot: true",
    kinds=_K8S,
    check=_check_tl026,
)

TL027 = Rule(
    id="TL027",
    title="Pod mounts the host filesystem or namespaces",
    severity=Severity.HIGH,
    description="A pod uses a hostPath volume, or sets hostPID: true or hostIPC: true.",
    rationale="Host mounts and shared host namespaces give a compromised pod a direct path to read host files or other processes and escape to the node.",
    remediation="Remove hostPath volumes and hostPID/hostIPC; use a PersistentVolumeClaim or emptyDir instead.",
    kinds=_K8S,
    check=_check_tl027,
)

RULES: tuple[Rule, ...] = (TL011, TL012, TL013, TL014, TL015, TL026, TL027)
