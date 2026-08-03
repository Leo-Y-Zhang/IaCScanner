"""Structural-anchor-to-line resolution (iacscanner/lines.py).

Findings carry an optional 1-based source ``line`` resolved from their
structural anchor: Terraform addresses map to their block start line,
Kubernetes and workflow anchors to their YAML node lines, and ``line N``
text anchors parse directly. Resolution never guesses (ambiguous or
unresolvable anchors stay line-less), never enters the baseline
fingerprint, and - like the rest of the scanner - never crashes on
hostile input.
"""
from __future__ import annotations

from pathlib import Path

from iacscanner.scanner import scan


def _line_by_anchor(result, path: str) -> dict[tuple[str, str], int | None]:
    return {(f.rule_id, f.location): f.line for f in result.findings if f.path == path}


# ------------------------------------------------- accuracy on the fixtures


class TestVulnerableFixtureLines:
    """Spot-check documented findings against hand-verified line numbers."""

    def test_terraform_anchors_point_at_their_block_start(self, vulnerable_result) -> None:
        lines = _line_by_anchor(vulnerable_result, "main.tf")
        assert lines[("TL010", "variable.db_password")] == 6
        assert lines[("TL001", "aws_s3_bucket.example_data")] == 12
        assert lines[("TL005", "aws_security_group.admin")] == 17
        assert lines[("TL006", "aws_ebs_volume.scratch")] == 38
        assert lines[("TL019", "aws_db_instance.app")] == 44
        assert lines[("TL009", "aws_cloudtrail.main")] == 55
        assert lines[("TL003", "aws_iam_policy.admin")] == 61

    def test_terraform_text_pattern_anchor_keeps_its_line(self, vulnerable_result) -> None:
        lines = _line_by_anchor(vulnerable_result, "main.tf")
        assert lines[("TL018", "line 50")] == 50

    def test_kubernetes_anchors_point_at_their_yaml_nodes(self, vulnerable_result) -> None:
        lines = _line_by_anchor(vulnerable_result, "deployment.yaml")
        assert lines[("TL013", "Deployment/example-app")] == 3
        assert lines[("TL027", "Deployment/example-app volume host-root")] == 20
        assert lines[("TL011", "Deployment/example-app container web")] == 24
        assert lines[("TL015", "Deployment/example-app container sidecar")] == 29

    def test_workflow_step_anchors_point_at_their_step_nodes(self, vulnerable_result) -> None:
        lines = _line_by_anchor(vulnerable_result, "ci-workflow.yml")
        assert lines[("TL016", "jobs.build.steps[0]")] == 11
        assert lines[("TL017", "jobs.build.steps[1]")] == 14
        assert lines[("TL028", "jobs.build.steps[2]")] == 16

    def test_json_line_anchors_resolve(self, vulnerable_result) -> None:
        lines = {f.location: f.line for f in vulnerable_result.findings if f.path == "config.json"}
        assert lines == {"line 3": 3, "line 4": 4, "line 8": 8}

    def test_every_vulnerable_finding_resolves_a_valid_line(self, vulnerable_result) -> None:
        assert all(f.line is not None and f.line >= 1 for f in vulnerable_result.findings)


# --------------------------------------------------------- omission contract


class TestOmissionNeverGuessing:
    def test_parse_error_finding_has_no_line(self, tmp_path: Path) -> None:
        (tmp_path / "bad.tf").write_text('resource "x" {\n', encoding="utf-8")
        result = scan(tmp_path)
        assert [f.rule_id for f in result.findings] == ["TL000"]
        assert result.findings[0].line is None

    def test_duplicate_terraform_address_is_ambiguous_and_omitted(self, tmp_path: Path) -> None:
        text = (
            'variable "password" {\n  default = "hunter2-first"\n}\n'
            'variable "password" {\n  default = "hunter2-second"\n}\n'
        )
        (tmp_path / "dup.tf").write_text(text, encoding="utf-8")
        result = scan(tmp_path)
        tl010 = [f for f in result.findings if f.rule_id == "TL010"]
        assert len(tl010) == 2  # both duplicate blocks fire
        assert all(f.line is None for f in tl010)

    def test_duplicate_kubernetes_document_is_ambiguous_and_omitted(self, tmp_path: Path) -> None:
        doc = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\nspec:\n  hostNetwork: true\n  containers: []\n"
        (tmp_path / "pods.yaml").write_text(doc + "---\n" + doc, encoding="utf-8")
        result = scan(tmp_path)
        tl013 = [f for f in result.findings if f.rule_id == "TL013"]
        assert len(tl013) == 2
        assert all(f.line is None for f in tl013)

    def test_duplicate_workflow_step_anchor_is_ambiguous_and_omitted(self, tmp_path: Path) -> None:
        doc = (
            "on: pull_request_target\n"
            "jobs:\n"
            "  build:\n"
            "    steps:\n"
            "      - uses: actions/checkout@v4\n"
            "        with:\n"
            "          ref: ${{ github.event.pull_request.head.sha }}\n"
        )
        (tmp_path / "wf.yml").write_text(doc + "---\n" + doc, encoding="utf-8")
        result = scan(tmp_path)
        tl016 = [f for f in result.findings if f.rule_id == "TL016"]
        assert len(tl016) == 2  # jobs.build.steps[0] exists in both documents
        assert all(f.line is None for f in tl016)

    def test_line_zero_anchor_is_never_emitted_as_a_line(self) -> None:
        # No rule produces "line 0", but the resolver must still refuse it:
        # a resolved line is always >= 1 or absent.
        from iacscanner.lines import attach_lines
        from iacscanner.models import Finding, ScanFile, Severity

        sf = ScanFile(path="x.json", kind="json", data={}, text="{}")
        finding = Finding(
            rule_id="TL018", severity=Severity.CRITICAL, path="x.json",
            location="line 0", message="m",
        )
        (resolved,) = attach_lines([sf], [finding])
        assert resolved.line is None


# ------------------------------------------------------- fingerprint safety


def test_line_is_not_part_of_identity_or_fingerprint() -> None:
    import dataclasses

    from iacscanner.baseline import fingerprint
    from iacscanner.models import Finding, Severity

    bare = Finding(
        rule_id="TL001", severity=Severity.CRITICAL, path="main.tf",
        location="aws_s3_bucket.x", message="m",
    )
    lined = dataclasses.replace(bare, line=12)
    assert fingerprint(bare) == fingerprint(lined)
    assert bare == lined  # line is display metadata, not identity
    assert bare.sort_key == lined.sort_key


# ------------------------------------------------------ adversarial fixtures


class TestResolverRobustness:
    """The resolver reads attacker-controlled files and must never raise."""

    def test_recursive_yaml_alias_resolves_without_crashing(self, tmp_path: Path) -> None:
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
            "spec:\n  hostNetwork: true\n  containers: []\n  loop: &l\n    self: *l\n"
        )
        (tmp_path / "pod.yaml").write_text(text, encoding="utf-8")
        result = scan(tmp_path)
        tl013 = [f for f in result.findings if f.rule_id == "TL013"]
        assert len(tl013) == 1
        assert tl013[0].line == 1  # the document node starts on line 1

    def test_reused_yaml_anchors_do_not_confuse_container_lines(self, tmp_path: Path) -> None:
        # The same aliased securityContext is shared by both containers;
        # each container anchor still maps to its own list-item node.
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
            "spec:\n"
            "  containers:\n"
            "    - name: a\n      image: img:1\n      securityContext: &priv\n        privileged: true\n"
            "    - name: b\n      image: img:1\n      securityContext: *priv\n"
        )
        (tmp_path / "pod.yaml").write_text(text, encoding="utf-8")
        result = scan(tmp_path)
        lines = {f.location: f.line for f in result.findings if f.rule_id == "TL011"}
        assert lines == {"Pod/p container a": 7, "Pod/p container b": 11}

    def test_deeply_nested_yaml_never_crashes(self, tmp_path: Path) -> None:
        depth = 4000
        (tmp_path / "deep.yaml").write_text(
            "x: " + "[" * depth + "]" * depth + "\n", encoding="utf-8"
        )
        result = scan(tmp_path)  # parse failure or success, but never a crash
        assert all(f.line is None or f.line >= 1 for f in result.findings)

    def test_deeply_nested_terraform_never_crashes(self, tmp_path: Path) -> None:
        depth = 300
        body = "a {\n" * depth + "}\n" * depth
        (tmp_path / "deep.tf").write_text(
            f'resource "aws_s3_bucket" "b" {{\n  acl = "public-read"\n{body}}}\n',
            encoding="utf-8",
        )
        result = scan(tmp_path)
        assert all(f.line is None or f.line >= 1 for f in result.findings)

    def test_huge_single_line_file_resolves_or_omits_quickly(self, tmp_path: Path) -> None:
        filler = '{"k": "' + "A" * 2_000_000 + '", "password": "hunter2-example"}'
        (tmp_path / "huge.json").write_text(filler, encoding="utf-8")
        result = scan(tmp_path)
        tl018 = [f for f in result.findings if f.rule_id == "TL018"]
        assert tl018 and all(f.line == 1 for f in tl018)

    def test_non_dict_metadata_in_workload_does_not_crash(self, tmp_path: Path) -> None:
        # Regression: a Pod with a non-mapping metadata previously raised
        # AttributeError inside the Kubernetes rules and aborted the scan.
        text = "apiVersion: v1\nkind: Pod\nmetadata: [1, 2]\nspec:\n  hostNetwork: true\n  containers: []\n"
        (tmp_path / "pod.yaml").write_text(text, encoding="utf-8")
        result = scan(tmp_path)
        tl013 = [f for f in result.findings if f.rule_id == "TL013"]
        assert [f.location for f in tl013] == ["Pod/unnamed"]
        assert tl013[0].line == 1

    def test_hostile_anchor_names_never_resolve_to_a_wrong_line(self, tmp_path: Path) -> None:
        # A workload named so that its document anchor collides with a
        # sibling container anchor ("Pod/p container evil" both ways) must
        # yield ambiguity (no line for either finding), never a guess.
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
            "spec:\n"
            "  containers:\n"
            "    - name: evil\n      image: img:1\n      securityContext:\n        privileged: true\n"
            "---\n"
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p container evil\n"
            "spec:\n  hostNetwork: true\n  containers: []\n"
        )
        (tmp_path / "pods.yaml").write_text(text, encoding="utf-8")
        result = scan(tmp_path)
        tl011 = [f for f in result.findings if f.rule_id == "TL011"]
        tl013 = [f for f in result.findings if f.rule_id == "TL013"]
        assert [f.location for f in tl011] == ["Pod/p container evil"]
        assert [f.location for f in tl013] == ["Pod/p container evil"]
        assert tl011[0].line is None
        assert tl013[0].line is None
