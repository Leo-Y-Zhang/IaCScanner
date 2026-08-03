"""The cross-file resource graph + reference resolver (iacscanner/graph.py).

The resolver's contract: resolve var/local chains to literals, recognise resource-address
references, and -- above all -- leave ANYTHING it cannot resolve as the literal ``${...}``
(missing refs, cycles, functions, data sources, too-deep nesting). Unresolved never becomes
a confident value, so the graph can only reduce false positives, never create one.
"""
from __future__ import annotations

import time

import hcl2

from iacscanner.graph import ResourceGraph, ResourceRef, ScanContext
from iacscanner.models import KIND_TERRAFORM, ScanFile
from iacscanner.parsers import _HCL2_OPTIONS


def _tf(name: str, text: str) -> ScanFile:
    data = hcl2.loads(text, serialization_options=_HCL2_OPTIONS)
    return ScanFile(path=name, kind=KIND_TERRAFORM, data=data, text=text)


def _graph(*files: tuple[str, str]) -> ResourceGraph:
    return ScanContext.build(tuple(_tf(n, t) for n, t in files)).graph


class TestVariableAndLocalResolution:
    def test_resolves_a_variable_default(self):
        g = _graph(("a.tf", 'variable "b" { default = "my-bucket" }'))
        assert g.resolve("${var.b}") == "my-bucket"

    def test_resolves_a_local(self):
        g = _graph(("a.tf", 'locals { region = "us-east-1" }'))
        assert g.resolve("${local.region}") == "us-east-1"

    def test_resolves_nested_interpolation(self):
        g = _graph(("a.tf", 'variable "b" { default = "data" }\nvariable "e" { default = "prod" }'))
        assert g.resolve("${var.b}-${var.e}-bucket") == "data-prod-bucket"

    def test_resolves_local_that_references_a_variable(self):
        g = _graph(("a.tf", 'variable "b" { default = "x" }\nlocals { full = "${var.b}-y" }'))
        assert g.resolve("${local.full}") == "x-y"

    def test_resolves_across_files(self):
        g = _graph(
            ("vars.tf", 'variable "b" { default = "shared-bucket" }'),
            ("main.tf", 'resource "aws_s3_bucket" "d" { bucket = var.b }'),
        )
        assert g.resolve("${var.b}") == "shared-bucket"

    def test_non_string_passes_through(self):
        g = _graph()
        assert g.resolve(True) is True
        assert g.resolve(42) == 42
        assert g.resolve(["a"]) == ["a"]

    def test_plain_string_passes_through(self):
        assert _graph().resolve("just-a-literal") == "just-a-literal"


class TestUnresolvedIsLeftLiteral:
    def test_missing_variable_is_left_literal(self):
        assert _graph().resolve("${var.absent}") == "${var.absent}"

    def test_missing_local_is_left_literal(self):
        assert _graph().resolve("${local.absent}") == "${local.absent}"

    def test_resource_attribute_is_left_literal(self):
        g = _graph(("a.tf", 'resource "aws_s3_bucket" "d" { bucket = "x" }'))
        assert g.resolve("${aws_s3_bucket.d.id}") == "${aws_s3_bucket.d.id}"

    def test_data_source_is_left_literal(self):
        assert _graph().resolve("${data.aws_ami.x.id}") == "${data.aws_ami.x.id}"

    def test_function_call_is_left_literal(self):
        g = _graph(("a.tf", 'variable "b" { default = "x" }'))
        assert g.resolve("${lower(var.b)}") == "${lower(var.b)}"

    def test_variable_without_default_is_left_literal(self):
        g = _graph(("a.tf", 'variable "b" { type = string }'))
        assert g.resolve("${var.b}") == "${var.b}"

    def test_partial_resolution_keeps_the_unresolved_part(self):
        g = _graph(("a.tf", 'variable "b" { default = "known" }'))
        assert g.resolve("${var.b}-${var.unknown}") == "known-${var.unknown}"


class TestCycleAndDepthSafety:
    def test_direct_cycle_is_left_literal(self):
        g = _graph(("a.tf", 'locals { x = "${local.x}" }'))
        assert g.resolve("${local.x}") == "${local.x}"

    def test_indirect_cycle_is_left_literal(self):
        g = _graph(("a.tf", 'locals { x = "${local.y}" }\nlocals { y = "${local.x}" }'))
        # neither resolves to a concrete value; the reference is returned unchanged
        result = g.resolve("${local.x}")
        assert "${local." in result

    def test_deep_resolution_terminates(self):
        # a long local chain (l7 -> l6 -> ... -> l1 -> var.v0) resolves without runaway recursion
        lines = ['variable "v0" { default = "base" }', 'locals { l1 = "${var.v0}" }']
        lines += ['locals { l' + str(i) + ' = "${local.l' + str(i - 1) + '}" }' for i in range(2, 8)]
        g = _graph(("a.tf", "\n".join(lines)))
        assert g.resolve("${local.l7}") == "base"


class TestResourceReferences:
    def test_extracts_a_resource_address(self):
        g = _graph()
        assert g.resolve_reference("${aws_s3_bucket.data.id}") == ResourceRef("aws_s3_bucket", "data")

    def test_extracts_address_ignoring_extra_attr_path(self):
        assert _graph().resolve_reference("${aws_s3_bucket.data.arn}") == ResourceRef("aws_s3_bucket", "data")

    def test_var_reference_is_not_a_resource_ref(self):
        assert _graph().resolve_reference("${var.b}") is None

    def test_reserved_namespaces_are_not_resource_refs(self):
        # module outputs / data sources / for_each / count / meta are not resource addresses;
        # treating them as such would defeat the unresolved-reference firewall.
        g = _graph()
        for expr in (
            "${module.naming.bucket_id}",
            "${data.aws_s3_bucket.existing.id}",
            "${each.value.id}",
            "${count.index}",
            "${local.x.y}",
            "${path.module.foo}",
        ):
            assert g.resolve_reference(expr) is None, expr

    def test_literal_is_not_a_resource_ref(self):
        assert _graph().resolve_reference("my-bucket") is None

    def test_non_string_is_not_a_resource_ref(self):
        assert _graph().resolve_reference(None) is None
        assert _graph().resolve_reference(123) is None


class TestCrossFileResourceIndex:
    def test_resources_span_all_files(self):
        g = _graph(
            ("a.tf", 'resource "aws_s3_bucket" "one" { bucket = "1" }'),
            ("b.tf", 'resource "aws_s3_bucket" "two" { bucket = "2" }'),
        )
        names = sorted(name for _, _, name, _ in g.resources("aws_s3_bucket"))
        assert names == ["one", "two"]

    def test_resources_filter_by_type(self):
        g = _graph(("a.tf", 'resource "aws_s3_bucket" "b" {}\nresource "aws_db_instance" "d" {}'))
        assert [t for _, t, _, _ in g.resources("aws_db_instance")] == ["aws_db_instance"]

    def test_has_resource_across_files(self):
        g = _graph(
            ("a.tf", 'resource "aws_s3_bucket" "b" {}'),
            ("b.tf", 'resource "aws_s3_bucket_public_access_block" "p" { bucket = aws_s3_bucket.b.id }'),
        )
        assert g.has_resource("aws_s3_bucket_public_access_block")
        assert not g.has_resource("aws_kms_key")


class TestDeterminismAndContext:
    def test_first_definition_wins_deterministically(self):
        g = _graph(
            ("a.tf", 'variable "b" { default = "first" }'),
            ("b.tf", 'variable "b" { default = "second" }'),
        )
        assert g.resolve("${var.b}") == "first"  # files arrive sorted; first wins

    def test_scan_context_is_frozen(self):
        import dataclasses
        ctx = ScanContext.build(())
        assert dataclasses.is_dataclass(ctx)
        try:
            ctx.files = ()  # type: ignore[misc]
        except dataclasses.FrozenInstanceError:
            return
        raise AssertionError("ScanContext should be frozen")

    def test_ignores_non_terraform_files(self):
        yaml_file = ScanFile(path="k.yaml", kind="kubernetes", data=[{"kind": "Pod"}], text="")
        g = ResourceGraph((yaml_file,))
        assert not g.has_resource("aws_s3_bucket")


def test_resolver_is_fast_on_a_hundred_file_tree():
    files = tuple(
        _tf(f"f{i}.tf", f'variable "v{i}" {{ default = "val{i}" }}\n'
                        f'resource "aws_s3_bucket" "b{i}" {{ bucket = var.v{i} }}')
        for i in range(100)
    )
    start = time.perf_counter()
    graph = ScanContext.build(files).graph
    for _, _, _, body in graph.resources("aws_s3_bucket"):
        graph.resolve(body.get("bucket"))
    assert time.perf_counter() - start < 1.0
