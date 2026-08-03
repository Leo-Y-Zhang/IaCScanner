"""Dockerfile rule pack (TL029-TL032): multi-stage aware, final-image scoped.

The false-positive discipline for Dockerfiles is STAGE ATTRIBUTION: a
misconfiguration written in a builder stage never reaches the shipped image,
so each rule fires only when the offending instruction lands in the FINAL
image - written in the final stage itself or inherited through a chain of
``FROM <internal stage>`` references. Builder-stage-only decoys must stay
silent, and anything unresolved (variables, unknown bases) falls back to
silence, never a guess.
"""
from __future__ import annotations

import json
from pathlib import Path

from conftest import parse_snippet, rule_ids
from iacscanner.docker import parse_dockerfile
from iacscanner.models import KIND_DOCKERFILE
from iacscanner.parsers import discover, parse_file
from iacscanner.rules import get_rule
from iacscanner.sarif import render_sarif
from iacscanner.scanner import scan


def _check(rule_id: str, tmp_path: Path, text: str):
    sf = parse_snippet(tmp_path, "Dockerfile", text)
    assert sf.kind == KIND_DOCKERFILE
    return get_rule(rule_id).check(sf)


def _ids(rule_id: str, tmp_path: Path, text: str) -> set[str]:
    return rule_ids(_check(rule_id, tmp_path, text))


# ------------------------------------------------------ discovery and parsing


class TestDiscoveryAndParsing:
    def test_dockerfile_is_discovered_and_parsed(self, tmp_path: Path) -> None:
        path = tmp_path / "Dockerfile"
        path.write_text("FROM alpine:3.20\n", encoding="utf-8")
        assert path in discover(tmp_path)
        sf = parse_file(path, "Dockerfile")
        assert sf.kind == KIND_DOCKERFILE
        assert sf.error is None

    def test_dockerfile_name_variants_are_discovered(self, tmp_path: Path) -> None:
        for name in ("app.dockerfile", "Containerfile", "dockerfile"):
            (tmp_path / name).write_text("FROM alpine:3.20\n", encoding="utf-8")
        (tmp_path / "notes.txt").write_text("not scanned", encoding="utf-8")
        names = {p.name for p in discover(tmp_path)}
        assert {"app.dockerfile", "Containerfile", "dockerfile"} <= names
        assert "notes.txt" not in names

    def test_dockerfile_dot_yaml_is_still_yaml(self, tmp_path: Path) -> None:
        sf = parse_snippet(tmp_path, "Dockerfile.yaml", "a: 1\n")
        assert sf.kind != KIND_DOCKERFILE

    def test_dockerfile_variant_names_are_discovered(self, tmp_path: Path) -> None:
        # The `docker build -f Dockerfile.prod` convention must not be a
        # silent recall hole: variant names are Dockerfiles unless their
        # extension already belongs to another scanned kind.
        for name in ("Dockerfile.prod", "Containerfile.dev"):
            (tmp_path / name).write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        (tmp_path / "notes.dockerfile.txt").write_text("FROM ubuntu:latest\n", encoding="utf-8")
        names = {p.name for p in discover(tmp_path)}
        assert {"Dockerfile.prod", "Containerfile.dev"} <= names
        assert "notes.dockerfile.txt" not in names
        sf = parse_file(tmp_path / "Dockerfile.prod", "Dockerfile.prod")
        assert sf.kind == KIND_DOCKERFILE
        assert sf.error is None

    def test_dockerfile_variant_with_iac_suffix_keeps_its_kind(self, tmp_path: Path) -> None:
        for name in ("Dockerfile.prod.yaml", "Containerfile.tf"):
            sf = parse_snippet(tmp_path, name, "a = 1\n")
            assert sf.kind != KIND_DOCKERFILE

    def test_stages_instructions_and_lines(self) -> None:
        model = parse_dockerfile(
            "FROM golang:1.22 AS build\n"
            "RUN go build ./...\n"
            "\n"
            "# a comment\n"
            "FROM alpine:3.20\n"
            "USER app\n"
        )
        assert len(model.stages) == 2
        build, final = model.stages
        assert (build.index, build.name, build.base, build.line) == (0, "build", "golang:1.22", 1)
        assert [i.cmd for i in build.instructions] == ["RUN"]
        assert (final.index, final.name, final.base, final.line) == (1, None, "alpine:3.20", 5)
        assert final.instructions[0].cmd == "USER"
        assert final.instructions[0].line == 6

    def test_line_continuation_joins_into_one_instruction(self) -> None:
        model = parse_dockerfile(
            "FROM alpine:3.20\nRUN apk update \\\n    && apk add curl\nUSER app\n"
        )
        (stage,) = model.stages
        assert [i.cmd for i in stage.instructions] == ["RUN", "USER"]
        assert stage.instructions[0].line == 2
        assert "apk add curl" in stage.instructions[0].args
        assert stage.instructions[1].line == 4

    def test_comment_inside_continuation_is_skipped(self) -> None:
        model = parse_dockerfile(
            "FROM alpine:3.20\nRUN apk update \\\n# comment inside\n    && apk add curl\n"
        )
        (stage,) = model.stages
        assert len(stage.instructions) == 1
        assert "apk add curl" in stage.instructions[0].args

    def test_escape_directive_switches_continuation_char(self) -> None:
        model = parse_dockerfile(
            "# escape=`\nFROM alpine:3.20\nRUN apk update `\n    && apk add curl\n"
        )
        (stage,) = model.stages
        assert len(stage.instructions) == 1
        assert "apk add curl" in stage.instructions[0].args

    def test_lowercase_instructions_are_normalized(self) -> None:
        model = parse_dockerfile("from alpine:3.20\nuser app\n")
        (stage,) = model.stages
        assert stage.base == "alpine:3.20"
        assert stage.instructions[0].cmd == "USER"

    def test_from_platform_flag_and_as_name(self) -> None:
        model = parse_dockerfile("FROM --platform=linux/amd64 ubuntu:22.04 AS base\n")
        (stage,) = model.stages
        assert stage.base == "ubuntu:22.04"
        assert stage.name == "base"

    def test_preamble_args_are_collected(self) -> None:
        model = parse_dockerfile('ARG BASE=ubuntu:22.04\nARG EMPTY\nFROM ${BASE}\n')
        assert dict(model.global_args) == {"BASE": "ubuntu:22.04"}

    def test_no_from_means_no_stages_and_no_findings(self, tmp_path: Path) -> None:
        text = "RUN echo hello\nUSER root\nEXPOSE 22\n"
        assert parse_dockerfile(text).stages == ()
        for rule_id in ("TL029", "TL030", "TL031", "TL032"):
            assert _ids(rule_id, tmp_path, text) == set()

    def test_parse_never_raises_on_garbage(self) -> None:
        for text in ("", "\\\n\\\n", "# escape=x\n\x00\xff FROM", "FROM\nAS\n=", "$" * 500):
            parse_dockerfile(text)  # must not raise


# --------------------------------------------------------------- heredocs


class TestHeredocs:
    """BuildKit heredoc bodies (syntax 1.4+, default in Docker 23+) are file
    or script CONTENT, never instructions: a FROM inside a heredoc must not
    fabricate a phantom stage, and USER/ENV/EXPOSE lines inside one must not
    fire rules against a genuinely clean final image."""

    _CLEAN_WITH_HEREDOC = (
        "FROM golang:1.22 AS build\n"
        "RUN go build ./...\n"
        "FROM alpine:3.20\n"
        "COPY <<CONF /app/inner.dockerfile\n"
        "FROM ubuntu:latest\n"
        "USER root\n"
        "EXPOSE 22\n"
        "ENV DB_PASSWORD=hunter2\n"
        "CONF\n"
        "USER app\n"
    )

    def test_heredoc_body_lines_are_not_instructions(self) -> None:
        model = parse_dockerfile(self._CLEAN_WITH_HEREDOC)
        assert len(model.stages) == 2
        final = model.stages[-1]
        assert [i.cmd for i in final.instructions] == ["COPY", "USER"]
        assert final.instructions[-1].line == 10

    def test_heredoc_body_produces_no_findings(self, tmp_path: Path) -> None:
        for rule_id in ("TL029", "TL030", "TL031", "TL032"):
            assert _ids(rule_id, tmp_path, self._CLEAN_WITH_HEREDOC) == set()

    def test_dash_variant_matches_tab_indented_terminator(self) -> None:
        model = parse_dockerfile(
            "FROM alpine:3.20\nRUN <<-EOF\n\tadduser -S app\n\tEOF\nUSER app\n"
        )
        (stage,) = model.stages
        assert [i.cmd for i in stage.instructions] == ["RUN", "USER"]

    def test_quoted_delimiters_and_multiple_heredocs_in_order(self) -> None:
        model = parse_dockerfile(
            "FROM alpine:3.20\n"
            "COPY <<'A' <<\"B\" /dest/\n"
            "USER root\n"
            "A\n"
            "EXPOSE 22\n"
            "B\n"
            "USER app\n"
        )
        (stage,) = model.stages
        assert [i.cmd for i in stage.instructions] == ["COPY", "USER"]
        assert stage.instructions[-1].args == "app"
        assert stage.instructions[-1].line == 7

    def test_unterminated_heredoc_consumes_to_eof_silently(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nRUN <<EOF\nUSER root\nEXPOSE 22\n"
        (stage,) = parse_dockerfile(text).stages
        assert [i.cmd for i in stage.instructions] == ["RUN"]
        for rule_id in ("TL029", "TL032"):
            assert _ids(rule_id, tmp_path, text) == set()

    def test_shell_shift_operator_is_not_a_heredoc(self, tmp_path: Path) -> None:
        # $((1<<8)) must not swallow the following lines as heredoc content.
        text = "FROM alpine:3.20\nRUN echo $((1<<8))\nUSER root\n"
        assert "TL029" in _ids("TL029", tmp_path, text)

    def test_onbuild_run_heredoc_body_is_skipped(self) -> None:
        model = parse_dockerfile(
            "FROM alpine:3.20\nONBUILD RUN <<EOF\nUSER root\nEOF\nUSER app\n"
        )
        (stage,) = model.stages
        assert [i.cmd for i in stage.instructions] == ["ONBUILD", "USER"]

    def test_heredoc_marker_on_non_run_copy_add_is_literal(self) -> None:
        # Docker defines heredocs only on RUN/COPY/ADD; ENV keeps its text.
        model = parse_dockerfile("FROM alpine:3.20\nENV X=<<EOF\nUSER app\n")
        (stage,) = model.stages
        assert [i.cmd for i in stage.instructions] == ["ENV", "USER"]


# ------------------------------------------------- continuation fidelity


class TestContinuationFidelity:
    """Docker removes the escape character and the newline and joins with NO
    separator, so arguments split across lines reassemble byte-for-byte."""

    def test_continuation_joins_without_inserted_space(self) -> None:
        (stage,) = parse_dockerfile("FROM alpine:3.20\nRUN echo hel\\\nlo\n").stages
        assert stage.instructions[0].args == "echo hello"

    def test_split_pinned_from_ref_reassembles_and_stays_silent(self, tmp_path: Path) -> None:
        text = "FROM registry.example.com/team/service\\\n:1.2.3\nUSER app\n"
        model = parse_dockerfile(text)
        assert model.stages[0].base == "registry.example.com/team/service:1.2.3"
        assert _ids("TL031", tmp_path, text) == set()

    def test_split_env_secret_reassembles_and_fires(self, tmp_path: Path) -> None:
        text = "# escape=`\nFROM alpine:3.20\nENV APP_PASSWORD=`\nnot-a-real-secret\n"
        assert "TL030" in _ids("TL030", tmp_path, text)


# --------------------------------------------------------- TL029: root user


class TestTL029RootUser:
    def test_user_root_in_final_stage_fires(self, tmp_path: Path) -> None:
        assert "TL029" in _ids("TL029", tmp_path, "FROM alpine:3.20\nUSER root\n")

    def test_user_uid_zero_fires(self, tmp_path: Path) -> None:
        assert "TL029" in _ids("TL029", tmp_path, "FROM alpine:3.20\nUSER 0\n")

    def test_user_root_with_group_fires(self, tmp_path: Path) -> None:
        assert "TL029" in _ids("TL029", tmp_path, "FROM alpine:3.20\nUSER root:wheel\n")

    def test_named_user_silent(self, tmp_path: Path) -> None:
        assert _ids("TL029", tmp_path, "FROM alpine:3.20\nUSER app\n") == set()

    def test_omitted_user_silent(self, tmp_path: Path) -> None:
        # The base image's default user is unknown: omitted -> never guessed.
        assert _ids("TL029", tmp_path, "FROM alpine:3.20\nRUN echo hi\n") == set()

    def test_variable_user_silent(self, tmp_path: Path) -> None:
        assert _ids("TL029", tmp_path, "FROM alpine:3.20\nUSER $APP_UID\n") == set()

    def test_root_only_in_builder_stage_silent(self, tmp_path: Path) -> None:
        text = "FROM golang:1.22 AS build\nUSER root\nFROM alpine:3.20\nUSER app\n"
        assert _ids("TL029", tmp_path, text) == set()

    def test_later_user_in_final_stage_drops_root(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nUSER root\nRUN apk add curl\nUSER app\n"
        assert _ids("TL029", tmp_path, text) == set()

    def test_root_inherited_through_stage_chain_fires(self, tmp_path: Path) -> None:
        text = "FROM golang:1.22 AS build\nUSER root\nFROM build\nRUN echo hi\n"
        findings = _check("TL029", tmp_path, text)
        assert [f.rule_id for f in findings] == ["TL029"]
        assert findings[0].location == "stage[build].USER[0]"
        assert "inherited from stage 'build'" in findings[0].message

    def test_final_stage_anchor_format(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20 AS runtime\nUSER root\n"
        (finding,) = _check("TL029", tmp_path, text)
        assert finding.location == "stage[runtime].USER[0]"


# --------------------------------------------------- TL030: baked env secret


class TestTL030EnvSecret:
    def test_literal_password_env_fires(self, tmp_path: Path) -> None:
        text = 'FROM alpine:3.20\nENV DB_PASSWORD="hunter2-not-real"\n'
        assert "TL030" in _ids("TL030", tmp_path, text)

    def test_legacy_space_form_fires(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nENV DB_PASSWORD hunter2-not-real\n"
        assert "TL030" in _ids("TL030", tmp_path, text)

    def test_multiple_pairs_fire_only_on_secret_names(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nENV APP_MODE=prod GITHUB_TOKEN=dummy-value-1234\n"
        findings = _check("TL030", tmp_path, text)
        assert len(findings) == 1
        assert "GITHUB_TOKEN" in findings[0].message

    def test_value_is_masked_in_message(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nENV API_SECRET=super-long-not-a-real-secret\n"
        (finding,) = _check("TL030", tmp_path, text)
        assert "super-long-not-a-real-secret" not in finding.message

    def test_variable_reference_silent(self, tmp_path: Path) -> None:
        assert _ids("TL030", tmp_path, "FROM alpine:3.20\nENV DB_PASSWORD=$SECRET_REF\n") == set()

    def test_empty_value_silent(self, tmp_path: Path) -> None:
        assert _ids("TL030", tmp_path, 'FROM alpine:3.20\nENV DB_PASSWORD=""\n') == set()

    def test_path_pointer_value_silent(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nENV DB_PASSWORD=/run/secrets/db_password\n"
        assert _ids("TL030", tmp_path, text) == set()

    def test_non_secret_suffix_silent(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20\nENV API_TOKEN_URL=https://auth.example.com/token\n"
        assert _ids("TL030", tmp_path, text) == set()

    def test_builder_only_env_secret_silent(self, tmp_path: Path) -> None:
        # An ENV value in a discarded builder stage never reaches the final image.
        text = (
            "FROM golang:1.22 AS build\nENV NPM_TOKEN=dummy-build-token\n"
            "FROM alpine:3.20\nUSER app\n"
        )
        assert _ids("TL030", tmp_path, text) == set()

    def test_inherited_env_secret_fires(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20 AS base\nENV API_SECRET=not-a-real-secret\nFROM base\nUSER app\n"
        (finding,) = _check("TL030", tmp_path, text)
        assert finding.location == "stage[base].ENV[0]"
        assert "inherited from stage 'base'" in finding.message

    def test_overwritten_secret_still_fires(self, tmp_path: Path) -> None:
        # The literal value persists in the final image's layer history even
        # when a later instruction overwrites the variable.
        text = "FROM alpine:3.20\nENV DB_PASSWORD=leaked-anyway\nENV DB_PASSWORD=$RUNTIME\n"
        assert "TL030" in _ids("TL030", tmp_path, text)


# ------------------------------------------------------ TL031: mutable base


class TestTL031MutableBase:
    def test_latest_tag_fires(self, tmp_path: Path) -> None:
        assert "TL031" in _ids("TL031", tmp_path, "FROM ubuntu:latest\n")

    def test_untagged_fires(self, tmp_path: Path) -> None:
        assert "TL031" in _ids("TL031", tmp_path, "FROM ubuntu\n")

    def test_pinned_tag_silent(self, tmp_path: Path) -> None:
        assert _ids("TL031", tmp_path, "FROM ubuntu:22.04\n") == set()

    def test_digest_pinned_silent(self, tmp_path: Path) -> None:
        text = "FROM ubuntu:latest@sha256:0000000000000000000000000000000000000000000000000000000000000000\n"
        assert _ids("TL031", tmp_path, text) == set()

    def test_scratch_silent(self, tmp_path: Path) -> None:
        assert _ids("TL031", tmp_path, "FROM scratch\n") == set()

    def test_builder_latest_with_pinned_final_silent(self, tmp_path: Path) -> None:
        text = "FROM golang:latest AS build\nRUN go build ./...\nFROM alpine:3.20\nUSER app\n"
        assert _ids("TL031", tmp_path, text) == set()

    def test_latest_reaching_final_through_stage_chain_fires(self, tmp_path: Path) -> None:
        text = "FROM golang:latest AS build\nRUN go build ./...\nFROM build\nUSER app\n"
        (finding,) = _check("TL031", tmp_path, text)
        assert finding.location == "stage[build].FROM"
        assert "golang:latest" in finding.message

    def test_arg_default_resolves_and_fires(self, tmp_path: Path) -> None:
        text = "ARG BASE=ubuntu:latest\nFROM ${BASE}\n"
        assert "TL031" in _ids("TL031", tmp_path, text)

    def test_unresolved_arg_silent(self, tmp_path: Path) -> None:
        assert _ids("TL031", tmp_path, "ARG BASE\nFROM ${BASE}\n") == set()

    def test_registry_port_untagged_fires(self, tmp_path: Path) -> None:
        assert "TL031" in _ids("TL031", tmp_path, "FROM registry.example.com:5000/app\n")

    def test_registry_port_tagged_silent(self, tmp_path: Path) -> None:
        assert _ids("TL031", tmp_path, "FROM registry.example.com:5000/app:1.2.3\n") == set()

    def test_base_matching_a_stage_name_silent(self, tmp_path: Path) -> None:
        # `FROM build` before the stage exists is a broken build, not an
        # untagged image pull; never guess.
        text = "FROM build\nUSER app\nFROM alpine:3.20 AS build\nUSER app\n"
        assert _ids("TL031", tmp_path, text) == set()


# ---------------------------------------------------- TL032: SSH port expose


class TestTL032ExposeSsh:
    def test_expose_22_fires(self, tmp_path: Path) -> None:
        assert "TL032" in _ids("TL032", tmp_path, "FROM alpine:3.20\nEXPOSE 22\n")

    def test_expose_22_tcp_fires(self, tmp_path: Path) -> None:
        assert "TL032" in _ids("TL032", tmp_path, "FROM alpine:3.20\nEXPOSE 22/tcp\n")

    def test_other_port_silent(self, tmp_path: Path) -> None:
        assert _ids("TL032", tmp_path, "FROM alpine:3.20\nEXPOSE 8080\n") == set()

    def test_udp_22_silent(self, tmp_path: Path) -> None:
        assert _ids("TL032", tmp_path, "FROM alpine:3.20\nEXPOSE 22/udp\n") == set()

    def test_variable_port_silent(self, tmp_path: Path) -> None:
        assert _ids("TL032", tmp_path, "FROM alpine:3.20\nEXPOSE $SSH_PORT\n") == set()

    def test_builder_only_expose_silent(self, tmp_path: Path) -> None:
        text = "FROM golang:1.22 AS build\nEXPOSE 22\nFROM alpine:3.20\nUSER app\n"
        assert _ids("TL032", tmp_path, text) == set()

    def test_inherited_expose_fires(self, tmp_path: Path) -> None:
        text = "FROM alpine:3.20 AS base\nEXPOSE 22\nFROM base\nUSER app\n"
        (finding,) = _check("TL032", tmp_path, text)
        assert finding.location == "stage[base].EXPOSE[0]"


# ------------------------------------------------ lines, suppression, output


class TestLinesAndIntegration:
    def test_anchors_resolve_to_source_lines(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "FROM golang:1.22 AS build\n"   # 1
            "USER root\n"                    # 2 (builder: silent)
            "FROM ubuntu:latest\n"           # 3 -> TL031
            "ENV DB_PASSWORD=not-real\n"     # 4 -> TL030
            "EXPOSE 22\n"                    # 5 -> TL032
            "USER root\n",                   # 6 -> TL029
            encoding="utf-8",
        )
        result = scan(tmp_path)
        lines = {(f.rule_id, f.location): f.line for f in result.findings}
        assert lines[("TL031", "stage[1].FROM")] == 3
        assert lines[("TL030", "stage[1].ENV[0]")] == 4
        assert lines[("TL032", "stage[1].EXPOSE[0]")] == 5
        assert lines[("TL029", "stage[1].USER[0]")] == 6

    def test_duplicate_stage_names_omit_the_line(self, tmp_path: Path) -> None:
        # Docker rejects duplicate stage names; if a file carries them anyway
        # the anchor is ambiguous and the line is omitted, never guessed.
        (tmp_path / "Dockerfile").write_text(
            "FROM alpine:3.19 AS app\nUSER root\nFROM alpine:3.19 AS app\nUSER root\n",
            encoding="utf-8",
        )
        result = scan(tmp_path)
        tl029 = [f for f in result.findings if f.rule_id == "TL029"]
        assert len(tl029) == 1  # final stage only
        assert tl029[0].line is None

    def test_inline_suppression_works_in_dockerfiles(self, tmp_path: Path) -> None:
        (tmp_path / "Dockerfile").write_text(
            "# themis:ignore TL029\nFROM alpine:3.20\nUSER root\n", encoding="utf-8"
        )
        result = scan(tmp_path)
        assert "TL029" not in rule_ids(result.findings)
        assert result.inline_suppressed_count == 1

    def test_vulnerable_docker_fixture_fires_exactly_the_pack(self, docker_vulnerable_result) -> None:
        assert rule_ids(docker_vulnerable_result.findings) == {"TL029", "TL030", "TL031", "TL032"}
        assert docker_vulnerable_result.parse_error_count == 0

    def test_secure_docker_fixture_is_fully_clean(self, docker_secure_result) -> None:
        assert docker_secure_result.findings == []
        assert docker_secure_result.parse_error_count == 0

    def test_fixture_findings_attribute_to_the_final_stage(self, docker_vulnerable_result) -> None:
        # The builder stage is named "build"; every finding must anchor into
        # the final "runtime" stage even though the builder also exists.
        for finding in docker_vulnerable_result.findings:
            assert finding.location.startswith("stage[runtime].")

    def test_sarif_output_stays_valid_with_dockerfile_findings(self, docker_vulnerable_result) -> None:
        log = json.loads(render_sarif(docker_vulnerable_result, docker_vulnerable_result.findings))
        assert log["version"] == "2.1.0"
        run = log["runs"][0]
        rule_count = len(run["tool"]["driver"]["rules"])
        assert {r["ruleId"] for r in run["results"]} == {"TL029", "TL030", "TL031", "TL032"}
        for res in run["results"]:
            assert 0 <= res["ruleIndex"] < rule_count
            uri = res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            assert "\\" not in uri
