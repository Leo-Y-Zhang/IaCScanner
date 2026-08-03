"""Inline ``# themis:ignore`` suppressions (iacscanner/suppress.py + scanner integration)."""
from __future__ import annotations

from pathlib import Path

from iacscanner.scanner import scan
from iacscanner.suppress import parse_suppressions, parse_suppressions_with_warnings


class TestParse:
    def test_ignore_all(self) -> None:
        s = parse_suppressions("acl = 1  # themis:ignore")
        assert s.all_rules and s.suppresses("TL001") and s.suppresses("TL999")

    def test_ignore_specific_ids(self) -> None:
        s = parse_suppressions("x  # themis:ignore TL005, TL010")
        assert not s.all_rules
        assert s.rule_ids == frozenset({"TL005", "TL010"})
        assert s.suppresses("TL005") and not s.suppresses("TL001")

    def test_dash_and_case_variants(self) -> None:
        assert parse_suppressions("# THEMIS-IGNORE TL001").suppresses("TL001")
        assert parse_suppressions("#themis:ignore TL002").suppresses("TL002")

    def test_hash_inside_a_string_is_not_a_comment(self) -> None:
        s = parse_suppressions('password = "abc#themis:ignore-me"')
        assert not s.all_rules and not s.rule_ids

    def test_single_quoted_string_is_also_safe(self) -> None:
        assert parse_suppressions("x = 'a # themis:ignore'").rule_ids == frozenset()

    def test_multiple_comments_accumulate(self) -> None:
        text = "a # themis:ignore TL001\nb # themis:ignore TL002"
        assert parse_suppressions(text).rule_ids == frozenset({"TL001", "TL002"})

    def test_no_comment_is_empty(self) -> None:
        s = parse_suppressions("just some code")
        assert not s.all_rules and not s.rule_ids

    def test_marker_after_an_escaped_quote_stays_inside_the_string(self) -> None:
        # `password = "abc\"#themis:ignore TL010"` -- the \" is escaped, so the # is still
        # inside the string and must NOT arm a suppression (escape-aware comment detection).
        s = parse_suppressions('password = "abc\\"#themis:ignore TL010"')
        assert not s.all_rules and not s.rule_ids


class TestMalformedRuleIdWarns:
    def test_typo_id_warns_and_suppresses_nothing(self) -> None:
        s, warnings = parse_suppressions_with_warnings("x  # themis:ignore TL01")
        assert not s.all_rules and not s.rule_ids  # fail closed, never a silent ignore-all
        assert any("TL01" in w for w in warnings)

    def test_too_many_digits_warns_and_does_not_bind(self) -> None:
        s, warnings = parse_suppressions_with_warnings("x  # themis:ignore TL9999")
        assert not s.all_rules and s.rule_ids == frozenset()
        assert any("TL9999" in w for w in warnings)

    def test_bare_ignore_has_no_warning(self) -> None:
        s, warnings = parse_suppressions_with_warnings("acl = 1  # themis:ignore")
        assert s.all_rules and warnings == []

    def test_valid_id_has_no_warning(self) -> None:
        s, warnings = parse_suppressions_with_warnings("x  # themis:ignore TL010")
        assert s.rule_ids == frozenset({"TL010"}) and warnings == []


class TestScannerIntegration:
    def test_specific_suppression_removes_only_that_rule(self, tmp_path: Path) -> None:
        (tmp_path / "a.tf").write_text(
            'resource "aws_s3_bucket" "b" { acl = "public-read" }  # themis:ignore TL001\n'
            'resource "aws_ebs_volume" "v" { encrypted = false }\n'
        )
        result = scan(tmp_path)
        ids = {f.rule_id for f in result.findings}
        assert "TL001" not in ids
        assert "TL006" in ids  # the unencrypted volume still fires
        assert result.inline_suppressed_count >= 1

    def test_ignore_all_clears_the_file(self, tmp_path: Path) -> None:
        (tmp_path / "a.tf").write_text(
            '# themis:ignore\nresource "aws_s3_bucket" "b" { acl = "public-read" }\n'
        )
        assert scan(tmp_path).findings == []

    def test_suppression_is_scoped_to_its_file(self, tmp_path: Path) -> None:
        (tmp_path / "a.tf").write_text(
            'resource "aws_s3_bucket" "b" { acl = "public-read" }  # themis:ignore TL001\n'
        )
        (tmp_path / "b.tf").write_text('resource "aws_s3_bucket" "c" { acl = "public-read" }\n')
        ids_by_path = {(f.path, f.rule_id) for f in scan(tmp_path).findings}
        assert ("a.tf", "TL001") not in ids_by_path
        assert ("b.tf", "TL001") in ids_by_path  # the other file is unaffected

    def test_typo_suppression_does_not_clear_the_file_and_warns(self, tmp_path: Path) -> None:
        (tmp_path / "a.tf").write_text(
            'resource "aws_s3_bucket" "b" { acl = "public-read" }  # themis:ignore TL01\n'
        )
        result = scan(tmp_path)
        assert "TL001" in {f.rule_id for f in result.findings}  # NOT silently ignore-all
        assert any("TL01" in w for w in result.suppression_warnings)
