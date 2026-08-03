"""Cross-file accuracy for the graph-migrated S3 rules (TL002/TL007/TL008).

The point of the ResourceGraph: a bucket and its companion public-access-block / encryption
/ versioning / logging resources may live in DIFFERENT files. These rules must resolve that
pairing across the whole scan (no false positive) while still firing when the companion is
genuinely absent (no false negative).
"""
from __future__ import annotations

from pathlib import Path

from iacscanner.scanner import scan

_BUCKET = 'resource "aws_s3_bucket" "data" { bucket = "my-data" }\n'
_COMPANIONS = """
resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = "log-bucket"
  target_prefix = "s3/"
}
"""


def _s3_findings(target: Path) -> set[str]:
    return {f.rule_id for f in scan(target).findings if f.rule_id in {"TL002", "TL007", "TL008"}}


def _write(dirpath: Path, **files: str) -> Path:
    for name, text in files.items():
        (dirpath / name).write_text(text, encoding="utf-8")
    return dirpath


class TestCrossFileBindingSilencesFindings:
    def test_companions_in_a_separate_file_bind_by_resource_address(self, tmp_path: Path) -> None:
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": _COMPANIONS})
        assert _s3_findings(tmp_path) == set()

    def test_companion_binds_by_literal_bucket_name(self, tmp_path: Path) -> None:
        pab = _COMPANIONS.replace("aws_s3_bucket.data.id", '"my-data"')
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": pab})
        assert _s3_findings(tmp_path) == set()

    def test_companion_binds_through_a_variable(self, tmp_path: Path) -> None:
        main = 'variable "b" { default = "my-data" }\nresource "aws_s3_bucket" "data" { bucket = var.b }\n'
        pab = _COMPANIONS.replace("aws_s3_bucket.data.id", "var.b")
        _write(tmp_path, **{"main.tf": main, "security.tf": pab})
        assert _s3_findings(tmp_path) == set()


class TestMissingCompanionStillFires:
    def test_bucket_with_no_companions_fires_all_three(self, tmp_path: Path) -> None:
        _write(tmp_path, **{"main.tf": _BUCKET})
        assert _s3_findings(tmp_path) == {"TL002", "TL007", "TL008"}

    def test_a_weak_public_access_block_still_fires_tl002(self, tmp_path: Path) -> None:
        weak = _COMPANIONS.replace("block_public_policy     = true", "block_public_policy     = false")
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": weak})
        assert "TL002" in _s3_findings(tmp_path)

    def test_companion_bound_to_a_different_bucket_does_not_help(self, tmp_path: Path) -> None:
        # the PAB protects "other", not "data" -> "data" is still unprotected
        other = _COMPANIONS.replace("aws_s3_bucket.data.id", '"someone-else"')
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": other})
        assert "TL002" in _s3_findings(tmp_path)


class TestNoFalsePositiveRegression:
    def test_old_file_scoped_false_positive_is_gone(self, tmp_path: Path) -> None:
        # exactly the pattern the old file-scoped rule mis-flagged: bucket alone in its file,
        # fully protected by companions in another file.
        _write(tmp_path, **{"buckets.tf": _BUCKET, "hardening.tf": _COMPANIONS})
        assert _s3_findings(tmp_path) == set()


class TestReservedNamespaceBindingsAreNotFabricated:
    """A companion whose bucket binds via a module output / data source / for_each is an
    UNRESOLVED reference, not a resource address -- it must fall through the firewall and
    count as coverage, never manufacture a false positive on a hardened bucket."""

    def test_companion_binds_via_module_output(self, tmp_path: Path) -> None:
        comp = _COMPANIONS.replace("aws_s3_bucket.data.id", "module.naming.bucket_id")
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": comp})
        assert _s3_findings(tmp_path) == set()

    def test_companion_binds_via_data_source(self, tmp_path: Path) -> None:
        comp = _COMPANIONS.replace("aws_s3_bucket.data.id", "data.aws_s3_bucket.existing.id")
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": comp})
        assert _s3_findings(tmp_path) == set()

    def test_companion_binds_via_for_each(self, tmp_path: Path) -> None:
        comp = _COMPANIONS.replace("aws_s3_bucket.data.id", "each.value.id")
        _write(tmp_path, **{"main.tf": _BUCKET, "security.tf": comp})
        assert _s3_findings(tmp_path) == set()
