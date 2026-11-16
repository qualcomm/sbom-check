# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validator CLI."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from click.testing import CliRunner
from spdx3_validate.core import SpdxValidateError

from spdx3_validator.cli import main
from spdx3_validator.models import (
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)


def test_jobs_must_be_positive(tmp_path):
    """Reject zero jobs before creating a process pool."""
    document = tmp_path / "document.spdx.json"
    document.write_text("{}", encoding="utf-8")

    result = CliRunner().invoke(main, ["--jobs", "0", str(document)])

    assert result.exit_code == 2
    assert "Invalid value for '--jobs'" in result.output


def test_batch_continues_when_one_file_has_structured_input_error(tmp_path):
    """Report a malformed file without aborting validation of the batch."""
    good = tmp_path / "good.spdx.json"
    bad = tmp_path / "bad.spdx.json"
    good.write_text("{}", encoding="utf-8")
    bad.write_text("{}", encoding="utf-8")

    valid_result = ValidationResult(
        is_valid=True,
        schema_valid=True,
        semantic_valid=True,
        messages=[],
    )
    invalid_result = ValidationResult(
        is_valid=False,
        schema_valid=False,
        semantic_valid=False,
        messages=[
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message="Invalid SPDX 3 validation input: malformed node",
                rule_id="spdx3_validation_input_error",
            )
        ],
    )

    def validate_file(file_path: Path):
        return file_path, invalid_result if file_path == bad else valid_result

    with (
        patch("spdx3_validator.cli.ProcessPoolExecutor", ThreadPoolExecutor),
        patch("spdx3_validator.cli.validate_single_file", side_effect=validate_file),
        patch("spdx3_validator.cli.configure_network_timeout") as configure_timeout,
    ):
        result = CliRunner().invoke(main, [str(tmp_path)])

    configure_timeout.assert_called()
    assert result.exit_code == 1
    assert "bad.spdx.json" in result.output
    assert "good.spdx.json" in result.output
    assert "spdx3_validation_input_error" in result.output


def test_worker_reuses_remote_failure_without_masking_local_errors(tmp_path):
    """Cache a valid document's outage but still report later local errors."""
    valid_document = (
        Path(__file__).resolve().parents[2] / "fixtures" / "minimal-spdx3.0.1.spdx.json"
    ).read_text(encoding="utf-8")
    (tmp_path / "a-first.spdx.json").write_text(valid_document, encoding="utf-8")
    (tmp_path / "b-second.spdx.json").write_text(valid_document, encoding="utf-8")
    (tmp_path / "c-missing-context.spdx.json").write_text("{}", encoding="utf-8")

    with (
        patch("spdx3_validator.cli.ProcessPoolExecutor", ThreadPoolExecutor),
        patch(
            "spdx3_validator.engine.ValidationEngine._validate_document",
            side_effect=URLError("network disabled"),
        ) as validate_document,
    ):
        result = CliRunner().invoke(main, ["--jobs", "1", str(tmp_path)])

    assert result.exit_code == 4
    assert result.output.count("remote_resource_unavailable") == 2
    assert "spdx3_missing_context" in result.output
    validate_document.assert_called_once()


def test_cli_reports_broken_upstream_schema_as_resource_failure(tmp_path):
    """A broken upstream schema is an incomplete validation, not bad SBOM data."""
    document = tmp_path / "document.spdx.json"
    document.write_text(
        '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld","@graph":[]}',
        encoding="utf-8",
    )
    parsed_document = MagicMock(data={"@graph": []}, source="document")

    with (
        patch(
            "spdx3_validator.engine.Document.from_text",
            return_value=parsed_document,
        ),
        patch(
            "spdx3_validator.engine.load_validation_resources",
            side_effect=SpdxValidateError("Invalid schema: broken upstream schema"),
        ),
    ):
        result = CliRunner().invoke(main, [str(document)])

    assert result.exit_code == 4
    assert "remote_resource_unavailable" in result.output
    assert "Invalid schema: broken upstream schema" in result.output


def test_remote_resource_failure_has_distinct_exit_code(tmp_path):
    """Use a distinct exit code when SPDX resources are unavailable."""
    document = tmp_path / "document.spdx.json"
    document.write_text("{}", encoding="utf-8")
    validation_result = ValidationResult(
        is_valid=False,
        schema_valid=None,
        semantic_valid=None,
        messages=[
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message="remote resource unavailable",
                rule_id="remote_resource_unavailable",
            )
        ],
    )

    with (
        patch("spdx3_validator.cli.validate_single_file") as validate_file,
        patch("spdx3_validator.cli.configure_network_timeout") as configure_timeout,
    ):
        validate_file.return_value = (document, validation_result)
        result = CliRunner().invoke(main, [str(document)])

    configure_timeout.assert_called_once_with()
    assert result.exit_code == 4
