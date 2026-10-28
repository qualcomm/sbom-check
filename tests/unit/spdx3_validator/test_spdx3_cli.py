# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validator CLI."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

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
    ):
        result = CliRunner().invoke(main, [str(tmp_path)])

    assert result.exit_code == 1
    assert "bad.spdx.json" in result.output
    assert "good.spdx.json" in result.output
    assert "spdx3_validation_input_error" in result.output


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

    with patch("spdx3_validator.cli.validate_single_file") as validate_file:
        validate_file.return_value = (document, validation_result)
        result = CliRunner().invoke(main, [str(document)])

    assert result.exit_code == 4
