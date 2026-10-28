# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the standalone CycloneDX validation CLI."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

import cyclone_validator.cli as cyclone_cli
from cyclone_validator.cli import collect_cyclonedx_files, main

FIXTURES = Path(__file__).parents[2] / "fixtures" / "cyclonedx"


def invoke_cli(*arguments: str):
    """Invoke the CLI through Click's test runner."""
    return CliRunner().invoke(main, list(arguments))


def test_worker_reuses_its_validation_engine() -> None:
    cyclone_cli._worker_state.clear()
    try:
        with patch("cyclone_validator.cli.CycloneDXValidationEngine") as engine_class:
            engine = engine_class.return_value
            engine.validate_file.return_value = Mock()

            cyclone_cli._initialize_worker()
            cyclone_cli.validate_single_file(Path("first.cdx.json"))
            cyclone_cli.validate_single_file(Path("second.cdx.json"))

        engine_class.assert_called_once_with(enable_semantic_validation=False)
        assert engine.validate_file.call_count == 2
    finally:
        cyclone_cli._worker_state.clear()


def test_help_describes_cyclonedx_validation():
    result = invoke_cli("--help")

    assert result.exit_code == 0
    assert "Validate CycloneDX JSON documents" in result.output
    assert "--output-format" in result.output
    assert "--recursive" in result.output
    assert "Output format" in result.output
    assert "Number of parallel jobs" in result.output


def test_version_is_available():
    result = invoke_cli("--version")

    assert result.exit_code == 0
    assert "cyclonedx-validate" in result.output


def test_valid_document_passes_schema_validation():
    result = invoke_cli(
        "--output-format",
        "json",
        str(FIXTURES / "valid-1.7.json"),
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"] == {
        "total_files": 1,
        "valid_files": 1,
        "invalid_files": 0,
    }
    assert payload["results"][0]["is_valid"] is True
    assert payload["results"][0]["messages"] == []


def test_invalid_document_reports_schema_paths():
    result = invoke_cli(
        "--output-format",
        "json",
        str(FIXTURES / "invalid-1.7.json"),
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    validation_result = payload["results"][0]
    assert validation_result["is_valid"] is False
    assert {message["field_path"] for message in validation_result["messages"]} == {
        "$.citations[0].timestamp",
    }
    assert all(
        message["rule_id"] == "cyclonedx_schema_error"
        for message in validation_result["messages"]
    )


def test_unsupported_version_is_reported_as_structured_error(tmp_path):
    document = json.loads((FIXTURES / "valid-1.7.json").read_text())
    document["specVersion"] = "1.2"
    document_path = tmp_path / "unsupported.json"
    document_path.write_text(json.dumps(document))

    result = invoke_cli("--output-format", "json", str(document_path))

    assert result.exit_code == 1
    payload = json.loads(result.output)
    message = payload["results"][0]["messages"][0]
    assert message["rule_id"] == "unsupported_version"
    assert "1.2" in message["message"]


def test_recursive_validation_reports_summary_counts(tmp_path):
    input_directory = tmp_path / "documents"
    input_directory.mkdir()
    (input_directory / "valid.cdx.json").write_bytes(
        (FIXTURES / "valid-1.6.json").read_bytes()
    )
    (input_directory / "invalid.cdx.json").write_bytes(
        (FIXTURES / "invalid-1.6.json").read_bytes()
    )

    result = invoke_cli(
        "--recursive",
        "--output-format",
        "json",
        str(input_directory),
    )

    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["summary"] == {
        "total_files": 2,
        "valid_files": 1,
        "invalid_files": 1,
    }
    assert [Path(item["file"]).name for item in payload["results"]] == [
        "invalid.cdx.json",
        "valid.cdx.json",
    ]


@pytest.mark.parametrize("jobs", ["0", "-1"])
def test_jobs_must_be_positive(tmp_path, jobs):
    input_directory = tmp_path / "documents"
    input_directory.mkdir()

    result = invoke_cli("--jobs", jobs, "--recursive", str(input_directory))

    assert result.exit_code == 2
    assert "Invalid value for" in result.output
    assert jobs in result.output


def test_collection_deduplicates_paths(tmp_path):
    document = tmp_path / "document.json"
    document.write_text("{}")

    files = collect_cyclonedx_files(
        (document, tmp_path), recursive=False, pattern="*.json"
    )

    assert files == [document.resolve()]


def test_directory_scan_ignores_unrelated_json_files(tmp_path):
    input_directory = tmp_path / "documents"
    input_directory.mkdir()
    (input_directory / "supplier.cdx.json").write_bytes(
        (FIXTURES / "valid-1.7.json").read_bytes()
    )
    (input_directory / "config.json").write_text("{}")

    result = invoke_cli("--output-format", "json", str(input_directory))

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"] == {
        "total_files": 1,
        "valid_files": 1,
        "invalid_files": 0,
    }
