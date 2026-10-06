# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for CLI module."""

import json
import re
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest
from click.testing import CliRunner

from sbom_check.cli import (
    _expand_pattern,
    _print_json_result,
    _print_text_result,
    collect_sbom_files,
    main,
)


def test_expand_pattern_supports_multiple_brace_groups():
    """Brace groups expand recursively rather than leaving later groups literal."""
    assert _expand_pattern("*.{a,b}.{c,d}.json") == (
        "*.a.c.json",
        "*.a.d.json",
        "*.b.c.json",
        "*.b.d.json",
    )


def test_expand_pattern_supports_empty_alternatives():
    """Empty brace alternatives remain valid shell-style expansions."""
    assert _expand_pattern("*.{spdx,}.json") == ("*.spdx.json", "*..json")


def test_expand_pattern_rejects_unmatched_closing_brace():
    """Malformed brace ordering produces a clear validation error."""
    with pytest.raises(ValueError, match=r"unmatched '\}'"):
        _expand_pattern("*.}a{.json")



def test_cli_reports_malformed_pattern_without_traceback(tmp_path):
    """Malformed --pattern input is reported as a user-facing CLI error."""
    result = CliRunner().invoke(
        main,
        ["--pattern", "*.}a{.json", str(tmp_path)],
    )

    assert result.exit_code == 3
    assert "Error: Invalid brace pattern" in result.output
    assert "Traceback" not in result.output



@pytest.mark.parametrize(
    ("pattern", "expected"),
    [
        ("*.json", ("*.json",)),
        ("*.{a,b}.json", ("*.a.json", "*.b.json")),
        (
            "*.{a,b}.{c,d}.json",
            ("*.a.c.json", "*.a.d.json", "*.b.c.json", "*.b.d.json"),
        ),
        ("x{a,{b,c}}y", ("xay", "xby", "xcy")),
        ("*.{spdx,}.json", ("*.spdx.json", "*..json")),
        ("{BOOT}.*.{spdx,cdx}.json", ("BOOT.*.spdx.json", "BOOT.*.cdx.json")),
        ("{}", ("",)),
        ("{foo,bar}[0-9]?.json", ("foo[0-9]?.json", "bar[0-9]?.json")),
        ("{a,a}.{b,b}", ("a.b", "a.b", "a.b", "a.b")),
    ],
)
def test_expand_pattern_matrix(pattern, expected):
    """Representative glob syntax expands without losing literal characters."""
    assert _expand_pattern(pattern) == expected


@pytest.mark.parametrize(
    "pattern",
    [
        "*.}a{.json",
        "*.{a,b.json",
        "*.a}b",
        "{a,{b,c}",
        "{a,b}}",
        "a{b{c}",
    ],
)
def test_expand_pattern_rejects_malformed_patterns(pattern):
    """Every malformed brace shape raises a useful error for the full pattern."""
    with pytest.raises(ValueError, match=re.escape(f"Invalid brace pattern {pattern!r}")):
        _expand_pattern(pattern)


def test_expand_pattern_rejects_pathological_expansion():
    """Brace expansion is bounded for hostile or accidental combinatorial input."""
    pattern = "".join("{a,b}" for _ in range(11))
    with pytest.raises(ValueError, match="more than 1024 patterns"):
        _expand_pattern(pattern)



@pytest.mark.parametrize(
    "pattern",
    [
        "*.}a{.json",
        "*.{a,b.json",
        "*.a}b",
        "{a,{b,c}",
        "{a,b}}",
        "a{b{c}",
    ],
)
def test_cli_rejects_invalid_patterns_without_traceback(tmp_path, pattern):
    """Invalid --pattern values fail cleanly at the CLI boundary."""
    result = CliRunner().invoke(main, ["--pattern", pattern, str(tmp_path)])

    assert result.exit_code == 3
    assert "Error: Invalid brace pattern" in result.output
    assert "Traceback" not in result.output


def test_cli_help():
    """Test CLI help command."""
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "Validate SPDX and CycloneDX JSON SBOM documents" in result.output
    assert "--profile" in result.output
    assert "--config" in result.output
    assert "--output-format" in result.output
    assert "default: *.{spdx,cdx}.json" in result.output


def test_cli_version():
    """Test CLI version command."""
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])

    assert result.exit_code == 0
    assert "sbom-check, version" in result.output
    # Version should contain some version info (could be dev version or numeric)
    assert ("dev" in result.output) or any(char.isdigit() for char in result.output)


def test_cli_list_profiles():
    """Test CLI list profiles command."""
    runner = CliRunner()
    result = runner.invoke(main, ["--list-profiles"])

    assert result.exit_code == 0
    assert "Available Configuration Profiles" in result.output
    assert "basic_spdx" in result.output
    assert "default" in result.output


def test_cli_generate_config():
    """Test CLI generate config command."""
    runner = CliRunner()
    result = runner.invoke(main, ["--generate-config"])

    assert result.exit_code == 0
    assert "SBOM-Check Configuration Template" in result.output
    assert "metadata:" in result.output


def test_cli_generate_config_basic_profile():
    """Test CLI generate config with basic profile."""
    runner = CliRunner()
    result = runner.invoke(main, ["--generate-config", "--profile", "basic_spdx"])

    assert result.exit_code == 0
    assert "SBOM-Check Configuration Template" in result.output
    assert "basic_spdx" in result.output


def test_cli_validate_config_valid(tmp_path):
    """Test CLI validate config with valid file."""
    runner = CliRunner()

    # Create a valid config file
    config_content = """
metadata:
  name: "Test Config"
  version: "1.0.0"
  description: "Test configuration"
spdx_validation:
  enable_schema_validation: true
  enable_semantic_validation: true
document_requirements:
  required_fields: []
  field_validation: {}
package_requirements:
  required_fields: []
  build_tools:
    require_build_tools: false
    examples: []
  external_refs:
    required_types: []
  files_analyzed_rules:
    when_true_requires: []
    when_false_prohibits: []
relationship_requirements:
  no_isolated_elements: false
custom_rules: []
"""

    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(config_content)

    result = runner.invoke(main, ["--validate-config", str(config_file)])

    assert result.exit_code == 0
    assert "Configuration file is valid" in result.output


def test_cli_validate_config_invalid(tmp_path):
    """Test CLI validate config with invalid file."""
    runner = CliRunner()

    # Create an invalid config file
    config_file = tmp_path / "invalid_config.yaml"
    config_file.write_text("metadata:\n  name: ''\n  version: ''")

    result = runner.invoke(main, ["--validate-config", str(config_file)])

    assert result.exit_code == 1
    assert "Configuration file has errors" in result.output


def test_cli_validate_config_nonexistent():
    """Test CLI validate config with non-existent file."""
    runner = CliRunner()

    result = runner.invoke(main, ["--validate-config", "nonexistent.yaml"])

    assert result.exit_code == 3
    assert "Error validating config file" in result.output


def test_cli_no_files():
    """Test CLI with no files specified."""
    runner = CliRunner()
    result = runner.invoke(main, [])

    assert result.exit_code == 2
    assert "No paths specified for validation" in result.output


def test_cli_validate_file_not_found():
    """Test CLI with non-existent file."""
    runner = CliRunner()
    result = runner.invoke(main, ["nonexistent.json"])

    assert result.exit_code == 2  # Click returns 2 for invalid arguments (file not found)


@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_valid_file(mock_engine_class, tmp_path):
    """Test CLI with valid SPDX file."""
    # Mock the engine to return a quick result
    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Test Profile"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.get_messages_by_severity.return_value = []

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    runner = CliRunner()

    # Create a minimal SPDX document
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
        "packages": [],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            }
        ],
    }

    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps(spdx_doc))

    result = runner.invoke(main, [str(test_file)])

    assert "Validation Results for:" in result.output
    assert test_file.name in result.output


@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_with_json_output(mock_engine_class, tmp_path):
    """Test CLI with JSON output format."""
    # Mock the engine to return a quick result
    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Test Profile"
    mock_result.file_path = "test.json"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.summary.info = 0
    mock_result.summary.total_rules = 0
    mock_result.summary.passed_rules = 0
    mock_result.summary.failed_rules = 0

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps(spdx_doc))

    result = runner.invoke(main, [str(test_file), "--output-format", "json"])

    # Should contain JSON output
    assert '"overall_valid"' in result.output
    assert '"spdx_valid"' in result.output
    assert '"profile_valid"' in result.output


@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_with_custom_profile(mock_engine_class, tmp_path):
    """Test CLI with custom profile."""
    # Mock the engine to return a quick result
    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Basic SPDX 2.3 Compliance"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.get_messages_by_severity.return_value = []

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps(spdx_doc))

    result = runner.invoke(main, [str(test_file), "--profile", "basic_spdx"])

    assert "Validation Results for:" in result.output
    assert "Profile: Basic SPDX 2.3 Compliance" in result.output


@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_with_custom_config(mock_engine_class, tmp_path):
    """Test CLI with custom config file."""
    # Mock the engine to return a quick result
    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Custom Config"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.get_messages_by_severity.return_value = []

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    runner = CliRunner()

    # Create custom config
    config_content = """
metadata:
  name: "Custom Config"
  version: "1.0.0"
  description: "Custom test configuration"
spdx_validation:
  enable_schema_validation: true
  enable_semantic_validation: true
document_requirements:
  required_fields: []
  field_validation: {}
package_requirements:
  required_fields: []
  build_tools:
    require_build_tools: false
    examples: []
  external_refs:
    required_types: []
  files_analyzed_rules:
    when_true_requires: []
    when_false_prohibits: []
relationship_requirements:
  no_isolated_elements: false
custom_rules: []
"""

    config_file = tmp_path / "custom_config.yaml"
    config_file.write_text(config_content)

    # Create SPDX file
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    test_file = tmp_path / "test.json"
    test_file.write_text(json.dumps(spdx_doc))

    result = runner.invoke(main, [str(test_file), "--config", str(config_file)])

    assert "Validation Results for:" in result.output
    assert "Profile: Custom Config" in result.output


@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_multiple_files(mock_engine_class, tmp_path):
    """Test CLI with multiple files."""
    # Mock the engine to return a quick result
    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Test Profile"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.get_messages_by_severity.return_value = []

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    test_file1 = tmp_path / "test1.json"
    test_file1.write_text(json.dumps(spdx_doc))

    test_file2 = tmp_path / "test2.json"
    test_file2.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
        result = runner.invoke(main, [str(test_file1), str(test_file2)])

    # Check that both file names appear in the output
    assert test_file1.name in result.output
    assert test_file2.name in result.output
    # Also verify that validation results appear for both files
    assert result.output.count("Validation Results for:") == 2


def test_cli_invalid_profile():
    """Test CLI with invalid profile name."""
    runner = CliRunner()

    result = runner.invoke(main, ["--profile", "nonexistent", "--list-profiles"])

    # Should still work for list-profiles even with invalid profile
    assert result.exit_code == 0


def test_cli_error_handling(tmp_path):
    """Test CLI error handling."""
    runner = CliRunner()

    # Create invalid JSON file
    test_file = tmp_path / "invalid.json"
    test_file.write_text("invalid json content")

    result = runner.invoke(main, [str(test_file)])

    # Should handle the error gracefully
    assert result.exit_code == 1
    assert "Validation Results for:" in result.output


# New tests for directory traversal and enhanced functionality

def test_cli_validate_directory_non_recursive(tmp_path):
    """Test directory scanning without recursion."""
    runner = CliRunner()

    # Create directory structure
    subdir = tmp_path / "subdir"
    subdir.mkdir()

    # Create SBOM files
    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # File in root directory (should be found)
    root_file = tmp_path / "test.spdx.json"
    root_file.write_text(json.dumps(spdx_doc))

    # File in subdirectory (should NOT be found without --recursive)
    sub_file = subdir / "sub.spdx.json"
    sub_file.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.get_messages_by_severity.return_value = []

        mock_engine = Mock()
        mock_engine.validate_file.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        result = runner.invoke(main, [str(tmp_path)])

        # Should find only the root file
        assert result.exit_code == 0
        assert root_file.name in result.output
        assert sub_file.name not in result.output


@patch("sbom_check.cli.ProcessPoolExecutor", new=ThreadPoolExecutor)
@patch("sbom_check.cli.SbomCheckEngine")
def test_cli_validate_directory_recursive(mock_engine_class, tmp_path):
    """Test recursive directory scanning."""
    runner = CliRunner()

    # Create nested directory structure
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    nested_dir = subdir / "nested"
    nested_dir.mkdir()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Create files at different levels
    root_file = tmp_path / "root.spdx.json"
    root_file.write_text(json.dumps(spdx_doc))

    sub_file = subdir / "sub.spdx.json"
    sub_file.write_text(json.dumps(spdx_doc))

    nested_file = nested_dir / "nested.spdx.json"
    nested_file.write_text(json.dumps(spdx_doc))

    mock_result = Mock()
    mock_result.overall_valid = True
    mock_result.spdx_valid = True
    mock_result.profile_valid = True
    mock_result.profile_name = "Test Profile"
    mock_result.messages = []
    mock_result.summary.errors = 0
    mock_result.summary.warnings = 0
    mock_result.get_messages_by_severity.return_value = []

    mock_engine = Mock()
    mock_engine.validate_file.return_value = mock_result
    mock_engine_class.return_value = mock_engine

    result = runner.invoke(main, ["--recursive", str(tmp_path)])

    # Should find all files with recursive scanning
    assert result.exit_code == 0
    assert "Validated 3 files:" in result.output
    assert "3 valid" in result.output


def test_default_scan_pattern_includes_spdx_and_cyclonedx(tmp_path):
    (tmp_path / "bom.spdx.json").write_text("{}")
    (tmp_path / "bom.cdx.json").write_text("{}")
    (tmp_path / "config.json").write_text("{}")
    (tmp_path / "settings.json").write_text("{}")

    files = collect_sbom_files((tmp_path,), recursive=False, pattern="*.{spdx,cdx}.json")

    assert [file.name for file in files] == ['bom.cdx.json', 'bom.spdx.json']


def test_cli_validate_custom_pattern(tmp_path):
    """Test custom file patterns."""
    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Create files with different extensions
    spdx_file = tmp_path / "test.spdx.json"
    spdx_file.write_text(json.dumps(spdx_doc))

    json_file = tmp_path / "test.json"
    json_file.write_text(json.dumps(spdx_doc))

    txt_file = tmp_path / "test.txt"
    txt_file.write_text("not json")

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.get_messages_by_severity.return_value = []

        mock_engine = Mock()
        mock_engine.validate_file.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        # Test with *.json pattern
        with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
            result = runner.invoke(main, ["--pattern", "*.json", str(tmp_path)])

        # Should find both .json and .spdx.json files
        assert result.exit_code == 0
        assert "Validated 2 files:" in result.output


def test_cli_validate_mixed_paths(tmp_path):
    """Test mix of files and directories."""
    runner = CliRunner()

    # Create directory with files
    subdir = tmp_path / "subdir"
    subdir.mkdir()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Individual file
    individual_file = tmp_path / "individual.spdx.json"
    individual_file.write_text(json.dumps(spdx_doc))

    # File in directory
    dir_file = subdir / "dir_file.spdx.json"
    dir_file.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.get_messages_by_severity.return_value = []

        mock_engine = Mock()
        mock_engine.validate_file.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        # Test with mix of file and directory
        with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
            result = runner.invoke(main, [str(individual_file), str(subdir)])

        # Should find both files
        assert result.exit_code == 0
        assert "Validated 2 files:" in result.output


def test_cli_validate_empty_directory(tmp_path):
    """Test directory with no matching files."""
    runner = CliRunner()

    # Create empty directory
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()

    # Create directory with non-matching files
    non_matching_dir = tmp_path / "non_matching"
    non_matching_dir.mkdir()
    (non_matching_dir / "test.txt").write_text("not an SBOM")

    result = runner.invoke(main, [str(empty_dir)])

    # Should exit with error when no files found
    assert result.exit_code == 1
    assert "No SBOM files found to validate" in result.output


def test_cli_validate_parallel_processing(tmp_path):
    """Test parallel processing with --jobs option."""
    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Create multiple files
    files = []
    for i in range(3):
        file_path = tmp_path / f"test{i}.spdx.json"
        file_path.write_text(json.dumps(spdx_doc))
        files.append(file_path)

    with patch("sbom_check.cli.validate_single_file") as mock_validate:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.get_messages_by_severity.return_value = []

        # Mock the validate_single_file function to return (path, result) tuple
        def mock_validate_func(file_path, profile, config):
            return file_path, mock_result

        mock_validate.side_effect = mock_validate_func

        with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
            result = runner.invoke(main, ["--jobs", "2"] + [str(f) for f in files])

        # Should process all files in parallel
        assert result.exit_code == 0
        assert "Validated 3 files:" in result.output
        assert mock_validate.call_count == 3


def test_cli_multiple_files_json_output(tmp_path):
    """Test JSON output for multiple files."""
    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Create multiple files
    file1 = tmp_path / "test1.spdx.json"
    file1.write_text(json.dumps(spdx_doc))

    file2 = tmp_path / "test2.spdx.json"
    file2.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.summary.info = 0
        mock_result.summary.total_rules = 0
        mock_result.summary.passed_rules = 0
        mock_result.summary.failed_rules = 0

        mock_engine = Mock()
        mock_engine.validate_file.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
            result = runner.invoke(main, ["--output-format", "json", str(file1), str(file2)])

        # Should contain JSON summary for multiple files
        assert result.exit_code == 0
        assert '"summary"' in result.output
        assert '"total_files": 2' in result.output
        assert '"results"' in result.output


def test_cli_mixed_validation_results(tmp_path):
    """Test output when some files pass, some fail."""
    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    # Create multiple files
    file1 = tmp_path / "valid.spdx.json"
    file1.write_text(json.dumps(spdx_doc))

    file2 = tmp_path / "invalid.spdx.json"
    file2.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        # Create different results for different files
        valid_result = Mock()
        valid_result.overall_valid = True
        valid_result.spdx_valid = True
        valid_result.profile_valid = True
        valid_result.profile_name = "Test Profile"
        valid_result.messages = []
        valid_result.summary.errors = 0
        valid_result.summary.warnings = 0
        valid_result.get_messages_by_severity.return_value = []

        invalid_result = Mock()
        invalid_result.overall_valid = False
        invalid_result.spdx_valid = False
        invalid_result.profile_valid = True
        invalid_result.profile_name = "Test Profile"
        invalid_result.messages = []
        invalid_result.summary.errors = 1
        invalid_result.summary.warnings = 0
        invalid_result.get_messages_by_severity.return_value = []

        mock_engine = Mock()
        # Return different results based on file path
        def mock_validate_file(file_path):
            if file_path.name == "valid.spdx.json":
                return valid_result
            else:
                return invalid_result

        mock_engine.validate_file.side_effect = mock_validate_file
        mock_engine_class.return_value = mock_engine

        with patch("sbom_check.cli.ProcessPoolExecutor", ThreadPoolExecutor):
            result = runner.invoke(main, [str(file1), str(file2)])

        # Should show mixed results and exit with error code
        assert result.exit_code == 1
        assert "Validated 2 files:" in result.output
        assert "1 valid" in result.output
        assert "1 invalid" in result.output
        assert "Overall: 1/2 files valid ⚠️" in result.output


def test_cli_backward_compatibility_single_file(tmp_path):
    """Test that existing single-file usage still works."""
    runner = CliRunner()

    spdx_doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    test_file = tmp_path / "test.spdx.json"
    test_file.write_text(json.dumps(spdx_doc))

    with patch("sbom_check.cli.SbomCheckEngine") as mock_engine_class:
        mock_result = Mock()
        mock_result.overall_valid = True
        mock_result.spdx_valid = True
        mock_result.profile_valid = True
        mock_result.profile_name = "Test Profile"
        mock_result.messages = []
        mock_result.summary.errors = 0
        mock_result.summary.warnings = 0
        mock_result.get_messages_by_severity.return_value = []

        mock_engine = Mock()
        mock_engine.validate_file.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        # Test existing single-file usage
        result = runner.invoke(main, [str(test_file)])

        # Should work exactly as before (single file output format)
        assert result.exit_code == 0
        assert "Validation Results for:" in result.output
        assert test_file.name in result.output
        # Should NOT show multiple-file summary format
        assert "Validated 1 files:" not in result.output


def _format_result(document_format: str, spec_version: str) -> SimpleNamespace:
    """Create a minimal result for output rendering tests."""
    return SimpleNamespace(
        overall_valid=True,
        document_format=document_format,
        spec_version=spec_version,
        spdx_valid=True,
        profile_valid=True,
        profile_name=None,
        file_path=None,
        messages=[],
        summary=SimpleNamespace(
            errors=0,
            warnings=0,
            info=0,
            total_rules=0,
            passed_rules=0,
            failed_rules=0,
        ),
        get_messages_by_severity=lambda severity: [],
    )


def test_text_output_uses_detected_format_and_marks_profile_not_applicable():
    """CycloneDX output must not use SPDX labels or profile status."""
    result = _format_result("CycloneDX", "1.7")

    with patch("sbom_check.cli.console") as mocked_console:
        _print_text_result(result, "bom.json")

    output = "\n".join(str(call.args[0]) for call in mocked_console.print.call_args_list)
    assert "CycloneDX 1.7 Validation: PASSED" in output
    assert "Profile Validation: NOT APPLICABLE" in output
    assert "SPDX 2.3 Validation" not in output


def test_json_output_includes_detected_format_and_specification():
    """JSON output exposes format-neutral metadata."""
    result = _format_result("CycloneDX", "1.7")

    with patch("sbom_check.cli.console") as mocked_console:
        _print_json_result(result)

    output = mocked_console.print.call_args.args[0]
    assert '"document_format": "CycloneDX"' in output
    assert '"spec_version": "1.7"' in output


def test_collect_sbom_files_deduplicates_brace_matches(tmp_path):
    document = tmp_path / "bom.spdx.json"
    document.write_text("{}")

    files = collect_sbom_files((tmp_path,), recursive=False, pattern="*.{spdx,spdx}.json")

    assert files == [document.resolve()]
