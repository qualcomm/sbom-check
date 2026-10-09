# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for data models."""

from types import SimpleNamespace

from sbom_check.models import (
    ProfileStatus,
    SbomCheckResult,
    ValidationMessage,
    ValidationSeverity,
    ValidationSummary,
)


def test_validation_message_creation():
    """Test creating a ValidationMessage."""
    msg = ValidationMessage(
        severity=ValidationSeverity.ERROR,
        message="Test error message",
        rule_id="test_rule",
        field_path="test.field",
        json_path="$['test']['field']",
        section_reference="Test Section",
        found_value="wrong",
        expected_value="correct",
        remediation="Fix the value",
    )

    assert msg.severity == ValidationSeverity.ERROR
    assert msg.message == "Test error message"
    assert msg.rule_id == "test_rule"
    assert msg.field_path == "test.field"
    assert msg.json_path == "$['test']['field']"
    assert msg.section_reference == "Test Section"
    assert msg.found_value == "wrong"
    assert msg.expected_value == "correct"
    assert msg.remediation == "Fix the value"


def test_validation_message_str():
    """Test string representation of ValidationMessage."""
    msg = ValidationMessage(
        severity=ValidationSeverity.WARNING,
        message="Test warning",
        field_path="test.field",
        json_path="$['test']['field']",
        found_value="actual",
        expected_value="expected",
    )

    str_repr = str(msg)
    assert "WARNING: Test warning" in str_repr
    assert "Field: test.field" in str_repr
    assert "JSON path: $['test']['field']" in str_repr
    assert "Found: actual" in str_repr
    assert "Expected: expected" in str_repr


def test_convert_spdx_messages_preserves_diagnostics():
    """Conversion from a core validator keeps all diagnostic context."""
    raw_message = SimpleNamespace(
        severity=ValidationSeverity.ERROR,
        message="Invalid reference",
        rule_id="spdx3-reference",
        field_path="creationInfo",
        json_path="$['@graph'][0]['creationInfo']",
        affected_element="https://example.com/package",
        section_reference="SPDX 3.0.1 SHACL validation",
        found_value="_:CreationInfo2",
        expected_value="SPDX CreationInfo",
        remediation="Use an SPDX CreationInfo reference.",
    )
    core_result = SimpleNamespace(messages=[raw_message])

    [message] = SbomCheckResult._convert_spdx_messages(core_result)

    assert message.affected_element == raw_message.affected_element
    assert message.json_path == raw_message.json_path
    assert message.section_reference == raw_message.section_reference
    assert message.found_value == raw_message.found_value
    assert message.expected_value == raw_message.expected_value
    assert message.remediation == raw_message.remediation


def test_validation_summary_success_rate():
    """Test ValidationSummary success rate calculation."""
    summary = ValidationSummary(
        total_rules=10,
        passed_rules=8,
        failed_rules=2,
        errors=2,
        warnings=1,
        info=0,
    )

    assert summary.success_rate == 80.0

    # Test with zero rules
    empty_summary = ValidationSummary()
    assert empty_summary.success_rate == 0.0


def test_sbom_check_result_creation():
    """Test creating an SbomCheckResult."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
        profile_name="test_profile",
        file_path="/test/file.json",
    )

    assert result.overall_valid is True
    assert result.spdx_valid is True
    assert result.profile_valid is True
    assert result.core_valid is True
    assert result.profile_status is ProfileStatus.PASSED
    assert result.profile_name == "test_profile"
    assert result.file_path == "/test/file.json"
    assert len(result.messages) == 0


def test_sbom_check_result_add_message():
    """Test adding messages to SbomCheckResult."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )

    # Add error message
    result.add_message(
        ValidationSeverity.ERROR,
        "Test error",
        rule_id="test_rule",
    )

    assert len(result.messages) == 1
    assert result.summary.errors == 1
    assert result.summary.failed_rules == 1
    assert result.overall_valid is False
    assert result.profile_valid is False

    # Add warning message
    result.add_message(
        ValidationSeverity.WARNING,
        "Test warning",
    )

    assert len(result.messages) == 2
    assert result.summary.warnings == 1


def test_sbom_check_result_get_messages_by_severity():
    """Test filtering messages by severity."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )

    result.add_message(ValidationSeverity.ERROR, "Error 1")
    result.add_message(ValidationSeverity.ERROR, "Error 2")
    result.add_message(ValidationSeverity.WARNING, "Warning 1")
    result.add_message(ValidationSeverity.INFO, "Info 1")

    errors = result.get_messages_by_severity(ValidationSeverity.ERROR)
    warnings = result.get_messages_by_severity(ValidationSeverity.WARNING)
    info = result.get_messages_by_severity(ValidationSeverity.INFO)

    assert len(errors) == 2
    assert len(warnings) == 1
    assert len(info) == 1

    assert all(msg.severity == ValidationSeverity.ERROR for msg in errors)
    assert all(msg.severity == ValidationSeverity.WARNING for msg in warnings)
    assert all(msg.severity == ValidationSeverity.INFO for msg in info)


def test_sbom_check_result_has_errors():
    """Test checking if result has errors."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )

    assert result.has_errors() is False

    result.add_message(ValidationSeverity.WARNING, "Warning")
    assert result.has_errors() is False

    result.add_message(ValidationSeverity.ERROR, "Error")
    assert result.has_errors() is True


def test_sbom_check_result_has_warnings():
    """Test checking if result has warnings."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )

    assert result.has_warnings() is False

    result.add_message(ValidationSeverity.ERROR, "Error")
    assert result.has_warnings() is False

    result.add_message(ValidationSeverity.WARNING, "Warning")
    assert result.has_warnings() is True


def test_validation_severity_enum():
    """Test ValidationSeverity enum values."""
    assert ValidationSeverity.ERROR == "ERROR"
    assert ValidationSeverity.WARNING == "WARNING"
    assert ValidationSeverity.INFO == "INFO"

    # Test that it's a string enum
    assert isinstance(ValidationSeverity.ERROR, str)
    assert ValidationSeverity.ERROR.value == "ERROR"
