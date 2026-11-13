# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for data models."""

from types import SimpleNamespace

import pytest

from sbom_check.models import (
    DocumentFormat,
    ProfileStatus,
    RuleCoverage,
    RuleOutcome,
    SbomCheckResult,
    ValidationMessage,
    ValidationSeverity,
    ValidationSummary,
)


def test_sbom_check_result_combine_accepts_deprecated_spdx_result():
    """The old keyword remains supported with a deprecation warning."""
    core_result = SimpleNamespace(is_valid=True, messages=[])

    with pytest.warns(DeprecationWarning, match="spdx_result is deprecated"):
        result = SbomCheckResult.combine(spdx_result=core_result)

    assert result.core_valid is True
    assert result.profile_valid is True
    assert result.profile_status is ProfileStatus.PASSED


def test_validation_message_creation():
    """Test creating a ValidationMessage."""
    msg = ValidationMessage(
        severity=ValidationSeverity.ERROR,
        message="Test error message",
        rule_id="test_rule",
        field_path="test.field",
        section_reference="Test Section",
        found_value="wrong",
        expected_value="correct",
        remediation="Fix the value",
    )

    assert msg.severity == ValidationSeverity.ERROR
    assert msg.message == "Test error message"
    assert msg.rule_id == "test_rule"
    assert msg.field_path == "test.field"
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
        found_value="actual",
        expected_value="expected",
    )

    str_repr = str(msg)
    assert "WARNING: Test warning" in str_repr
    assert "Field: test.field" in str_repr
    assert "Found: actual" in str_repr
    assert "Expected: expected" in str_repr


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


def test_document_format_enum_includes_spdx3():
    """DocumentFormat gains SPDX3 while existing members keep their values."""
    assert DocumentFormat.SPDX.value == "SPDX"
    assert DocumentFormat.SPDX3.value == "SPDX3"
    assert DocumentFormat.CYCLONEDX.value == "CycloneDX"
    assert DocumentFormat.UNKNOWN.value == "unknown"


def test_profile_status_enum_adds_skipped_and_unsupported():
    """ProfileStatus gains SKIPPED/UNSUPPORTED; original members are unchanged."""
    assert ProfileStatus.PASSED.value == "passed"
    assert ProfileStatus.FAILED.value == "failed"
    assert ProfileStatus.NOT_APPLICABLE.value == "not_applicable"
    assert ProfileStatus.SKIPPED.value == "skipped"
    assert ProfileStatus.UNSUPPORTED.value == "unsupported"


def test_rule_outcome_enum_values():
    """RuleOutcome exposes exactly the five documented members and values."""
    assert RuleOutcome.PASSED.value == "passed"
    assert RuleOutcome.FAILED.value == "failed"
    assert RuleOutcome.SKIPPED.value == "skipped"
    assert RuleOutcome.NOT_APPLICABLE.value == "not_applicable"
    assert RuleOutcome.UNSUPPORTED.value == "unsupported"


def test_rule_coverage_blocks_completeness_only_for_unsupported():
    """blocks_completeness is True only for the UNSUPPORTED outcome."""
    for outcome in (
        RuleOutcome.PASSED,
        RuleOutcome.FAILED,
        RuleOutcome.SKIPPED,
        RuleOutcome.NOT_APPLICABLE,
    ):
        coverage = RuleCoverage(rule_id="r1", outcome=outcome)
        assert coverage.blocks_completeness is False

    unsupported = RuleCoverage(rule_id="r1", outcome=RuleOutcome.UNSUPPORTED)
    assert unsupported.blocks_completeness is True


def test_add_rule_coverage_unsupported_flips_overall_valid_and_profile_status():
    """An UNSUPPORTED rule fails overall_valid closed and downgrades profile_status."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
        profile_status=ProfileStatus.PASSED,
    )

    result.add_rule_coverage(
        RuleCoverage(rule_id="r1", outcome=RuleOutcome.UNSUPPORTED)
    )

    assert result.overall_valid is False
    assert result.profile_status is ProfileStatus.SKIPPED
    assert result.profile_valid is True  # profile_valid must not be touched


def test_add_rule_coverage_passed_does_not_change_validity_or_status():
    """A PASSED rule coverage entry leaves overall_valid and profile_status alone."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
        profile_status=ProfileStatus.PASSED,
    )

    result.add_rule_coverage(RuleCoverage(rule_id="r1", outcome=RuleOutcome.PASSED))

    assert result.overall_valid is True
    assert result.profile_status is ProfileStatus.PASSED


def test_rules_by_outcome_filters_correctly():
    """rules_by_outcome returns only coverage entries matching the given outcome."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )
    result.add_rule_coverage(RuleCoverage(rule_id="r1", outcome=RuleOutcome.PASSED))
    result.add_rule_coverage(RuleCoverage(rule_id="r2", outcome=RuleOutcome.FAILED))
    result.add_rule_coverage(
        RuleCoverage(rule_id="r3", outcome=RuleOutcome.UNSUPPORTED)
    )

    passed = result.rules_by_outcome(RuleOutcome.PASSED)
    unsupported = result.rules_by_outcome(RuleOutcome.UNSUPPORTED)

    assert [c.rule_id for c in passed] == ["r1"]
    assert [c.rule_id for c in unsupported] == ["r3"]


def test_has_unevaluated_rules_true_and_false_cases():
    """has_unevaluated_rules reflects whether any entry blocks completeness."""
    result = SbomCheckResult(
        overall_valid=True,
        spdx_valid=True,
        profile_valid=True,
    )
    assert result.has_unevaluated_rules() is False

    result.add_rule_coverage(RuleCoverage(rule_id="r1", outcome=RuleOutcome.PASSED))
    assert result.has_unevaluated_rules() is False

    result.add_rule_coverage(
        RuleCoverage(rule_id="r2", outcome=RuleOutcome.UNSUPPORTED)
    )
    assert result.has_unevaluated_rules() is True


def test_combine_unsupported_rule_coverage_forces_overall_invalid():
    """An unevaluated required rule forces overall_valid False with zero errors.

    This is the central guarantee: a document cannot be reported as
    complete when a required completeness rule never actually ran, even
    if the core result is valid and there are no error messages at all.
    """
    core_result = SimpleNamespace(is_valid=True, messages=[])
    unsupported = RuleCoverage(rule_id="r1", outcome=RuleOutcome.UNSUPPORTED)

    result = SbomCheckResult.combine(
        core_result=core_result,
        profile_rule_coverage=[unsupported],
    )

    assert result.summary.errors == 0
    assert result.overall_valid is False
    assert result.profile_status is ProfileStatus.SKIPPED


def test_combine_spdx3_document_format_sets_spdx_valid_and_profile_name():
    """combine() treats SPDX3 as an SPDX document for spdx_valid/profile_name."""
    core_result = SimpleNamespace(is_valid=True, messages=[])

    result = SbomCheckResult.combine(
        core_result=core_result,
        document_format=DocumentFormat.SPDX3,
        profile_name="qualcomm-spdx3",
        spec_version="3.0.1",
    )

    assert result.spdx_valid is True
    assert result.profile_name == "qualcomm-spdx3"
    assert result.profile_status is ProfileStatus.PASSED


def test_combine_without_rule_coverage_behaves_as_before_for_spdx23():
    """Regression: combine() with no profile_rule_coverage is unchanged for SPDX 2.3."""
    core_result = SimpleNamespace(is_valid=True, messages=[])

    result = SbomCheckResult.combine(
        core_result=core_result,
        document_format=DocumentFormat.SPDX,
        profile_name="qualcomm",
        spec_version="2.3",
    )

    assert result.overall_valid is True
    assert result.spdx_valid is True
    assert result.profile_valid is True
    assert result.profile_status is ProfileStatus.PASSED
    assert result.profile_name == "qualcomm"
    assert result.rule_coverage == []
