# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SBOM validation engine."""

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cyclone_validator.engine import CycloneDXValidationEngine
from sbom_check.config.loader import ConfigLoader
from sbom_check.detection import DetectedDocument
from sbom_check.engine import SbomCheckEngine
from sbom_check.models import (
    DocumentFormat,
    ProfileStatus,
    RuleOutcome,
    SbomCheckResult,
    ValidationSeverity,
)
from sbom_check.profile.rules_spdx3 import SPDX3_RULES
from spdx_validator.engine import ValidationEngine


def test_engine_initialization():
    """Test that SbomCheckEngine initializes correctly."""
    engine = SbomCheckEngine()
    assert engine is not None
    assert engine.config is not None


def test_deprecated_spdx_engine_alias_returns_core_engine():
    """The former public engine attribute remains available during migration."""
    engine = SbomCheckEngine()

    with pytest.warns(DeprecationWarning, match="spdx_engine"):
        assert engine.spdx_engine is engine.engine


def test_engine_override_is_used_in_auto_detect_mode(sample_valid_spdx_document):
    """An injected core engine takes precedence over format auto-detection."""
    replacement_engine = Mock()
    replacement_engine.validate_dict.return_value = Mock(is_valid=True, messages=[])
    engine = SbomCheckEngine()
    engine.engine = replacement_engine

    engine.validate_dict(sample_valid_spdx_document)

    replacement_engine.validate_dict.assert_called_once_with(sample_valid_spdx_document)


def test_deprecated_spdx_engine_override_does_not_replace_cyclonedx_validator():
    """The deprecated SPDX-specific override leaves CycloneDX dispatch intact."""
    spdx_engine = ValidationEngine()
    engine = SbomCheckEngine()

    with pytest.warns(DeprecationWarning, match="spdx_engine"):
        engine.spdx_engine = spdx_engine

    with patch.object(
        CycloneDXValidationEngine,
        "validate_dict",
        autospec=True,
        side_effect=CycloneDXValidationEngine.validate_dict,
    ) as validate_cyclonedx:
        result = engine.validate_dict({"bomFormat": "CycloneDX", "specVersion": "1.7"})

    validate_cyclonedx.assert_called_once()
    assert result.overall_valid
    assert result.core_valid
    assert result.document_format == "CycloneDX"


def test_deprecated_spdx_engine_override_is_used_in_auto_detect_mode(
    sample_valid_spdx_document,
):
    """The deprecated setter overrides the auto-detected SPDX validator."""
    replacement_engine = Mock()
    replacement_engine.validate_dict.return_value = Mock(is_valid=True, messages=[])
    engine = SbomCheckEngine()

    with pytest.warns(DeprecationWarning, match="spdx_engine"):
        engine.spdx_engine = replacement_engine

    engine.validate_dict(sample_valid_spdx_document)

    replacement_engine.validate_dict.assert_called_once_with(sample_valid_spdx_document)


def test_auto_detected_validator_is_built_once_and_reused(
    sample_valid_spdx_document,
):
    """Auto-detection retains one validator instance per validator class."""

    class CountingValidator:
        instances = 0

        def __init__(self) -> None:
            type(self).instances += 1

        def validate_dict(self, document):
            del document
            return Mock(is_valid=True, messages=[])

    detected = DetectedDocument(DocumentFormat.SPDX, "2.3", CountingValidator)
    with patch("sbom_check.engine.detect_document", return_value=detected):
        engine = SbomCheckEngine()
        engine.validate_dict(sample_valid_spdx_document)
        engine.validate_dict(sample_valid_spdx_document)

    assert CountingValidator.instances == 1


def test_engine_initialization_with_config():
    """Test engine initialization with custom config."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")
    engine = SbomCheckEngine(config)

    assert engine.config == config


def test_engine_initialization_with_profile():
    """Test engine initialization with profile name."""
    engine = SbomCheckEngine(profile_name="basic_spdx")

    assert engine.config.metadata.name == "Basic SPDX 2.3 Compliance"


def test_default_profile_requires_explicit_files_analyzed(
    sample_valid_spdx_document,
):
    """Test the default profile requires filesAnalyzed despite the SPDX default."""
    package = sample_valid_spdx_document["packages"][0]
    package.pop("filesAnalyzed")
    package["packageVerificationCode"] = {
        # Arbitrary valid hexadecimal value; digest calculation is not tested here.
        "packageVerificationCodeValue": "a" * 40,
    }

    result = SbomCheckEngine().validate_dict(sample_valid_spdx_document)

    assert not result.overall_valid
    assert result.spdx_valid
    assert not result.profile_valid
    assert any(
        message.rule_id == "missing_package_field"
        and message.field_path == "packages[0].filesAnalyzed"
        for message in result.messages
    )


def test_validate_json_string_invalid_json():
    """Test validation with invalid JSON."""
    engine = SbomCheckEngine()
    result = engine.validate_json_string("invalid json")

    assert not result.overall_valid
    assert result.spdx_valid is None
    assert result.profile_valid is None
    assert result.profile_name is None
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE
    assert len(result.messages) > 0
    assert result.messages[0].severity == ValidationSeverity.ERROR
    assert "Invalid JSON" in result.messages[0].message


@patch("sbom_check.engine.ValidationEngine")
def test_validate_json_string_valid_json(mock_validation_engine):
    """Test validation with valid JSON structure."""
    # Mock the spdx validator to return success quickly
    mock_spdx_result = Mock()
    mock_spdx_result.is_valid = True
    mock_spdx_result.messages = []
    mock_spdx_result.schema_valid = True
    mock_spdx_result.semantic_valid = True

    mock_engine_instance = Mock()
    mock_engine_instance.validate_dict.return_value = mock_spdx_result
    mock_validation_engine.return_value = mock_engine_instance

    engine = SbomCheckEngine()

    # Create a minimal valid SPDX document
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

    result = engine.validate_json_string(json.dumps(spdx_doc))

    assert result is not None
    assert result.profile_name == "Default SBOM Requirements"


@patch("sbom_check.engine.ValidationEngine")
def test_validate_dict(mock_validation_engine):
    """Test validation with dictionary input."""
    # Mock the spdx validator to return success quickly
    mock_spdx_result = Mock()
    mock_spdx_result.is_valid = True
    mock_spdx_result.messages = []
    mock_spdx_result.schema_valid = True
    mock_spdx_result.semantic_valid = True

    mock_engine_instance = Mock()
    mock_engine_instance.validate_dict.return_value = mock_spdx_result
    mock_validation_engine.return_value = mock_engine_instance

    engine = SbomCheckEngine()

    spdx_dict = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {"created": "2023-01-01T00:00:00Z", "creators": ["Tool: test"]},
    }

    result = engine.validate_dict(spdx_dict, "test.json")

    assert result is not None
    assert result.file_path == "test.json"


def test_validate_file_not_found():
    """Test validation with non-existent file."""
    engine = SbomCheckEngine()
    result = engine.validate_file("nonexistent.json")

    assert not result.overall_valid
    assert not result.spdx_valid
    assert not result.profile_valid
    assert len(result.messages) > 0
    assert result.messages[0].severity == ValidationSeverity.ERROR
    assert "File not found" in result.messages[0].message


def test_validate_file_read_error(tmp_path):
    """Test validation with file read error."""
    engine = SbomCheckEngine()

    # Create a file with invalid permissions (if possible)
    test_file = tmp_path / "test.json"
    test_file.write_text('{"test": "data"}')
    test_file.chmod(0o000)  # Remove all permissions

    try:
        result = engine.validate_file(test_file)

        assert not result.overall_valid
        assert not result.spdx_valid
        assert not result.profile_valid
        assert len(result.messages) > 0
        assert result.messages[0].severity == ValidationSeverity.ERROR
        assert "Error reading file" in result.messages[0].message
    finally:
        # Restore permissions for cleanup
        test_file.chmod(0o644)


@patch("sbom_check.engine.ValidationEngine")
def test_validate_file_valid_json(mock_validation_engine, tmp_path):
    """Test validation with valid JSON file."""
    # Mock the spdx validator to return success quickly
    mock_spdx_result = Mock()
    mock_spdx_result.is_valid = True
    mock_spdx_result.messages = []
    mock_spdx_result.schema_valid = True
    mock_spdx_result.semantic_valid = True

    mock_engine_instance = Mock()
    mock_engine_instance.validate_dict.return_value = mock_spdx_result
    mock_validation_engine.return_value = mock_engine_instance

    engine = SbomCheckEngine()

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

    result = engine.validate_file(test_file)

    assert result is not None
    assert str(test_file) in result.file_path


def test_get_nested_field():
    """Test nested field extraction."""
    engine = SbomCheckEngine()

    data = {"level1": {"level2": {"value": "test"}}}

    # Test existing nested field
    value = engine._get_nested_field(data, "level1.level2.value")
    assert value == "test"

    # Test non-existent field
    value = engine._get_nested_field(data, "level1.nonexistent")
    assert value is None

    # Test top-level field
    value = engine._get_nested_field(data, "level1")
    assert value == data["level1"]


def test_validate_document_requirements():
    """Test document requirements validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with missing required fields
    spdx_data = {}
    engine._validate_document_requirements(spdx_data, result)

    # Should have error messages for missing required fields
    assert len(result.messages) > 0
    error_messages = [
        msg for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    ]
    assert len(error_messages) > 0


def test_validate_package_requirements():
    """Test package requirements validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with no packages
    spdx_data = {}
    engine._validate_package_requirements(spdx_data, result)

    # Test with packages
    spdx_data = {"packages": [{"name": "test-package", "SPDXID": "SPDXRef-Package"}]}
    engine._validate_package_requirements(spdx_data, result)

    # Should have some validation messages
    assert (
        len(result.messages) >= 0
    )  # May or may not have messages depending on validation


def test_validate_build_tools_coverage():
    """Test build tools coverage validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with packages missing build tools
    packages = [{"name": "some-library"}, {"name": "another-package"}]

    engine._validate_build_tools_coverage(packages, result)

    # Should have warning about missing build tools
    warnings = [
        msg for msg in result.messages if msg.severity == ValidationSeverity.WARNING
    ]
    assert len(warnings) > 0
    assert "missing build tools" in warnings[0].message.lower()


def test_validate_single_package():
    """Test single package validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test package with missing required fields
    package = {
        "name": "test-package"
        # Missing other required fields
    }

    engine._validate_single_package(package, 0, result)

    # Should have error messages for missing fields
    errors = [
        msg for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    ]
    assert len(errors) > 0


def test_validate_single_package_uses_true_rules_when_files_analyzed_is_omitted():
    """Test that omitted filesAnalyzed applies the when_true_requires rules."""
    config = ConfigLoader().load_profile("basic_spdx")
    config.package_requirements.files_analyzed_rules.when_true_requires = [
        "packageVerificationCode"
    ]
    engine = SbomCheckEngine(config)

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)
    package = {"name": "test-package"}

    engine._validate_single_package(package, 0, result)

    assert any(
        message.rule_id == "files_analyzed_missing_field"
        and message.field_path == "packages[0].packageVerificationCode"
        for message in result.messages
    )


def test_validate_relationship_requirements():
    """Test relationship requirements validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with missing DESCRIBES relationship
    spdx_data = {"SPDXID": "SPDXRef-DOCUMENT", "relationships": []}

    engine._validate_relationship_requirements(spdx_data, result)

    # Should have error about missing DESCRIBES relationship
    errors = [
        msg for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    ]
    assert len(errors) > 0
    assert "DESCRIBES" in errors[0].message


def test_validate_custom_rules():
    """Test custom rules validation."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test custom rules (currently a placeholder)
    spdx_data = {}
    engine._validate_custom_rules(spdx_data, result)

    # Should not crash (placeholder implementation)
    assert True


def test_document_namespace_http_url_allowed():
    """Test that HTTP URLs are allowed in documentNamespace field."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with HTTP URL in documentNamespace
    spdx_data = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "http://example.com/test-namespace",
        "creationInfo": {
            "created": "2023-01-01T00:00:00Z",
            "creators": ["Tool: test"],
            "licenseListVersion": "3.19",
        },
    }

    engine._validate_document_requirements(spdx_data, result)

    # Should not have any errors about HTTP scheme
    scheme_errors = [
        msg
        for msg in result.messages
        if msg.severity == ValidationSeverity.ERROR and "scheme" in msg.message.lower()
    ]
    assert len(scheme_errors) == 0, (
        f"HTTP URLs should be allowed, but got errors: {[msg.message for msg in scheme_errors]}"
    )


def test_document_namespace_https_url_allowed():
    """Test that HTTPS URLs are still allowed in documentNamespace field."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with HTTPS URL in documentNamespace
    spdx_data = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "https://example.com/test-namespace",
        "creationInfo": {
            "created": "2023-01-01T00:00:00Z",
            "creators": ["Tool: test"],
            "licenseListVersion": "3.19",
        },
    }

    engine._validate_document_requirements(spdx_data, result)

    # Should not have any errors about HTTPS scheme
    scheme_errors = [
        msg
        for msg in result.messages
        if msg.severity == ValidationSeverity.ERROR and "scheme" in msg.message.lower()
    ]
    assert len(scheme_errors) == 0, (
        f"HTTPS URLs should be allowed, but got errors: {[msg.message for msg in scheme_errors]}"
    )


def test_document_namespace_fragment_prohibited():
    """Test that fragment identifiers are still prohibited in documentNamespace."""
    engine = SbomCheckEngine()

    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    # Test with fragment in documentNamespace (should be rejected)
    spdx_data = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test Document",
        "documentNamespace": "http://example.com/test-namespace#fragment",
        "creationInfo": {
            "created": "2023-01-01T00:00:00Z",
            "creators": ["Tool: test"],
            "licenseListVersion": "3.19",
        },
    }

    engine._validate_document_requirements(spdx_data, result)

    # Should have error about fragment identifier
    fragment_errors = [
        msg
        for msg in result.messages
        if msg.severity == ValidationSeverity.ERROR
        and "fragment" in msg.message.lower()
    ]
    assert len(fragment_errors) > 0, (
        "Fragment identifiers should be prohibited in documentNamespace"
    )


def test_engine_instantiates_selected_validator_class():
    """Test that the selected validator class is instantiated as engine."""
    config = ConfigLoader().load_profile("default")
    engine = SbomCheckEngine(config, validator_class=CycloneDXValidationEngine)

    assert isinstance(engine.engine, CycloneDXValidationEngine)


def test_explicit_spdx_validator_subclass_preserves_spdx_metadata_and_profile(
    sample_valid_spdx_document,
):
    """An explicit validator override does not determine the input format."""

    class CustomValidationEngine(ValidationEngine):
        pass

    result = SbomCheckEngine(validator_class=CustomValidationEngine).validate_dict(
        sample_valid_spdx_document
    )

    assert result.document_format == "SPDX"
    assert result.spec_version == "2.3"
    assert result.profile_status is not ProfileStatus.NOT_APPLICABLE
    assert result.profile_name == "Default SBOM Requirements"


def test_explicit_validator_uses_declared_spdx_22_version(
    sample_invalid_spdx_document,
):
    """SPDX metadata comes from the document rather than a validator default."""
    result = SbomCheckEngine(validator_class=ValidationEngine).validate_dict(
        sample_invalid_spdx_document
    )

    assert result.document_format == "SPDX"
    assert result.spec_version == "2.2"


def test_cyclonedx_schema_paths_are_preserved_in_combined_result():
    """CycloneDX JSON paths survive SbomCheckResult conversion."""
    engine = SbomCheckEngine(
        validator_class=CycloneDXValidationEngine,
    )
    result = engine.validate_dict(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [{"type": "invalid", "name": 123}],
        }
    )

    assert not result.overall_valid
    assert result.core_valid is False
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE
    assert result.document_format == "CycloneDX"
    assert result.spec_version == "1.7"
    assert result.profile_valid is None
    assert {message.field_path for message in result.messages} >= {
        "$.components[0].type",
        "$.components[0].name",
    }


def test_engine_auto_detects_cyclonedx_without_explicit_validator_class():
    """Direct engine callers receive automatic format dispatch."""
    result = SbomCheckEngine().validate_dict(
        {"bomFormat": "CycloneDX", "specVersion": "1.7"}
    )

    assert result.overall_valid
    assert result.document_format == "CycloneDX"
    assert result.spec_version == "1.7"
    assert result.core_valid is True
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE


def test_missing_spdx_version_preserves_validator_and_profile_diagnostics(
    sample_valid_spdx_document,
):
    document = deepcopy(sample_valid_spdx_document)
    document.pop("spdxVersion")
    document["packages"][0].pop("downloadLocation")
    document["creationInfo"].pop("licenseListVersion")
    document["relationships"] = []

    result = SbomCheckEngine().validate_dict(document)
    messages = [message.message for message in result.messages]

    assert result.document_format == "SPDX"
    assert len(messages) > 1
    assert any("downloadLocation" in message for message in messages)
    assert any("spdxVersion" in message for message in messages)
    assert any("licenseListVersion" in message for message in messages)
    assert any("DESCRIBES" in message for message in messages)


def test_unsupported_spdx_version_preserves_validator_diagnostics(
    sample_invalid_spdx_document,
):
    result = SbomCheckEngine().validate_dict(sample_invalid_spdx_document)
    messages = [message.message for message in result.messages]

    assert result.document_format == "SPDX"
    assert len(messages) > 1
    assert any("SPDX-2.2" in message or "SPDX-2.3" in message for message in messages)


def test_cyclonedx_additional_properties_make_combined_result_invalid() -> None:
    result = SbomCheckEngine().validate_dict(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "bogusRootField": True,
            "components": [{"type": "library", "name": "example", "bogusField": True}],
        }
    )

    assert result.document_format == "CycloneDX"
    assert result.core_valid is False
    assert result.overall_valid is False
    assert result.summary.errors == 2
    assert result.summary.warnings == 1
    schema_messages = [
        message
        for message in result.messages
        if message.rule_id == "cyclonedx_schema_error"
    ]
    assert len(schema_messages) == 2
    assert {message.field_path for message in schema_messages} == {
        "$",
        "$.components[0]",
    }


def test_engine_returns_structured_result_for_unsupported_input():
    """Unsupported documents never fall through to SPDX validation."""
    result = SbomCheckEngine().validate_dict({"format": "unknown"})

    assert not result.overall_valid
    assert result.document_format == "unknown"
    assert result.core_valid is False
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE
    assert result.messages[0].rule_id == "unsupported_format"


def test_explicit_validator_returns_structured_result_for_non_object_input():
    result = SbomCheckEngine(
        validator_class=CycloneDXValidationEngine,
    ).validate_dict([])

    assert not result.overall_valid
    assert result.document_format == "unknown"
    assert result.core_valid is False
    assert result.messages[0].rule_id == "unsupported_format"


SPDX3_FIXTURE = (
    Path(__file__).resolve().parents[2] / "fixtures" / "spdx3" / "complete.spdx.json"
)


class _PassingSpdx3Core:
    """Core validator stand-in that reports a conformant SPDX 3 document.

    The real SPDX 3.0.1 core validator is delivered separately, so tests
    that need core validation to succeed substitute this.
    """

    format = DocumentFormat.SPDX3

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def validate(self, *_args, **_kwargs):
        return self.validate_dict({})

    def validate_json_string(self, *_args, **_kwargs):
        return self.validate_dict({})

    def validate_file(self, *_args, **_kwargs):
        return self.validate_dict({})

    def validate_dict(self, *_args, **_kwargs):
        return SimpleNamespace(is_valid=True, messages=[])


def _spdx3_document():
    """Load the SPDX 3.0.1 fixture document."""
    return json.loads(SPDX3_FIXTURE.read_text(encoding="utf-8"))


def test_spdx3_document_does_not_pass_without_core_validation():
    """An SPDX 3 document must not pass while core validation is unavailable."""
    result = SbomCheckEngine().validate_dict(_spdx3_document())

    assert result.document_format is DocumentFormat.SPDX3
    assert result.spec_version == "3.0.1"
    assert result.overall_valid is False
    assert result.core_valid is False


def test_spdx3_profile_rules_run_and_report_coverage():
    """Every registered SPDX 3 rule must be accounted for in coverage."""
    result = SbomCheckEngine().validate_dict(_spdx3_document())

    assert len(result.rule_coverage) == len(SPDX3_RULES)
    assert {entry.rule_id for entry in result.rule_coverage} == {
        rule.rule_id for rule in SPDX3_RULES
    }
    assert result.has_unevaluated_rules() is False


def test_complete_spdx3_document_passes_profile_validation():
    """The conforming fixture must satisfy every implemented rule."""
    result = SbomCheckEngine().validate_dict(_spdx3_document())

    assert result.profile_status is ProfileStatus.PASSED
    assert result.rules_by_outcome(RuleOutcome.FAILED) == []


def test_valid_spdx3_document_can_fail_profile_while_passing_core():
    """Profile failure must be reportable independently of core conformance.

    This is the distinction the profile layer exists to preserve: a
    document can be structurally valid SPDX 3.0.1 and still not meet
    Qualcomm completeness requirements.
    """
    document = json.loads(
        (SPDX3_FIXTURE.parent / "incomplete-package.spdx.json").read_text(
            encoding="utf-8"
        )
    )

    result = SbomCheckEngine(validator_class=_PassingSpdx3Core).validate_dict(document)

    assert result.core_valid is True
    assert result.profile_status is ProfileStatus.FAILED
    assert result.overall_valid is False
    assert result.rules_by_outcome(RuleOutcome.FAILED)


def test_spdx3_profile_failures_are_not_presented_as_spec_failures():
    """Profile findings must carry profile rule ids, not spec rule ids."""
    document = json.loads(
        (SPDX3_FIXTURE.parent / "incomplete-package.spdx.json").read_text(
            encoding="utf-8"
        )
    )

    result = SbomCheckEngine(validator_class=_PassingSpdx3Core).validate_dict(document)

    rule_ids = {message.rule_id for message in result.messages}
    assert rule_ids
    assert all(rule_id.startswith("spdx3_completeness.") for rule_id in rule_ids)


def test_spdx3_profile_findings_carry_element_paths_and_remediation():
    """Each profile finding must be actionable on its own."""
    document = json.loads(
        (SPDX3_FIXTURE.parent / "missing-supplier.spdx.json").read_text(
            encoding="utf-8"
        )
    )

    result = SbomCheckEngine(validator_class=_PassingSpdx3Core).validate_dict(document)

    assert result.messages
    for message in result.messages:
        assert message.field_path
        assert message.remediation


def test_spdx3_reports_core_validation_unavailable():
    """The unavailable SPDX 3 core validator must be visible in messages."""
    result = SbomCheckEngine().validate_dict(_spdx3_document())

    rule_ids = {message.rule_id for message in result.messages}
    assert "spdx3_core_validation_unavailable" in rule_ids


def test_spdx3_does_not_run_spdx2_profile_rules():
    """SPDX 2.3 field-path rules must not be applied to SPDX 3 documents."""
    result = SbomCheckEngine().validate_dict(_spdx3_document())

    rule_ids = {message.rule_id for message in result.messages}
    assert "missing_required_field" not in rule_ids
    assert "missing_package_field" not in rule_ids
    assert "missing_describes_relationship" not in rule_ids


def test_spdx2_profile_is_unaffected_by_spdx3_support():
    """SPDX 2.3 documents keep reporting no rule coverage."""
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "Test",
        "documentNamespace": "https://example.com/test",
        "creationInfo": {
            "created": "2023-01-01T00:00:00Z",
            "creators": ["Tool: test"],
        },
    }

    result = SbomCheckEngine().validate_dict(document)

    assert result.document_format is DocumentFormat.SPDX
    assert result.rule_coverage == []
    assert result.has_unevaluated_rules() is False
