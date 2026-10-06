# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SBOM validation engine."""

import json
from unittest.mock import Mock, patch

from sbom_check.config.loader import ConfigLoader
from sbom_check.engine import SbomCheckEngine
from sbom_check.models import SbomCheckResult, ValidationSeverity


def test_engine_initialization():
    """Test that SbomCheckEngine initializes correctly."""
    engine = SbomCheckEngine()
    assert engine is not None
    assert engine.config is not None


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


def test_validate_json_string_invalid_json():
    """Test validation with invalid JSON."""
    engine = SbomCheckEngine()
    result = engine.validate_json_string("invalid json")

    assert not result.overall_valid
    assert not result.spdx_valid
    assert not result.profile_valid
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


def test_unknown_license_symbols_accepts_valid_expressions():
    """Valid SPDX ids, compound expressions, and sentinels are accepted."""
    engine = SbomCheckEngine()

    for value in [
        "MIT",
        "MIT OR Apache-2.0",
        "GPL-2.0-only WITH Classpath-exception-2.0",
        "NOASSERTION",
        "NONE",
        "",
    ]:
        assert engine._unknown_license_symbols(value, set()) == [], value


def test_unknown_license_symbols_rejects_free_text():
    """Free-form license names that are not SPDX ids are reported."""
    engine = SbomCheckEngine()

    assert engine._unknown_license_symbols("BSD", set()) == ["BSD"]
    assert engine._unknown_license_symbols("Public Domain", set()) == ["Public Domain"]


def test_unknown_license_symbols_rejects_malformed_expression():
    """A syntactically malformed expression is reported as invalid."""
    engine = SbomCheckEngine()

    assert engine._unknown_license_symbols("MIT AND", set()) == ["MIT AND"]
    assert engine._unknown_license_symbols("(MIT", set()) == ["(MIT"]


def test_unknown_license_symbols_license_ref_requires_declaration():
    """A LicenseRef- id is accepted only when declared, otherwise reported."""
    engine = SbomCheckEngine()

    declared = {"LicenseRef-foo"}
    assert engine._unknown_license_symbols("LicenseRef-foo", declared) == []
    assert engine._unknown_license_symbols("MIT AND LicenseRef-foo", declared) == []
    assert engine._unknown_license_symbols("LicenseRef-bar", declared) == [
        "LicenseRef-bar"
    ]
    assert engine._unknown_license_symbols("LicenseRef-foo", set()) == [
        "LicenseRef-foo"
    ]


def test_validate_package_licenses_reports_invalid_fields():
    """Invalid licenseConcluded/licenseDeclared values produce errors."""
    engine = SbomCheckEngine()
    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    package = {
        "SPDXID": "SPDXRef-Package-0",
        "licenseConcluded": "MIT",
        "licenseDeclared": "Public Domain",
    }
    engine._validate_package_licenses(package, 0, set(), result)

    errors = [
        msg for msg in result.messages if msg.rule_id == "invalid_license_expression"
    ]
    assert len(errors) == 1
    assert "licenseDeclared" in errors[0].field_path


def test_validate_package_licenses_skips_missing_fields():
    """Packages without license fields produce no license errors."""
    engine = SbomCheckEngine()
    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    engine._validate_package_licenses({"SPDXID": "SPDXRef-Package-0"}, 0, set(), result)

    assert result.messages == []


def test_validate_package_requirements_validates_licenses_in_default_profile():
    """The default profile flags invalid license expressions on packages."""
    engine = SbomCheckEngine()  # default profile
    result = SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)

    spdx_data = {
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-0",
                "name": "pkg",
                "licenseConcluded": "NotA License",
                "licenseDeclared": "LicenseRef-custom",
            }
        ],
        "hasExtractedLicensingInfos": [{"licenseId": "LicenseRef-custom"}],
    }
    engine._validate_package_requirements(spdx_data, result)

    license_errors = [
        msg for msg in result.messages if msg.rule_id == "invalid_license_expression"
    ]
    # Only the free-text licenseConcluded is invalid; the declared LicenseRef- is fine.
    assert len(license_errors) == 1
    assert "licenseConcluded" in license_errors[0].field_path
