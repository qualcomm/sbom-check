# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SPDX Pydantic models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from spdx_validator.models import (
    ChecksumAlgorithm,
    CreationInfo,
    SpdxDocument,
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)


def test_validation_message_creation() -> None:
    """Test ValidationMessage model creation."""
    message = ValidationMessage(
        severity=ValidationSeverity.ERROR,
        message="Test error message",
        path="test.path",
        element_id="SPDXRef-Document",
        rule_id="test_rule",
    )

    assert message.severity == ValidationSeverity.ERROR
    assert message.message == "Test error message"
    assert message.path == "test.path"
    assert message.element_id == "SPDXRef-Document"
    assert message.rule_id == "test_rule"


def test_validation_result_properties() -> None:
    """Test ValidationResult properties."""
    error_msg = ValidationMessage(
        severity=ValidationSeverity.ERROR,
        message="Error message",
    )
    warning_msg = ValidationMessage(
        severity=ValidationSeverity.WARNING,
        message="Warning message",
    )

    result = ValidationResult(
        is_valid=False,
        messages=[error_msg, warning_msg],
        schema_valid=False,
        semantic_valid=True,
    )

    assert not result.is_valid
    assert result.has_errors
    assert result.has_warnings
    assert len(result.messages) == 2


def test_creation_info_validation() -> None:
    """Test CreationInfo model validation."""
    # Valid creation info
    creation_info = CreationInfo(
        created="2024-01-01T00:00:00Z",
        creators=["Tool: test-tool"],
        licenseListVersion="3.21",
    )

    assert creation_info.created == "2024-01-01T00:00:00Z"
    assert creation_info.creators == ["Tool: test-tool"]
    assert creation_info.licenseListVersion == "3.21"

    # Invalid - empty creators list
    with pytest.raises(ValidationError):
        CreationInfo(
            created="2024-01-01T00:00:00Z",
            creators=[],  # Should fail min_length=1
        )


def test_spdx_document_version_validation() -> None:
    """Test SPDX document version validation."""
    valid_doc_data = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z",
            "creators": ["Tool: test-tool"],
        },
        "name": "Test Document",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/test",
    }

    # Valid document
    doc = SpdxDocument.model_validate(valid_doc_data)
    assert doc.spdxVersion == "SPDX-2.3"
    assert doc.dataLicense == "CC0-1.0"

    # Invalid SPDX version
    invalid_version_data = valid_doc_data.copy()
    invalid_version_data["spdxVersion"] = "SPDX-2.2"

    with pytest.raises(ValidationError, match=r"Only SPDX-2\.3 is supported"):
        SpdxDocument.model_validate(invalid_version_data)

    # Invalid data license
    invalid_license_data = valid_doc_data.copy()
    invalid_license_data["dataLicense"] = "MIT"

    with pytest.raises(ValidationError, match=r"Data license must be CC0-1\.0"):
        SpdxDocument.model_validate(invalid_license_data)


def test_checksum_algorithm_enum() -> None:
    """Test ChecksumAlgorithm enum values."""
    assert ChecksumAlgorithm.SHA1 == "SHA1"
    assert ChecksumAlgorithm.SHA256 == "SHA256"
    assert ChecksumAlgorithm.BLAKE3 == "BLAKE3"

    # Test all enum values are valid
    for algorithm in ChecksumAlgorithm:
        assert isinstance(algorithm.value, str)
        assert len(algorithm.value) > 0


def test_minimal_valid_spdx_document() -> None:
    """Test creation of minimal valid SPDX document."""
    minimal_doc = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "creationInfo": {
            "created": "2024-01-01T00:00:00Z",
            "creators": ["Tool: spdx-validator-test"],
        },
        "name": "Minimal Test Document",
        "dataLicense": "CC0-1.0",
        "documentNamespace": "https://example.com/minimal-test",
    }

    doc = SpdxDocument.model_validate(minimal_doc)
    assert doc.SPDXID == "SPDXRef-DOCUMENT"
    assert doc.name == "Minimal Test Document"
    assert doc.packages is None  # Optional field
    assert doc.files is None  # Optional field
