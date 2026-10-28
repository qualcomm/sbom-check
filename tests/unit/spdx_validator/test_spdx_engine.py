# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for ValidationEngine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import Mock, mock_open, patch

import pytest

from spdx_validator.engine import ValidationEngine
from spdx_validator.models import (
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)


@pytest.fixture
def minimal_spdx_json() -> str:
    """Minimal valid SPDX document as JSON string."""
    return json.dumps(
        {
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
    )


@pytest.fixture
def mock_validation_result() -> ValidationResult:
    """Mock validation result."""
    return ValidationResult(
        is_valid=True,
        messages=[],
        schema_valid=True,
        semantic_valid=True,
    )


class TestValidationEngine:
    """Test cases for ValidationEngine."""

    def test_init_default_settings(self) -> None:
        """Test engine initialization with default settings."""
        engine = ValidationEngine()

        assert engine.enable_schema_validation is True
        assert engine.enable_semantic_validation is True
        assert engine.schema_validator is not None
        assert engine.semantic_validator is not None

    def test_init_schema_only(self) -> None:
        """Test engine initialization with schema validation only."""
        engine = ValidationEngine(
            enable_schema_validation=True,
            enable_semantic_validation=False,
        )

        assert engine.enable_schema_validation is True
        assert engine.enable_semantic_validation is False
        assert engine.schema_validator is not None
        assert engine.semantic_validator is None

    def test_init_semantic_only(self) -> None:
        """Test engine initialization with semantic validation only."""
        engine = ValidationEngine(
            enable_schema_validation=False,
            enable_semantic_validation=True,
        )

        assert engine.enable_schema_validation is False
        assert engine.enable_semantic_validation is True
        assert engine.schema_validator is None
        assert engine.semantic_validator is not None

    def test_validate_rejects_mismatched_spec_version(
        self, minimal_spdx_json: str
    ) -> None:
        document = json.loads(minimal_spdx_json)

        result = ValidationEngine().validate(document, spec_version="2.2")

        assert not result.is_valid
        assert result.messages[0].rule_id == "spec_version_mismatch"

    def test_validate_accepts_bare_spec_version(
        self, minimal_spdx_json: str, mock_validation_result: ValidationResult
    ) -> None:
        document = json.loads(minimal_spdx_json)
        engine = ValidationEngine()

        with patch.object(
            engine, "validate_dict", return_value=mock_validation_result
        ) as validate_dict:
            result = engine.validate(document, spec_version="2.3")

        assert result is mock_validation_result
        validate_dict.assert_called_once_with(document)

    def test_validate_accepts_prefixed_spec_version(
        self, minimal_spdx_json: str, mock_validation_result: ValidationResult
    ) -> None:
        document = json.loads(minimal_spdx_json)
        engine = ValidationEngine()

        with patch.object(
            engine, "validate_dict", return_value=mock_validation_result
        ) as validate_dict:
            result = engine.validate(document, spec_version="SPDX-2.3")

        assert result is mock_validation_result
        validate_dict.assert_called_once_with(document)

    def test_validate_json_string_invalid_json(self) -> None:
        """Test validation of invalid JSON string."""
        engine = ValidationEngine()
        result = engine.validate_json_string("invalid json {")

        assert not result.is_valid
        assert not result.schema_valid
        assert not result.semantic_valid
        assert len(result.messages) == 1
        assert "Invalid JSON" in result.messages[0].message
        assert result.messages[0].rule_id == "json_parse_error"

    def test_legacy_json_keyword_is_supported_with_warning(self) -> None:
        engine = ValidationEngine()

        with pytest.warns(DeprecationWarning, match="spdx_json"):
            result = engine.validate_json_string(spdx_json="invalid json {")

        assert not result.is_valid

    def test_legacy_dict_keyword_is_supported_with_warning(self) -> None:
        engine = ValidationEngine()

        with pytest.warns(DeprecationWarning, match="spdx_data"):
            result = engine.validate_dict(spdx_data={"test": "data"})

        assert not result.is_valid

    @patch("spdx_validator.validators.JsonSchemaValidator.validate")
    @patch("spdx_validator.validators.SemanticValidator.validate")
    def test_validate_json_string_success(
        self,
        mock_semantic_validate: Mock,
        mock_schema_validate: Mock,
        minimal_spdx_json: str,
        mock_validation_result: ValidationResult,
    ) -> None:
        """Test successful validation of JSON string."""
        mock_schema_validate.return_value = mock_validation_result
        mock_semantic_validate.return_value = mock_validation_result

        engine = ValidationEngine()
        result = engine.validate_json_string(minimal_spdx_json)

        assert result.is_valid
        assert result.schema_valid
        assert result.semantic_valid
        mock_schema_validate.assert_called_once()
        mock_semantic_validate.assert_called_once()

    @patch("spdx_validator.validators.JsonSchemaValidator.validate")
    def test_validate_dict_schema_failure_skips_semantic(
        self,
        mock_schema_validate: Mock,
    ) -> None:
        """Test that semantic validation is skipped when schema validation fails."""
        # Mock schema validation failure
        schema_result = ValidationResult(
            is_valid=False,
            messages=[
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message="Schema error",
                    rule_id="schema_error",
                )
            ],
            schema_valid=False,
            semantic_valid=True,
        )
        mock_schema_validate.return_value = schema_result

        engine = ValidationEngine()
        result = engine.validate_dict({"test": "data"})

        assert not result.is_valid
        assert not result.schema_valid
        assert not result.semantic_valid  # Should be False due to skipping

        # Should have original schema error plus skip warning
        assert len(result.messages) >= 2
        assert any("Schema error" in msg.message for msg in result.messages)
        assert any(
            "Semantic validation skipped" in msg.message for msg in result.messages
        )

    def test_validate_dict_rejects_non_hex_package_verification_code(
        self, sample_valid_spdx_document: dict[str, Any]
    ) -> None:
        """Test that the public validator rejects non-hex verification codes."""
        package = sample_valid_spdx_document["packages"][0]
        package["filesAnalyzed"] = True
        package["packageVerificationCode"] = {"packageVerificationCodeValue": "Z" * 40}

        result = ValidationEngine().validate_dict(sample_valid_spdx_document)

        assert len(result.messages) == 1
        message = result.messages[0]
        assert message.rule_id == "invalid_package_verification_code"
        assert message.path == (
            "packages.0.packageVerificationCode.packageVerificationCodeValue"
        )
        assert message.element_id == "SPDXRef-Package-TestApp"
        assert result.schema_valid
        assert not result.semantic_valid
        assert not result.is_valid

    def test_validate_dict_accepts_uppercase_hex_package_verification_code(
        self, sample_valid_spdx_document: dict[str, Any]
    ) -> None:
        """Test that uppercase hexadecimal verification codes match the official validator."""
        package = sample_valid_spdx_document["packages"][0]
        package["filesAnalyzed"] = True
        package["packageVerificationCode"] = {"packageVerificationCodeValue": "A" * 40}

        result = ValidationEngine().validate_dict(sample_valid_spdx_document)

        assert result.schema_valid
        assert result.semantic_valid
        assert result.is_valid
        assert len(result.messages) == 0

    @patch("spdx_validator.models.SpdxDocument.model_validate")
    @patch("spdx_validator.validators.JsonSchemaValidator.validate")
    @patch("spdx_validator.validators.SemanticValidator.validate")
    def test_validate_dict_pydantic_failure(
        self,
        mock_semantic_validate: Mock,
        mock_schema_validate: Mock,
        mock_pydantic_validate: Mock,
        mock_validation_result: ValidationResult,
    ) -> None:
        """Test handling of Pydantic validation failure."""
        mock_schema_validate.return_value = mock_validation_result
        mock_semantic_validate.return_value = mock_validation_result
        mock_pydantic_validate.side_effect = ValueError("Pydantic error")

        engine = ValidationEngine()
        result = engine.validate_dict({"test": "data"})

        assert not result.is_valid
        assert not result.schema_valid  # Should be False due to Pydantic error
        assert result.semantic_valid  # Semantic validation still passed

        assert any(
            "Pydantic model validation failed" in msg.message for msg in result.messages
        )

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_validate_file_success(
        self,
        mock_exists: Mock,
        mock_file: Mock,
        minimal_spdx_json: str,
    ) -> None:
        """Test successful file validation."""
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = minimal_spdx_json

        with patch.object(ValidationEngine, "validate_json_string") as mock_validate:
            mock_validate.return_value = ValidationResult(
                is_valid=True,
                messages=[],
                schema_valid=True,
                semantic_valid=True,
            )

            engine = ValidationEngine()
            result = engine.validate_file("test.json")

            assert result.is_valid
            mock_validate.assert_called_once_with(minimal_spdx_json)

    def test_validate_file_not_found(self) -> None:
        """Test validation of non-existent file."""
        engine = ValidationEngine()
        result = engine.validate_file("nonexistent.json")

        assert not result.is_valid
        assert not result.schema_valid
        assert not result.semantic_valid
        assert len(result.messages) == 1
        assert "File not found" in result.messages[0].message
        assert result.messages[0].rule_id == "file_not_found"

    @patch("pathlib.Path.open")
    @patch("pathlib.Path.exists")
    def test_validate_file_read_error(
        self, mock_exists: Mock, mock_open_func: Mock
    ) -> None:
        """Test handling of file read errors."""
        mock_exists.return_value = True
        mock_open_func.side_effect = PermissionError("Permission denied")

        engine = ValidationEngine()
        result = engine.validate_file("test.json")

        assert not result.is_valid
        assert not result.schema_valid
        assert not result.semantic_valid
        assert len(result.messages) == 1
        assert "Error reading file" in result.messages[0].message
        assert result.messages[0].rule_id == "file_read_error"

    @patch("spdx_validator.validators.JsonSchemaValidator.validate")
    @patch("spdx_validator.validators.SemanticValidator.validate")
    def test_validate_dict_both_validations_disabled(
        self,
        mock_semantic_validate: Mock,
        mock_schema_validate: Mock,
    ) -> None:
        """Test validation with both validators disabled."""
        engine = ValidationEngine(
            enable_schema_validation=False,
            enable_semantic_validation=False,
        )

        result = engine.validate_dict({"test": "data"})

        # Should still try Pydantic validation
        assert not result.is_valid  # Will fail Pydantic validation
        mock_schema_validate.assert_not_called()
        mock_semantic_validate.assert_not_called()

    def test_validate_dict_does_not_mutate_caller_document(self) -> None:
        """Test that normalization does not mutate the caller document."""
        document = {
            "packages": [
                {
                    "externalRefs": [
                        {"referenceCategory": "PACKAGE_MANAGER"},
                        {"referenceCategory": "PERSISTENT_ID"},
                    ]
                }
            ]
        }

        engine = ValidationEngine(
            enable_schema_validation=False,
            enable_semantic_validation=False,
        )
        engine.validate_dict(document)

        assert document["packages"][0]["externalRefs"] == [
            {"referenceCategory": "PACKAGE_MANAGER"},
            {"referenceCategory": "PERSISTENT_ID"},
        ]

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("pathlib.Path.exists")
    def test_validate_file_with_path_object(
        self, mock_exists: Mock, mock_file: Mock
    ) -> None:
        """Test file validation with Path object."""
        test_path = Path("test.json")
        mock_exists.return_value = True
        mock_file.return_value.read.return_value = '{"test": "data"}'

        with patch.object(ValidationEngine, "validate_json_string") as mock_validate:
            mock_validate.return_value = ValidationResult(
                is_valid=True,
                messages=[],
                schema_valid=True,
                semantic_valid=True,
            )

            engine = ValidationEngine()
            result = engine.validate_file(test_path)

            assert result.is_valid
            mock_validate.assert_called_once_with('{"test": "data"}')
