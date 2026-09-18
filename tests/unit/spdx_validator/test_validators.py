# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SPDX validators."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from spdx_validator.models import ValidationSeverity
from spdx_validator.validators import JsonSchemaValidator, SemanticValidator


@pytest.fixture
def minimal_spdx_data() -> dict[str, object]:
    """Minimal valid SPDX document data."""
    return {
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


@pytest.fixture
def mock_spdx_schema() -> dict[str, object]:
    """Mock SPDX JSON schema."""
    return {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {
            "SPDXID": {"type": "string"},
            "spdxVersion": {"type": "string"},
            "name": {"type": "string"},
            "dataLicense": {"type": "string"},
            "documentNamespace": {"type": "string"},
            "creationInfo": {
                "type": "object",
                "properties": {
                    "created": {"type": "string"},
                    "creators": {"type": "array", "items": {"type": "string"}},
                },
                "required": ["created", "creators"],
            },
        },
        "required": [
            "SPDXID",
            "spdxVersion",
            "name",
            "dataLicense",
            "documentNamespace",
            "creationInfo",
        ],
    }


class TestJsonSchemaValidator:
    """Test cases for JsonSchemaValidator."""

    def test_init_with_custom_schema_path(self) -> None:
        """Test validator initialization with custom schema path."""
        custom_path = Path("/custom/schema.json")
        validator = JsonSchemaValidator(custom_path)
        assert validator.schema_path == custom_path

    def test_init_with_default_schema_path(self) -> None:
        """Test validator initialization with the bundled schema resource."""
        validator = JsonSchemaValidator()
        assert validator.schema_path is None
        assert validator._schema_resource.name == "spdx-2.3-spec.json"

    def test_default_schema_loads_from_package_resource(self) -> None:
        """Test that the bundled schema is readable as a package resource."""
        schema = JsonSchemaValidator().schema

        assert schema["$schema"] == "http://json-schema.org/draft-07/schema#"

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("json.load")
    def test_schema_loading(
        self, mock_json_load: Mock, mock_file: Mock, mock_spdx_schema: dict[str, object]
    ) -> None:
        """Test JSON schema loading."""
        mock_json_load.return_value = mock_spdx_schema

        validator = JsonSchemaValidator(Path("test_schema.json"))
        schema = validator.schema

        assert schema == mock_spdx_schema
        mock_file.assert_called_once()
        mock_json_load.assert_called_once()

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("json.load")
    def test_validate_valid_document(
        self,
        mock_json_load: Mock,
        mock_file: Mock,
        mock_spdx_schema: dict[str, object],
        minimal_spdx_data: dict[str, object],
    ) -> None:
        """Test validation of valid SPDX document."""
        mock_json_load.return_value = mock_spdx_schema

        validator = JsonSchemaValidator(Path("test_schema.json"))
        result = validator.validate(minimal_spdx_data)

        assert result.is_valid
        assert result.schema_valid
        assert len(result.messages) == 0

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("json.load")
    def test_validate_invalid_document(
        self,
        mock_json_load: Mock,
        mock_file: Mock,
        mock_spdx_schema: dict[str, object],
    ) -> None:
        """Test validation of invalid SPDX document."""
        mock_json_load.return_value = mock_spdx_schema

        invalid_data = {"SPDXID": "SPDXRef-DOCUMENT"}  # Missing required fields

        validator = JsonSchemaValidator(Path("test_schema.json"))
        result = validator.validate(invalid_data)

        assert not result.is_valid
        assert not result.schema_valid
        assert len(result.messages) > 0
        assert all(msg.severity == ValidationSeverity.ERROR for msg in result.messages)

    @patch("pathlib.Path.open", new_callable=mock_open)
    @patch("json.load")
    def test_validate_schema_loading_error(
        self, mock_json_load: Mock, mock_file: Mock
    ) -> None:
        """Test handling of schema loading errors."""
        mock_json_load.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)

        validator = JsonSchemaValidator(Path("invalid_schema.json"))
        result = validator.validate({"test": "data"})

        assert not result.is_valid
        assert not result.schema_valid
        assert len(result.messages) == 1
        assert "JSON schema validation failed" in result.messages[0].message

    def test_normalize_reference_categories_underscore_to_hyphen(self) -> None:
        """Test normalization of underscore referenceCategory values to hyphen versions."""
        validator = JsonSchemaValidator()

        # Test data with underscore versions
        test_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package1",
                    "name": "Test Package 1",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE_MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/test@1.0.0",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package2",
                    "name": "Test Package 2",
                    "externalRefs": [
                        {
                            "referenceCategory": "PERSISTENT_ID",
                            "referenceType": "swh",
                            "referenceLocator": "swh:1:cnt:abc123",
                        }
                    ],
                },
            ],
        }

        # Apply normalization
        validator._normalize_reference_categories_targeted(test_data)

        # Verify normalization occurred
        assert (
            test_data["packages"][0]["externalRefs"][0]["referenceCategory"]
            == "PACKAGE-MANAGER"
        )
        assert (
            test_data["packages"][1]["externalRefs"][0]["referenceCategory"]
            == "PERSISTENT-ID"
        )

    def test_normalize_reference_categories_preserves_existing_hyphen_versions(
        self,
    ) -> None:
        """Test that existing hyphen versions are preserved during normalization."""
        validator = JsonSchemaValidator()

        # Test data with hyphen versions (should remain unchanged)
        test_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package1",
                    "name": "Test Package 1",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/test@1.0.0",
                        }
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package2",
                    "name": "Test Package 2",
                    "externalRefs": [
                        {
                            "referenceCategory": "PERSISTENT-ID",
                            "referenceType": "swh",
                            "referenceLocator": "swh:1:cnt:abc123",
                        }
                    ],
                },
            ],
        }

        # Apply normalization
        validator._normalize_reference_categories_targeted(test_data)

        # Verify hyphen versions are preserved
        assert (
            test_data["packages"][0]["externalRefs"][0]["referenceCategory"]
            == "PACKAGE-MANAGER"
        )
        assert (
            test_data["packages"][1]["externalRefs"][0]["referenceCategory"]
            == "PERSISTENT-ID"
        )

    def test_normalize_reference_categories_mixed_versions(self) -> None:
        """Test normalization with mixed underscore and hyphen versions in same document."""
        validator = JsonSchemaValidator()

        # Test data with mixed versions
        test_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package1",
                    "name": "Test Package 1",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE_MANAGER",  # underscore
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/test@1.0.0",
                        },
                        {
                            "referenceCategory": "PERSISTENT-ID",  # hyphen
                            "referenceType": "swh",
                            "referenceLocator": "swh:1:cnt:abc123",
                        },
                    ],
                },
                {
                    "SPDXID": "SPDXRef-Package2",
                    "name": "Test Package 2",
                    "externalRefs": [
                        {
                            "referenceCategory": "PERSISTENT_ID",  # underscore
                            "referenceType": "doi",
                            "referenceLocator": "10.1000/182",
                        },
                        {
                            "referenceCategory": "SECURITY",  # unchanged
                            "referenceType": "cve",
                            "referenceLocator": "CVE-2021-1234",
                        },
                    ],
                },
            ],
        }

        # Apply normalization
        validator._normalize_reference_categories_targeted(test_data)

        # Verify all are normalized to hyphen versions
        assert (
            test_data["packages"][0]["externalRefs"][0]["referenceCategory"]
            == "PACKAGE-MANAGER"
        )
        assert (
            test_data["packages"][0]["externalRefs"][1]["referenceCategory"]
            == "PERSISTENT-ID"
        )
        assert (
            test_data["packages"][1]["externalRefs"][0]["referenceCategory"]
            == "PERSISTENT-ID"
        )
        assert (
            test_data["packages"][1]["externalRefs"][1]["referenceCategory"]
            == "SECURITY"
        )  # unchanged

    def test_normalize_reference_categories_no_packages(self) -> None:
        """Test normalization with document that has no packages."""
        validator = JsonSchemaValidator()

        test_data = {"SPDXID": "SPDXRef-DOCUMENT", "name": "Test Document"}

        # Should not raise any errors
        validator._normalize_reference_categories_targeted(test_data)

        # Data should remain unchanged
        assert test_data == {"SPDXID": "SPDXRef-DOCUMENT", "name": "Test Document"}

    def test_normalize_reference_categories_no_external_refs(self) -> None:
        """Test normalization with packages that have no externalRefs."""
        validator = JsonSchemaValidator()

        test_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package1",
                    "name": "Test Package 1",
                    # No externalRefs
                }
            ],
        }

        # Should not raise any errors
        validator._normalize_reference_categories_targeted(test_data)

        # Data should remain unchanged
        assert "externalRefs" not in test_data["packages"][0]


class TestSemanticValidator:
    """Test cases for SemanticValidator."""

    def test_init(self) -> None:
        """Test validator initialization."""
        validator = SemanticValidator()
        assert validator is not None

    def test_init_with_default_ontology_path(self) -> None:
        """Test validator initialization with default ontology path (ignored)."""
        validator = SemanticValidator()
        # The optimized validator doesn't use ontology files
        assert validator is not None

    def test_validate_success(self) -> None:
        """Test successful semantic validation with DESCRIBES relationship."""
        # Valid data with DESCRIBES relationship
        valid_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": "https://example.com/test",
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Package",
                }
            ],
            "packages": [
                {
                    "SPDXID": "SPDXRef-Package",
                    "name": "Test Package",
                }
            ],
        }

        validator = SemanticValidator()
        result = validator.validate(valid_data)

        # Should pass validation with DESCRIBES relationship and valid SPDX IDs
        assert result.semantic_valid
        assert result.is_valid
        assert len(result.messages) == 0

    def test_validate_missing_describes_relationship(
        self, minimal_spdx_data: dict[str, object]
    ) -> None:
        """Test validation failure for missing DESCRIBES relationship."""
        validator = SemanticValidator()
        result = validator.validate(minimal_spdx_data)

        # Should fail because no DESCRIBES relationship
        assert not result.semantic_valid
        assert not result.is_valid
        assert len(result.messages) > 0
        assert any("DESCRIBES relationship" in msg.message for msg in result.messages)

    def test_validate_invalid_spdx_id_reference(self) -> None:
        """Test validation failure for invalid SPDX ID references."""
        invalid_data = {
            "SPDXID": "SPDXRef-DOCUMENT",
            "documentNamespace": "https://example.com/test",
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-NonExistent",  # Invalid reference
                }
            ],
        }

        validator = SemanticValidator()
        result = validator.validate(invalid_data)

        assert not result.semantic_valid
        assert not result.is_valid
        assert len(result.messages) > 0
        assert any("unknown related SPDX ID" in msg.message for msg in result.messages)

    def test_validate_semantic_processing_error(self) -> None:
        """Test handling of semantic processing errors."""
        # Create invalid data that will cause an error in constraint checking
        invalid_data = {
            "invalid": "structure"
        }  # This will cause an error in the optimized method

        validator = SemanticValidator()
        result = validator.validate(invalid_data)

        # Should handle the error gracefully and return a failed result
        assert not result.semantic_valid
        assert not result.is_valid
        assert len(result.messages) >= 1
        # Should fail because no DESCRIBES relationship is present
        assert any("DESCRIBES relationship" in msg.message for msg in result.messages)
