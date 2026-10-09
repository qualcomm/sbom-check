# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validation engine."""

import json
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError

from rdflib.exceptions import ParserError
from spdx3_validate.core import UnknownVersionError
from spdx3_validate.core import (
    ValidationError as CustomValidationError,
)
from spdx3_validate.core import (
    ValidationResult as CustomValidationResult,
)

from spdx3_validator.engine import ValidationEngine


class TestValidationEngine:
    """Test cases for the SPDX 3 validation engine."""

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_success(self, mock_validate: Mock):
        """Test successful dictionary validation without invoking the real validator."""
        mock_validate.return_value = CustomValidationResult()
        document = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}

        result = ValidationEngine().validate_dict(document)

        assert result.is_valid is True
        assert result.schema_valid is True
        assert result.semantic_valid is True
        assert result.messages == []
        mock_validate.assert_called_once()
        assert mock_validate.call_args.kwargs["version"] == "3.0.1"

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_remote_resource_failure_marks_checks_unevaluated(
        self, mock_validate: Mock
    ):
        """Mark checks as unevaluated when a required remote resource is unavailable."""
        mock_validate.side_effect = URLError("network disabled")

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "remote_resource_unavailable"

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_http_protocol_failure_is_remote_resource_failure(
        self, mock_validate: Mock
    ):
        """Convert HTTP protocol failures into remote-resource failures."""
        mock_validate.side_effect = IncompleteRead(b"partial")

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "remote_resource_unavailable"

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_parser_failure_is_structured(self, mock_validate: Mock):
        """Convert ambiguous RDF parser failures without calling them remote errors."""
        mock_validate.side_effect = ParserError("truncated RDF document")

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "spdx3_validation_parse_error"

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_rejects_non_object(self, mock_validate: Mock):
        """Test that dictionary validation rejects a non-object JSON value."""
        result = ValidationEngine().validate_dict([])  # type: ignore[arg-type]

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_format"
        assert result.messages[0].message == (
            "Unsupported input: the JSON document must be a top-level object."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_missing_context(self, mock_validate: Mock):
        """Test handling of a document without an @context."""
        result = ValidationEngine().validate_dict({"@graph": []})

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx3_missing_context"
        assert result.messages[0].message == (
            "The SPDX document is missing the required @context."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_rejects_unsupported_context_format(
        self, mock_validate: Mock
    ):
        """Reject an SPDX document whose context is not a string."""
        result = ValidationEngine().validate_dict({"@context": {"spdx": "3.0.1"}})

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx3_unsupported_context_format"
        assert result.messages[0].message == (
            "Unsupported @context format: expected a string."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_unknown_version(self, mock_validate: Mock):
        """Test handling of an unsupported SPDX context version."""
        mock_validate.side_effect = UnknownVersionError(
            "test.spdx.json has unknown version"
        )

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/4.0.0/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx_version"
        assert result.messages[0].message == (
            "Unsupported SPDX version: test.spdx.json has unknown version"
        )

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_schema_and_shacl_errors(self, mock_validate: Mock):
        """Test conversion of both schema and SHACL errors."""
        schema_error = CustomValidationError(
            "test.spdx.json",
            "schema",
            "Document does not conform to the SPDX schema",
        )
        shacl_error = CustomValidationError(
            "test.spdx.json",
            "shacl",
            """Violation of type sh:ClassConstraintComponent:
                sh:class <https://spdx.org/rdf/3.0.1/terms/Core/CreationInfo>
                Focus Node: <https://example.com/package/example>
                Value Node: _:CreationInfo2
                Result path: <https://spdx.org/rdf/3.0.1/terms/Core/creationInfo>
                Message: Value does not have class ns1:CreationInfo""",
        )
        mock_validate.return_value = CustomValidationResult(
            errors=[schema_error, shacl_error]
        )

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 2

        schema_message, shacl_message = result.messages
        assert schema_message.rule_id == "json_schema"
        assert schema_message.field_path is None
        assert schema_message.json_path is None
        assert schema_message.message == (
            "Schema validation error: Document does not conform to the SPDX schema"
        )
        assert shacl_message.rule_id == "spdx3_shacl_class_constraint"
        assert shacl_message.affected_element == "https://example.com/package/example"
        assert shacl_message.field_path == "creationInfo"
        assert shacl_message.found_value == "_:CreationInfo2"

    @patch("spdx3_validator.engine.validate")
    def test_validate_dict_shacl_error_preserves_affected_element(
        self, mock_validate: Mock
    ):
        """Test conversion of SHACL focus nodes into affected elements."""
        error = CustomValidationError(
            "test.spdx.json",
            "shacl",
            """Violation of type sh:ClassConstraintComponent:
                sh:class <https://spdx.org/rdf/3.0.1/terms/Core/CreationInfo>
                Focus Node: <https://example.com/package/example>
                Value Node: _:CreationInfo2
                Result path: <https://spdx.org/rdf/3.0.1/terms/Core/creationInfo>
                Message: Value does not have class ns1:CreationInfo""",
        )
        mock_validate.return_value = CustomValidationResult(errors=[error])

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is True
        assert result.semantic_valid is False
        assert len(result.messages) == 1

        message = result.messages[0]
        assert message.rule_id == "spdx3_shacl_class_constraint"
        assert message.affected_element == "https://example.com/package/example"
        assert message.field_path == "creationInfo"
        assert message.found_value == "_:CreationInfo2"

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_success(self, mock_validate: Mock, tmp_path: Path):
        """Test successful file validation without invoking the real validator."""
        mock_validate.return_value = CustomValidationResult()
        document = tmp_path / "document.spdx.json"
        document.write_text(
            json.dumps({"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}),
            encoding="utf-8",
        )

        result = ValidationEngine().validate_file(document)

        assert result.is_valid is True
        assert result.schema_valid is True
        assert result.semantic_valid is True
        assert result.messages == []
        mock_validate.assert_called_once()
        assert mock_validate.call_args.kwargs["version"] == "3.0.1"

    @patch("spdx3_validator.engine.validate")
    def test_validate_file_invalid_json(self, mock_validate: Mock, tmp_path: Path):
        """Test handling of a file that does not contain valid JSON."""
        document = tmp_path / "invalid.spdx.json"
        document.write_text('{"@context":', encoding="utf-8")

        result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "json_parse_error"
        assert "Invalid JSON" in result.messages[0].message
        mock_validate.assert_not_called()

    def test_validate_file_not_found(self, tmp_path: Path):
        """Test validation of a non-existent file."""
        document = tmp_path / "nonexistent.spdx.json"

        result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "file_not_found"
        assert result.messages[0].message == f"File not found: {document}"

    def test_validate_file_read_error(self, tmp_path: Path):
        """Test handling of file read errors."""
        document = tmp_path / "document.spdx.json"

        with patch.object(Path, "open", side_effect=OSError("Permission denied")):
            result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is False
        assert result.semantic_valid is False
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "file_read_error"
        assert "Error reading file" in result.messages[0].message
