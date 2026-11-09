# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3 validation engine."""

import json
from http.client import IncompleteRead
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch
from urllib.error import URLError

import pytest
import requests
from rdflib.exceptions import ParserError
from spdx3_validate.core import SpdxValidateError, UnknownVersionError
from spdx3_validate.core import (
    ValidationError as CustomValidationError,
)
from spdx3_validate.core import (
    ValidationResult as CustomValidationResult,
)

from spdx3_validator.engine import ValidationEngine
from spdx3_validator.models import ValidationResult
from spdx3_validator.resources import (
    _get_spdx_version,
    _load_schema_validator,
    _load_shacl_graph,
)


def _clear_resource_caches() -> None:
    """Reset cached resources between tests that exercise resource loading."""
    _load_schema_validator.cache_clear()
    _load_shacl_graph.cache_clear()
    _get_spdx_version.cache_clear()


class TestValidationEngine:
    """Test cases for the SPDX 3 validation engine."""

    def test_nested_context_scan_handles_deep_values(self):
        """Traverse deeply nested JSON-LD iteratively without recursion errors."""
        value: object = {"@context": "file:///etc/passwd"}
        for _ in range(3000):
            value = [value]

        assert ValidationEngine._contains_nested_context(value)

    def test_validate_dict_too_deep_returns_structured_error(self):
        """Handle deeply nested objects passed directly through the public API."""
        nested_graph: object = 0
        for _ in range(3000):
            nested_graph = [nested_graph]

        result = ValidationEngine().validate_dict(
            {
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "@graph": nested_graph,
            }
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "document_too_deeply_nested"

    def test_validate_json_string_too_deep_returns_structured_error(self):
        """Return a validation result rather than leaking RecursionError."""
        nested_graph = "[" * 3000 + "0" + "]" * 3000
        document = (
            '{"@context":"https://spdx.org/rdf/3.0.1/spdx-context.jsonld",'
            f'"@graph":{nested_graph}'
            "}"
        )

        result = ValidationEngine().validate_json_string(document)

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "document_too_deeply_nested"
        assert "too deeply nested" in result.messages[0].message

    @pytest.mark.parametrize("spec_version", ["3.0.1", "SPDX-3.0.1"])
    def test_validate_matching_version_delegates_to_validate_dict(
        self, spec_version: str
    ):
        """Accept bare and SPDX-prefixed SPDX 3.0.1 version identifiers."""
        engine = ValidationEngine()
        document = {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        expected = ValidationResult(is_valid=True, messages=[])

        with patch.object(engine, "validate_dict", return_value=expected) as validate:
            result = engine.validate(document, spec_version)

        assert result is expected
        validate.assert_called_once_with(document)

    def test_validate_rejects_mismatched_version(self):
        """Reject requested SPDX versions other than the supported version."""
        engine = ValidationEngine()
        with patch.object(engine, "validate_dict") as validate:
            result = engine.validate({}, "SPDX-3.0.0")

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "spec_version_mismatch"
        validate.assert_not_called()

    @pytest.mark.parametrize(
        ("schema_enabled", "semantic_enabled"),
        [(False, True), (True, False), (False, False)],
    )
    def test_validate_document_runs_only_enabled_stages(
        self, schema_enabled: bool, semantic_enabled: bool
    ):
        """Skip disabled schema and SHACL validation stages independently."""
        engine = ValidationEngine(
            enable_schema_validation=schema_enabled,
            enable_semantic_validation=semantic_enabled,
        )
        parsed_document = MagicMock()
        parsed_document.data = {}
        parsed_document.graph = MagicMock()
        parsed_document.source = "document"
        resources = MagicMock()
        resources.schema_validator.iter_errors.return_value = []

        with (
            patch("spdx3_validator.resources.socket.setdefaulttimeout") as set_timeout,
            patch(
                "spdx3_validator.engine.Document.from_text",
                return_value=parsed_document,
            ) as parse_document,
            patch(
                "spdx3_validator.engine.load_validation_resources",
                return_value=resources,
            ) as load_resources,
            patch("spdx3_validator.engine.check_graph", return_value=[]) as check_graph,
        ):
            result = engine._validate_document({})

        assert result.valid is True
        processed_result = engine._process_validation_result(result)
        assert processed_result.schema_valid is (True if schema_enabled else None)
        assert processed_result.semantic_valid is (True if semantic_enabled else None)
        set_timeout.assert_not_called()
        if schema_enabled:
            resources.schema_validator.iter_errors.assert_called_once_with({})
        else:
            resources.schema_validator.iter_errors.assert_not_called()
        if semantic_enabled:
            check_graph.assert_called_once()
        else:
            check_graph.assert_not_called()
        if schema_enabled or semantic_enabled:
            parse_document.assert_called_once()
            load_resources.assert_called_once_with(
                enable_schema_validation=schema_enabled,
                enable_semantic_validation=semantic_enabled,
            )
        else:
            parse_document.assert_not_called()
            load_resources.assert_not_called()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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
        assert mock_validate.call_args.args[0]["@context"].endswith(
            "/3.0.1/spdx-context.jsonld"
        )

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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

    def test_shacl_resource_decode_failure_is_not_blamed_on_document(self):
        """Map malformed downloaded SHACL data to a remote-resource failure."""
        _clear_resource_caches()
        parsed_document = MagicMock()
        schema_response = MagicMock()
        schema_response.__enter__.return_value = schema_response
        schema_response.json.return_value = {"type": "object"}
        shacl_response = MagicMock()
        shacl_response.__enter__.return_value = shacl_response
        shacl_response.content = b"\xff"

        try:
            with (
                patch(
                    "spdx3_validator.engine.Document.from_text",
                    return_value=parsed_document,
                ),
                patch(
                    "spdx3_validator.resources.requests.get",
                    side_effect=[schema_response, shacl_response],
                ) as get_resources,
            ):
                document = {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
                }
                result = ValidationEngine().validate_dict(document)
        finally:
            _clear_resource_caches()

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "remote_resource_unavailable"
        assert "Invalid SPDX 3 validation input" not in result.messages[0].message
        assert get_resources.call_count == 2

    @pytest.mark.parametrize(
        ("exception_type", "status_code"),
        [
            (requests.exceptions.ConnectionError, None),
            (requests.exceptions.HTTPError, 503),
            (requests.exceptions.Timeout, None),
            (requests.exceptions.SSLError, None),
        ],
    )
    @pytest.mark.parametrize("failed_request_index", [0, 1])
    def test_requests_resource_failures_include_safe_diagnostics(
        self, exception_type, status_code, failed_request_index: int
    ):
        """Report requests failures with their type, URL, and HTTP status."""
        _clear_resource_caches()
        parsed_document = MagicMock()
        successful_response = MagicMock()
        successful_response.__enter__.return_value = successful_response
        successful_response.json.return_value = {"type": "object"}
        calls: list[str] = []

        def get_resource(url: str, **kwargs: object) -> MagicMock:
            call_index = len(calls)
            calls.append(url)
            if call_index == failed_request_index:
                request = requests.Request("GET", url).prepare()
                response = None
                if status_code is not None:
                    response = requests.Response()
                    response.status_code = status_code
                    response.url = url
                    response.request = request
                raise exception_type(
                    "request failed at /private/local/path",
                    request=request,
                    response=response,
                )
            return successful_response

        try:
            with (
                patch(
                    "spdx3_validator.engine.Document.from_text",
                    return_value=parsed_document,
                ),
                patch(
                    "spdx3_validator.resources.requests.get",
                    side_effect=get_resource,
                ) as mock_get,
            ):
                document = {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
                }
                result = ValidationEngine().validate_dict(document)
        finally:
            _clear_resource_caches()

        message = result.messages[0].message
        failed_url = mock_get.call_args_list[failed_request_index].args[0]
        assert result.messages[0].rule_id == "remote_resource_unavailable"
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert exception_type.__name__ in message
        assert failed_url in message
        assert "/private/local/path" not in message
        if status_code is not None:
            assert f"({status_code})" in message

    def test_validate_dict_file_not_found_is_remote_resource_failure(self):
        """Treat resource-loading FileNotFoundError as unavailable infrastructure."""
        with (
            patch(
                "spdx3_validator.engine.Document.from_text", return_value=MagicMock()
            ),
            patch(
                "spdx3_validator.engine.load_validation_resources",
                side_effect=FileNotFoundError("resource not found"),
            ),
        ):
            result = ValidationEngine().validate_dict(
                {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
            )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "remote_resource_unavailable"

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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

    @pytest.mark.parametrize(
        ("document", "parser_exception"),
        [
            (
                {
                    "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                    "@graph": [{"@id": "_:x", "@reverse": 5}],
                },
                AttributeError("'int' object has no attribute 'items'"),
            ),
        ],
    )
    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_malformed_node_is_structured_input_error(
        self, mock_validate: Mock, document: dict, parser_exception: Exception
    ):
        """Do not leak rdflib Python exceptions for malformed JSON-LD nodes."""
        mock_validate.side_effect = parser_exception

        result = ValidationEngine().validate_dict(document)

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "spdx3_validation_input_error"
        assert "Invalid SPDX 3 validation input" in result.messages[0].message

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_rejects_non_object(self, mock_validate: Mock):
        """Test that dictionary validation rejects a non-object JSON value."""
        result = ValidationEngine().validate_dict([])  # type: ignore[arg-type]

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_format"
        assert result.messages[0].message == (
            "Unsupported input: the JSON document must be a top-level object."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_missing_context(self, mock_validate: Mock):
        """Test handling of a document without an @context."""
        result = ValidationEngine().validate_dict({"@graph": []})

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "spdx3_missing_context"
        assert result.messages[0].message == (
            "The SPDX document is missing the required @context."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_rejects_unsupported_context_format(
        self, mock_validate: Mock
    ):
        """Reject an SPDX document whose context is not a string."""
        result = ValidationEngine().validate_dict({"@context": {"spdx": "3.0.1"}})

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx3_context_form"
        assert result.messages[0].message == (
            "Unsupported @context format: expected a string."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_rejects_array_context(self, mock_validate: Mock):
        """Reject an SPDX document whose context is an array."""
        result = ValidationEngine().validate_dict(
            {
                "@context": [
                    "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                    {"ex": "https://example.com/"},
                ]
            }
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx3_context_form"
        assert result.messages[0].message == (
            "SPDX 3 documents with an array-valued @context are not "
            "supported by the underlying validator."
        )
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_upstream_unknown_version_is_structured(
        self, mock_validate: Mock
    ):
        """Convert an upstream unknown-version failure into a validation result."""
        mock_validate.side_effect = UnknownVersionError(
            "validator reported an unknown version"
        )

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "unsupported_spdx_version"
        assert result.messages[0].message == (
            "Unsupported SPDX version: validator reported an unknown version"
        )
        mock_validate.assert_called_once()

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_spdx_validation_error_is_unevaluated(
        self, mock_validate: Mock
    ):
        """Mark checks unevaluated when upstream validation cannot proceed."""
        mock_validate.side_effect = SpdxValidateError("upstream validation failed")

        result = ValidationEngine().validate_dict(
            {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "spdx_validate_error"

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_rejects_nested_context(self, mock_validate: Mock):
        """Reject nested contexts before JSON-LD parsing can resolve them."""
        result = ValidationEngine().validate_dict(
            {
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "@graph": [
                    {
                        "@context": "file:///etc/passwd",
                        "type": "Person",
                    }
                ],
            }
        )

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert result.messages[0].rule_id == "unsupported_spdx3_context_form"
        assert "Nested @context values are not supported" in result.messages[0].message
        mock_validate.assert_not_called()

    @patch("spdx3_validator.engine.ShaclDiagnosticParser.parse_shacl_error")
    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_dict_does_not_hide_result_processing_errors(
        self, mock_validate: Mock, mock_parse: Mock
    ):
        """Do not classify bugs in result conversion as input errors."""
        mock_validate.return_value = CustomValidationResult(
            errors=[CustomValidationError("document", "shacl", "diagnostic")]
        )
        mock_parse.side_effect = AttributeError("diagnostic parser bug")

        with pytest.raises(AttributeError, match="diagnostic parser bug"):
            ValidationEngine().validate_dict(
                {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
            )

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
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
        assert mock_validate.call_args.args[0]["@context"].endswith(
            "/3.0.1/spdx-context.jsonld"
        )

    @patch("spdx3_validator.engine.ValidationEngine._validate_document")
    def test_validate_file_invalid_json(self, mock_validate: Mock, tmp_path: Path):
        """Test handling of a file that does not contain valid JSON."""
        document = tmp_path / "invalid.spdx.json"
        document.write_text('{"@context":', encoding="utf-8")

        result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "json_parse_error"
        assert "Invalid JSON" in result.messages[0].message
        mock_validate.assert_not_called()

    def test_validate_file_not_found(self, tmp_path: Path):
        """Test validation of a non-existent file."""
        document = tmp_path / "nonexistent.spdx.json"

        result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "file_not_found"
        assert result.messages[0].message == f"File not found: {document}"

    def test_validate_file_read_error(self, tmp_path: Path):
        """Test handling of file read errors."""
        document = tmp_path / "document.spdx.json"

        with patch.object(Path, "open", side_effect=OSError("Permission denied")):
            result = ValidationEngine().validate_file(document)

        assert result.is_valid is False
        assert result.schema_valid is None
        assert result.semantic_valid is None
        assert len(result.messages) == 1
        assert result.messages[0].rule_id == "file_read_error"
        assert "Error reading file" in result.messages[0].message
