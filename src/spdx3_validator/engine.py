# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""SPDX 3.0.1 validation engine."""

import json
from http.client import HTTPException
from json import JSONDecodeError
from pathlib import Path
from typing import Any
from urllib.error import URLError

from rdflib.exceptions import ParserError
from rdflib.plugins.parsers.notation3 import BadSyntax
from spdx3_validate.core import (
    Document,
    SpdxValidateError,
    UnknownVersionError,
    check_graph,
)
from spdx3_validate.core import ValidationError as CustomValidationError
from spdx3_validate.core import ValidationResult as CustomValidationResult

from sbom_validator.engine import ValidatorEngine
from sbom_validator.models import REMOTE_RESOURCE_UNAVAILABLE_RULE_ID
from spdx3_validator.diagnostics import ShaclDiagnosticParser
from spdx3_validator.models import (
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)
from spdx3_validator.resources import (
    SPDX_CONTEXT_URL,
    SPDX_VERSION,
    ValidationResources,
    configure_network_timeout,
    load_validation_resources,
)


class ValidationEngine(ValidatorEngine):
    """Validation engine for SPDX 3.0.1 documents."""

    def __init__(self) -> None:
        """Initialize the validation engine for SPDX 3.0.1."""

    @staticmethod
    def _unique_errors(
        errors: list[CustomValidationError],
    ) -> list[CustomValidationError]:
        """
        Remove duplicate validation errors caused by lossy schema-error formatting.

        The underlying validator can produce distinct schema errors that are rendered
        with the same source, kind, and message. Keep only the first occurrence for
        clearer user-facing output.
        """
        seen = set()
        unique = []

        for error in errors:
            if (key := (error.source, error.kind, error.message)) not in seen:
                seen.add(key)
                unique.append(error)

        return unique

    @staticmethod
    def _user_facing_error(error: Exception, source_path: Path | None) -> str:
        """Remove the temporary source path from a validation error message."""
        message = str(error)
        if source_path is not None:
            message = message.replace(str(source_path), "document")
        return message

    @staticmethod
    def _contains_nested_context(value: Any) -> bool:
        """Return whether a JSON-LD value contains a nested @context key."""
        if isinstance(value, dict):
            return any(
                key == "@context" or ValidationEngine._contains_nested_context(item)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return any(
                ValidationEngine._contains_nested_context(item) for item in value
            )
        return False

    @staticmethod
    def _validate_document(document: dict[str, Any]) -> CustomValidationResult:
        """Parse and validate a document using cached resources."""
        configure_network_timeout()
        parsed_document = Document.from_text("document", json.dumps(document))
        resources: ValidationResources = load_validation_resources()
        errors: list[CustomValidationError] = []

        for error in resources.schema_validator.iter_errors(parsed_document.data):
            message = (
                error.message if isinstance(error.instance, str) else "Is not valid"
            )
            errors.append(
                CustomValidationError(
                    parsed_document.source,
                    "schema",
                    f"{error.json_path}: {message}",
                )
            )

        errors.extend(
            CustomValidationError(parsed_document.source, "shacl", message)
            for message in check_graph(
                parsed_document.graph, resources.shacl_graph, resources.version, True
            )
        )
        return CustomValidationResult(errors=errors)

    @staticmethod
    def _process_validation_result(
        result: CustomValidationResult,
    ) -> ValidationResult:
        """Convert the upstream validation result to the public result model."""
        all_messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True

        if result.valid:
            return ValidationResult(
                is_valid=True,
                messages=all_messages,
                schema_valid=schema_valid,
                semantic_valid=semantic_valid,
            )

        schema_errors = [error for error in result.errors if error.kind == "schema"]
        for error in ValidationEngine._unique_errors(schema_errors):
            schema_valid = False
            all_messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=f"Schema validation error: {error.message}",
                    rule_id="json_schema",
                    field_path=None,
                    json_path=(
                        error.message.split(":", 1)[0]
                        if error.message.startswith("$")
                        else None
                    ),
                )
            )

        shacl_errors = [error for error in result.errors if error.kind == "shacl"]
        for error in shacl_errors:
            semantic_valid = False
            shacl_error = ShaclDiagnosticParser.parse_shacl_error(error.message)
            all_messages.append(shacl_error)

        return ValidationResult(
            is_valid=False,
            messages=all_messages,
            schema_valid=schema_valid,
            semantic_valid=semantic_valid,
        )

    def _validate(  # pylint: disable=too-many-return-statements  # noqa: PLR0911
        self, document: dict[str, Any]
    ) -> ValidationResult:
        """
        Validate SPDX 3.0.1 document.

        Args:
            document: Parsed SPDX 3.0.1 document to validate.

        Returns:
            Validation result
        """
        source_path: Path | None = None
        try:
            result = self._validate_document(document)
        except UnknownVersionError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "Unsupported SPDX version: "
                            f"{self._user_facing_error(e, source_path)}"
                        ),
                        rule_id="unsupported_spdx_version",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except SpdxValidateError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation error: "
                            f"{self._user_facing_error(e, source_path)}"
                        ),
                        rule_id="spdx_validate_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except FileNotFoundError:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="SPDX validation resource not found.",
                        rule_id="spdx3_validation_resource_not_found",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except (
            HTTPException,
            URLError,
            TimeoutError,
            ConnectionError,
        ) as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation could not be completed because a "
                            f"required remote resource was unavailable: {e}"
                        ),
                        rule_id=REMOTE_RESOURCE_UNAVAILABLE_RULE_ID,
                        remediation=(
                            "Make the required SPDX validation resources available "
                            "and run validation again."
                        ),
                    )
                ],
                # Resource availability is neither a schema nor a semantic
                # failure in the submitted SBOM. Neither check was evaluated.
                schema_valid=None,
                semantic_valid=None,
            )
        except OSError:
            # Do not expose raw OS error text: it may contain a local path from
            # the validation host. This is a defensive fallback for resource
            # failures not represented by one of the more specific exceptions.
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation could not be completed because a "
                            "required remote resource was unavailable."
                        ),
                        rule_id=REMOTE_RESOURCE_UNAVAILABLE_RULE_ID,
                        remediation=(
                            "Make the required SPDX validation resources available "
                            "and run validation again."
                        ),
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
            )
        except (ParserError, BadSyntax) as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation could not be completed because an "
                            f"RDF document could not be parsed: {e}"
                        ),
                        rule_id="spdx3_validation_parse_error",
                        remediation=(
                            "Check the SBOM and required SPDX validation resources "
                            "and run validation again."
                        ),
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
            )
        except JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid JSON: {e!s}",
                        rule_id="json_parse_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except (AttributeError, TypeError, ValueError) as e:
            # rdflib's JSON-LD parser can raise ordinary Python exceptions for
            # malformed node content (rather than a ParserError). Keep those
            # failures local to this document so callers can continue validating
            # a batch of files.
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid SPDX 3 validation input: {e}",
                        rule_id="spdx3_validation_input_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        return self._process_validation_result(result)

    def validate_json_string(self, json_string: str) -> ValidationResult:
        """Validate SPDX document from JSON string.

        Args:
            json_string: SPDX document as JSON string

        Returns:
            Combined validation result
        """
        try:
            spdx_data = json.loads(json_string)
        except json.JSONDecodeError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid JSON: {e!s}",
                        rule_id="json_parse_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        return self.validate_dict(spdx_data)

    def validate_dict(  # pylint: disable=too-many-return-statements  # noqa: PLR0911
        self, document: dict[str, Any]
    ) -> ValidationResult:
        """Validate SPDX document from dictionary.

        Args:
            document: SPDX document as dictionary (already normalized if from JSON)

        Returns:
            Combined validation result
        """
        runtime_document: Any = document
        if not isinstance(runtime_document, dict):
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "Unsupported input: the JSON document must be a top-level object."
                        ),
                        rule_id="unsupported_format",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        if "@context" not in document:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=("The SPDX document is missing the required @context."),
                        rule_id="spdx3_missing_context",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        context = document["@context"]
        if isinstance(context, list):
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX 3 documents with an array-valued @context are not "
                            "supported by the underlying validator."
                        ),
                        rule_id="unsupported_spdx3_context_form",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        if not isinstance(context, str):
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="Unsupported @context format: expected a string.",
                        rule_id="unsupported_spdx3_context_form",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        if context != SPDX_CONTEXT_URL:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "Unsupported SPDX version: the document must use the "
                            f"SPDX {SPDX_VERSION} context {SPDX_CONTEXT_URL!r}."
                        ),
                        rule_id="unsupported_spdx_version",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        if any(
            key != "@context" and self._contains_nested_context(value)
            for key, value in document.items()
        ):
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "Nested @context values are not supported; SPDX 3.0.1 "
                            "requires a single top-level context."
                        ),
                        rule_id="spdx3_validation_input_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        return self._validate(document)

    def validate_file(self, file_path: str | Path) -> ValidationResult:
        """Validate SPDX document from file.

        Args:
            file_path: Path to SPDX JSON file

        Returns:
            Validation result
        """
        try:
            file_path = Path(file_path)
            with file_path.open(encoding="utf-8") as f:
                spdx_json = f.read()
            return self.validate_json_string(spdx_json)
        except FileNotFoundError:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"File not found: {file_path}",
                        rule_id="file_not_found",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
        except (OSError, UnicodeDecodeError) as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Error reading file {file_path}: {e!s}",
                        rule_id="file_read_error",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )
