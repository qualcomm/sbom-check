# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""SPDX 3.0.1 validation engine."""

import json
from http.client import HTTPException
from json import JSONDecodeError
from pathlib import Path
from typing import Any
from urllib.error import URLError

import requests
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
    load_validation_resources,
)


class _ResourceLoadError(OSError):
    """Represent non-requests failures while loading validation resources."""


class ValidationEngine(ValidatorEngine):
    """Validation engine for SPDX 3.0.1 documents."""

    def __init__(
        self,
        schema_path: str | Path | None = None,
        enable_schema_validation: bool = True,
        enable_semantic_validation: bool = True,
    ) -> None:
        """Initialize the validation engine for SPDX 3.0.1."""
        if schema_path is not None:
            raise ValueError("A custom schema path is not supported for SPDX 3.")
        self.enable_schema_validation = enable_schema_validation
        self.enable_semantic_validation = enable_semantic_validation

    def validate(self, document: dict[str, Any], spec_version: str) -> ValidationResult:
        """Validate a parsed SPDX document against the requested version."""
        if (version := spec_version.removeprefix("SPDX-")) != SPDX_VERSION:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "Document SPDX version does not match the requested "
                            f"version {version}"
                        ),
                        rule_id="spec_version_mismatch",
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
            )
        return self.validate_dict(document)

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
    def _contains_nested_context(value: Any) -> bool:
        """Return whether a JSON-LD value contains a nested @context key."""
        stack = [value]
        visited: set[int] = set()

        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                if id(current) in visited:
                    continue
                visited.add(id(current))
                for key, item in current.items():
                    if key == "@context":
                        return True
                    stack.append(item)
            elif isinstance(current, list):
                if id(current) in visited:
                    continue
                visited.add(id(current))
                stack.extend(current)

        return False

    def _validate_document(self, document: dict[str, Any]) -> CustomValidationResult:
        """Parse and run the enabled validation stages using cached resources."""
        errors: list[CustomValidationError] = []
        if not self.enable_schema_validation and not self.enable_semantic_validation:
            return CustomValidationResult(errors=errors)

        parsed_document = Document.from_text("document", json.dumps(document))
        try:
            resources: ValidationResources = load_validation_resources(
                enable_schema_validation=self.enable_schema_validation,
                enable_semantic_validation=self.enable_semantic_validation,
            )
        except requests.RequestException:
            raise
        except Exception as resource_error:
            raise _ResourceLoadError from resource_error

        if (
            self.enable_schema_validation
            and resources.schema_validator is not None
        ):
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

        if self.enable_semantic_validation and resources.shacl_graph is not None:
            errors.extend(
                CustomValidationError(parsed_document.source, "shacl", message)
                for message in check_graph(
                    parsed_document.graph,
                    resources.shacl_graph,
                    resources.version,
                    True,
                )
            )
        return CustomValidationResult(errors=errors)

    def _process_validation_result(
        self, result: CustomValidationResult
    ) -> ValidationResult:
        """Convert the upstream validation result to the public result model."""
        all_messages: list[ValidationMessage] = []
        schema_valid = True if self.enable_schema_validation else None
        semantic_valid = True if self.enable_semantic_validation else None

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

    @staticmethod
    def _document_too_deeply_nested_result() -> ValidationResult:
        """Create a structured validation failure result."""
        return ValidationResult(
            is_valid=False,
            messages=[
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message="Document is too deeply nested to validate.",
                    rule_id="document_too_deeply_nested",
                )
            ],
            schema_valid=None,
            semantic_valid=None,
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
        try:
            result = self._validate_document(document)
        except RecursionError:
            return self._document_too_deeply_nested_result()
        except UnknownVersionError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Unsupported SPDX version: {e}",
                        rule_id="unsupported_spdx_version",
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
            )
        except SpdxValidateError as e:
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"SPDX validation error: {e}",
                        rule_id="spdx_validate_error",
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
            )
        except requests.RequestException as e:
            request = getattr(e, "request", None)
            response = getattr(e, "response", None)
            if request is None and response is not None:
                request = getattr(response, "request", None)

            detail = type(e).__name__
            if (status_code := getattr(response, "status_code", None)) is not None:
                detail += f" ({status_code})"
            if url := getattr(request, "url", None):
                detail += f" for {url}"

            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            "SPDX validation could not be completed because a "
                            f"required remote resource was unavailable: {detail}"
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
            # the validation host. Non-requests resource-loading failures are
            # wrapped as OSError so they are not blamed on the submitted SBOM.
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
            )
        except RecursionError:
            return self._document_too_deeply_nested_result()

        try:
            return self.validate_dict(spdx_data)
        except RecursionError:
            return self._document_too_deeply_nested_result()

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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                        rule_id="unsupported_spdx3_context_form",
                    )
                ],
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
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
                schema_valid=None,
                semantic_valid=None,
            )
