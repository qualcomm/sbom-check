# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""SPDX 3.0.1 validation engine."""

import json
from http.client import HTTPException
from json import JSONDecodeError
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from urllib.error import URLError

from rdflib.exceptions import ParserError
from rdflib.plugins.parsers.notation3 import BadSyntax
from spdx3_validate import validate
from spdx3_validate.core import SpdxValidateError, UnknownVersionError
from spdx3_validate.core import ValidationError as CustomValidationError
from spdx3_validate.core import ValidationResult as CustomValidationResult

from sbom_validator.engine import ValidatorEngine
from sbom_validator.models import DocumentFormat
from spdx3_validator.diagnostics import ShaclDiagnosticParser
from spdx3_validator.models import (
    REMOTE_RESOURCE_UNAVAILABLE_RULE_ID,
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)

SPDX_VERSION = "3.0.1"


class ValidationEngine(ValidatorEngine):
    """Validation engine for SPDX 3.0.1 documents."""

    def __init__(self) -> None:
        """Initialize the validation engine for SPDX 3.0.1."""
        self.format = DocumentFormat.SPDX3

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
        all_messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True
        source_path: Path | None = None
        try:
            with TemporaryDirectory() as temp_dir:
                source_path = Path(temp_dir) / "document.spdx.json"
                source_path.write_text(json.dumps(document), encoding="utf-8")

                result: CustomValidationResult = validate(
                    sources=str(source_path), version=SPDX_VERSION
                )

            if result.valid:
                return ValidationResult(
                    is_valid=True,
                    messages=all_messages,
                    schema_valid=schema_valid,
                    semantic_valid=semantic_valid,
                )

            schema_errors = [
                error for error in result.errors if error.kind == "schema"
            ]
            for error in self._unique_errors(schema_errors):
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
                        message="SPDX validation temporary file not found",
                        rule_id="temporary_file_not_found",
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
        except ValueError as e:
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

    def validate_json_string(self, spdx_json: str) -> ValidationResult:
        """Validate SPDX document from JSON string.

        Args:
            spdx_json: SPDX document as JSON string

        Returns:
            Combined validation result
        """
        try:
            spdx_data = json.loads(spdx_json)
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

    def validate_dict(self, spdx_data: dict[str, Any]) -> ValidationResult:
        """Validate SPDX document from dictionary.

        Args:
            spdx_data: SPDX document as dictionary (already normalized if from JSON)

        Returns:
            Combined validation result
        """
        runtime_document: Any = spdx_data
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

        if "@context" not in spdx_data:
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

        if not isinstance(spdx_data["@context"], str):
            return ValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="Unsupported @context format: expected a string.",
                        rule_id="spdx3_unsupported_context_format",
                    )
                ],
                schema_valid=False,
                semantic_valid=False,
            )

        return self._validate(spdx_data)

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
