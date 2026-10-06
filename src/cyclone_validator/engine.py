# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""CycloneDX validation engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from cyclone_validator.validators import (
    CycloneDXValidationResult,
    JsonSchemaValidator,
    SemanticValidator,
)
from sbom_check.models import ValidationMessage, ValidationSeverity
from sbom_validator.engine import ValidatorEngine


class CycloneDXValidationEngine(ValidatorEngine):
    """Engine adapter that delegates CycloneDX schema checks to a validator."""

    def __init__(
        self,
        schema_path: str | Path | None = None,
        enable_schema_validation: bool = True,
        enable_semantic_validation: bool = True,
    ) -> None:
        """Initialize the engine and configure its validation stages."""
        del schema_path  # CycloneDX selects bundled schemas by specVersion.
        self.enable_schema_validation = enable_schema_validation
        self.enable_semantic_validation = enable_semantic_validation

        self.schema_validator: JsonSchemaValidator | None = None
        self.semantic_validator: SemanticValidator | None = None

        if enable_schema_validation:
            self.schema_validator = JsonSchemaValidator()
        if enable_semantic_validation:
            self.semantic_validator = SemanticValidator()

    def validate(
        self, document: dict[str, Any], spec_version: str
    ) -> CycloneDXValidationResult:
        """Validate a parsed CycloneDX document."""
        messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True

        if self.enable_schema_validation and self.schema_validator:
            try:
                schema_result = self.schema_validator.validate(
                    document, spec_version
                )
            except ValueError as error:
                return CycloneDXValidationResult(
                    is_valid=False,
                    messages=[
                        ValidationMessage(
                            severity=ValidationSeverity.ERROR,
                            message=str(error),
                            rule_id="unsupported_version",
                        )
                    ],
                )
            messages.extend(schema_result.messages)
            schema_valid = schema_result.is_valid

        if self.enable_semantic_validation and self.semantic_validator and schema_valid:
            semantic_result = self.semantic_validator.validate(
                document, spec_version
            )
            messages.extend(semantic_result.messages)
            semantic_valid = semantic_result.is_valid
        elif self.enable_semantic_validation and not schema_valid:
            messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.WARNING,
                    message=(
                        "Semantic validation skipped due to schema validation failures"
                    ),
                    rule_id="semantic_validation_skipped",
                )
            )
            semantic_valid = False

        return CycloneDXValidationResult(
            is_valid=schema_valid and semantic_valid,
            messages=messages,
        )

    def validate_json_string(self, json_string: str) -> CycloneDXValidationResult:
        """Validate a CycloneDX document from a JSON string."""
        try:
            document = json.loads(json_string)
        except json.JSONDecodeError as error:
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Invalid JSON: {error!s}",
                        rule_id="json_parse_error",
                    )
                ],
            )

        if not isinstance(document, dict):
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="CycloneDX JSON document must be an object",
                        rule_id="invalid_document_type",
                    )
                ],
            )

        spec_version = document.get("specVersion")
        if not isinstance(spec_version, str):
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="CycloneDX document must define a string specVersion",
                        rule_id="missing_spec_version",
                    )
                ],
            )

        return self.validate_dict(document, spec_version)

    def validate_dict(
        self, document: dict[str, Any], spec_version: str | None = None
    ) -> CycloneDXValidationResult:
        """Validate a CycloneDX document from a dictionary."""
        version = spec_version or document.get("specVersion")
        if not isinstance(version, str):
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message="CycloneDX document must define a string specVersion",
                        rule_id="missing_spec_version",
                    )
                ],
            )
        return self.validate(document, version)

    def validate_file(self, file_path: str | Path) -> CycloneDXValidationResult:
        """Validate a CycloneDX document from a file."""
        try:
            with Path(file_path).open(encoding="utf-8") as file_handle:
                return self.validate_json_string(file_handle.read())
        except FileNotFoundError:
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"File not found: {file_path}",
                        rule_id="file_not_found",
                    )
                ],
            )
        except (OSError, UnicodeDecodeError) as error:
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Error reading file {file_path}: {error!s}",
                        rule_id="file_read_error",
                    )
                ],
            )


CycloneDXEngine = CycloneDXValidationEngine

__all__ = ["CycloneDXEngine", "CycloneDXValidationEngine"]
