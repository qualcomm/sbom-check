# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Main SPDX validation engine combining JSON Schema and OWL validation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sbom_validator.engine import ValidatorEngine
from spdx_validator.models import (
    SpdxDocument,
    ValidationMessage,
    ValidationResult,
    ValidationSeverity,
)
from spdx_validator.validators import JsonSchemaValidator, SemanticValidator


class ValidationEngine(ValidatorEngine):
    """Main SPDX validation engine that combines multiple validation approaches."""

    def __init__(
        self,
        schema_path: str | Path | None = None,
        enable_schema_validation: bool = True,
        enable_semantic_validation: bool = True,
    ) -> None:
        """Initialize the validation engine.

        Args:
            schema_path: Path to SPDX 2.3 JSON schema file
            enable_schema_validation: Whether to perform JSON schema validation
            enable_semantic_validation: Whether to perform semantic constraint validation
        """
        self.enable_schema_validation = enable_schema_validation
        self.enable_semantic_validation = enable_semantic_validation

        self.schema_validator: JsonSchemaValidator | None = None
        self.semantic_validator: SemanticValidator | None = None

        if enable_schema_validation:
            self.schema_validator = JsonSchemaValidator(schema_path)

        if enable_semantic_validation:
            self.semantic_validator = SemanticValidator()

    def validate(
        self, document: dict[str, Any], spec_version: str = "SPDX-2.3"
    ) -> ValidationResult:
        """Validate a parsed SPDX document through the engine pipeline."""
        del spec_version
        return self.validate_dict(document)

    def validate_json_string(self, json_string: str) -> ValidationResult:
        """Validate SPDX document from JSON string.

        Args:
            json_string: SPDX document as JSON string

        Returns:
            Combined validation result
        """
        try:
            # Parse JSON with custom object hook for normalization during parsing
            spdx_data = json.loads(json_string, object_hook=self._normalize_object_hook)
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

    def _normalize_object_hook(self, obj: dict[str, Any]) -> dict[str, Any]:
        """Object hook for JSON parsing to normalize during parsing.

        Converts underscore variants to hyphen variants for enum values:
        - PACKAGE_MANAGER -> PACKAGE-MANAGER
        - PERSISTENT_ID -> PERSISTENT-ID

        Args:
            obj: Dictionary object from JSON parsing

        Returns:
            Normalized object
        """
        if "referenceCategory" in obj:
            ref_cat = obj["referenceCategory"]
            if ref_cat == "PACKAGE_MANAGER":
                obj["referenceCategory"] = "PACKAGE-MANAGER"
            elif ref_cat == "PERSISTENT_ID":
                obj["referenceCategory"] = "PERSISTENT-ID"
        return obj

    def _normalize_data(self, data: dict[str, Any]) -> dict[str, Any]:
        """Normalize SPDX data to handle spec inconsistencies.

        Efficiently converts underscore variants to hyphen variants for enum values:
        - PACKAGE_MANAGER -> PACKAGE-MANAGER
        - PERSISTENT_ID -> PERSISTENT-ID

        Only processes packages.externalRefs.referenceCategory fields for performance.

        Args:
            data: SPDX document as dictionary

        Returns:
            Data with enum values corrected (modifies in-place for performance)
        """
        # Only process packages if they exist
        if "packages" in data and isinstance(data["packages"], list):  # pylint: disable=too-many-nested-blocks
            for package in data["packages"]:
                if (
                    isinstance(package, dict)
                    and "externalRefs" in package
                    and isinstance(package["externalRefs"], list)
                ):
                    for ext_ref in package["externalRefs"]:
                        if isinstance(ext_ref, dict) and "referenceCategory" in ext_ref:
                            ref_cat = ext_ref["referenceCategory"]
                            if ref_cat == "PACKAGE_MANAGER":
                                ext_ref["referenceCategory"] = "PACKAGE-MANAGER"
                            elif ref_cat == "PERSISTENT_ID":
                                ext_ref["referenceCategory"] = "PERSISTENT-ID"

        return data

    def _enhance_pydantic_error_message(
        self, error_message: str, document: dict[str, Any]
    ) -> str:
        """Enhance Pydantic error message by replacing package indices with SPDX IDs.

        Args:
            error_message: Original Pydantic error message
            spdx_data: SPDX document data to extract SPDX IDs from

        Returns:
            Enhanced error message with SPDX IDs
        """
        # Pattern to match "packages.N." where N is a number
        pattern = r"packages\.(\d+)\."

        def replace_package_reference(match: re.Match[str]) -> str:
            package_index = int(match.group(1))
            packages = document.get("packages", [])

            if 0 <= package_index < len(packages):
                package = packages[package_index]
                if spdx_id := package.get("SPDXID"):
                    return f"{spdx_id}."

            # Fallback to original if SPDX ID not found
            return match.group(0)

        return re.sub(pattern, replace_package_reference, error_message)

    def validate_dict(self, document: dict[str, Any]) -> ValidationResult:
        """Validate SPDX document from dictionary.

        Args:
            document: SPDX document as dictionary (already normalized if from JSON)

        Returns:
            Combined validation result
        """
        document = self._normalize_data(document)
        all_messages: list[ValidationMessage] = []
        schema_valid = True
        semantic_valid = True

        # Perform JSON schema validation
        if self.enable_schema_validation and self.schema_validator:
            schema_result = self.schema_validator.validate(document)
            all_messages.extend(schema_result.messages)
            schema_valid = schema_result.schema_valid

        # Perform semantic validation only if schema validation passes
        if self.enable_semantic_validation and self.semantic_validator and schema_valid:
            semantic_result = self.semantic_validator.validate(document)
            all_messages.extend(semantic_result.messages)
            semantic_valid = semantic_result.semantic_valid
        elif self.enable_semantic_validation and not schema_valid:
            # Skip semantic validation if schema validation failed
            all_messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.WARNING,
                    message="Semantic validation skipped due to schema validation failures",
                    rule_id="semantic_validation_skipped",
                )
            )
            semantic_valid = False

        # Try to parse with Pydantic for additional validation
        try:
            SpdxDocument.model_validate(document)
        except (ValueError, TypeError, AttributeError) as e:
            # Enhance error message with SPDX IDs
            enhanced_message = self._enhance_pydantic_error_message(str(e), document)
            all_messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=f"Pydantic model validation failed: {enhanced_message}",
                    rule_id="pydantic_validation_error",
                )
            )
            schema_valid = False

        overall_valid = schema_valid and semantic_valid

        return ValidationResult(
            is_valid=overall_valid,
            messages=all_messages,
            schema_valid=schema_valid,
            semantic_valid=semantic_valid,
        )

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
