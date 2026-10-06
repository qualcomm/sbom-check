# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""CycloneDX JSON Schema validation implementations."""

# pylint: disable=fixme

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from cyclonedx.schema import OutputFormat, SchemaVersion
from cyclonedx.validation import make_schemabased_validator

from sbom_check.models import ValidationMessage, ValidationSeverity

_SCHEMA_VERSIONS: dict[str, SchemaVersion] = {
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}


@dataclass(frozen=True, slots=True)
class CycloneDXValidationResult:
    """Result returned by CycloneDX JSON Schema validation."""

    is_valid: bool
    messages: list[ValidationMessage]


class SemanticValidator:
    """Validate CycloneDX semantic constraints.

    TODO: Implement CycloneDX semantic validation rules after the schema
    validator is complete.
    """

    def validate(
        self, document: dict[str, Any], spec_version: str
    ) -> CycloneDXValidationResult:
        """Return a passing result until semantic rules are implemented."""
        del document, spec_version
        # TODO: Add CycloneDX semantic constraint validation.
        return CycloneDXValidationResult(is_valid=True, messages=[])


class JsonSchemaValidator:
    """Validate CycloneDX documents against version-specific JSON schemas."""

    def validate(
        self, document: dict[str, Any], spec_version: str
    ) -> CycloneDXValidationResult:
        """Validate a parsed CycloneDX document against its declared schema."""
        if (schema_version := _SCHEMA_VERSIONS.get(spec_version)) is None:
            raise ValueError(f"Unsupported CycloneDX schema version: {spec_version}")

        validator = make_schemabased_validator(OutputFormat.JSON, schema_version)
        errors = validator.validate_str(json.dumps(document), all_errors=True)
        messages = self._convert_errors(errors)
        # Additional properties are schema violations and must invalidate the document.
        return CycloneDXValidationResult(is_valid=not messages, messages=messages)

    @staticmethod
    def _convert_errors(
        errors: Iterable[Any] | Any | None,
    ) -> list[ValidationMessage]:
        if errors is None:
            return []

        if not isinstance(errors, Iterable):
            errors = (errors,)

        messages: list[ValidationMessage] = []
        for error in errors:
            raw_error = getattr(error, "data", None)
            path = _format_json_path(getattr(raw_error, "path", None))
            message = getattr(raw_error, "message", None) or str(error)
            schema = getattr(raw_error, "schema", None)
            description = schema.get("description") if isinstance(schema, dict) else None
            title = schema.get("title") if isinstance(schema, dict) else None

            if title and description:
                message = f"{title}: {message}. {description}"
            elif description:
                message = f"{message}. {description}"
            elif title:
                message = f"{title}: {message}"

            messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=message,
                    rule_id="cyclonedx_schema_error",
                    field_path=path,
                )
            )

        return messages


def _format_json_path(path: Any) -> str | None:
    """Format a JSON Schema path as a readable document path."""
    if path is None:
        return None

    if not (parts := list(path)):
        return "$"

    formatted = "$"
    for part in parts:
        formatted += f"[{part}]" if isinstance(part, int) else f".{part}"
    return formatted


CycloneDXValidator = JsonSchemaValidator

__all__ = [
    "CycloneDXValidationResult",
    "CycloneDXValidator",
    "JsonSchemaValidator",
    "SemanticValidator",
]
