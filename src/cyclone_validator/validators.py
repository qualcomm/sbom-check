# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""CycloneDX JSON Schema validation implementations."""

# pylint: disable=fixme

from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator
from jsonschema.exceptions import best_match

from cyclone_validator.models import (
    CycloneDXValidationResult,
    ValidationMessage,
    ValidationSeverity,
)

_SCHEMA_VERSIONS: dict[str, SchemaVersion] = {
    "1.2": SchemaVersion.V1_2,
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}


_MAX_ENUM_ERROR_LENGTH = 512


def iter_bom_ref_holders(
    document: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield ``(json_path, element)`` for every element that may carry a bom-ref.

    Covers ``metadata.component``, top-level and nested ``components``, and
    top-level and nested ``services``. Dependency entries may legally point at
    any of these, so reference resolution and uniqueness consider all of them.
    """
    metadata = document.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        yield from _walk_element("$.metadata.component", metadata["component"])
    for key in ("components", "services"):
        if isinstance(items := document.get(key), list):
            yield from _walk_list(f"$.{key}", items)


def _walk_list(path: str, items: list[Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    for index, item in enumerate(items):
        if isinstance(item, dict):
            yield from _walk_element(f"{path}[{index}]", item)


def _walk_element(
    path: str, element: dict[str, Any]
) -> Iterable[tuple[str, dict[str, Any]]]:
    yield path, element
    for key in ("components", "services"):
        if isinstance(children := element.get(key), list):
            yield from _walk_list(f"{path}.{key}", children)


class SemanticValidator:
    """Validate CycloneDX semantic integrity the JSON Schema cannot express.

    Every failure here is a hard error: duplicate ``bom-ref`` values make
    dependency entries ambiguous, and dangling references describe a graph
    that does not match the document's contents.
    """

    def validate(
        self, document: dict[str, Any], spec_version: str
    ) -> CycloneDXValidationResult:
        """Check bom-ref uniqueness and dependency reference resolution."""
        del spec_version
        messages: list[ValidationMessage] = []

        first_seen: dict[str, str] = {}
        duplicates: dict[str, list[str]] = {}
        for path, element in iter_bom_ref_holders(document):
            if not isinstance(ref := element.get("bom-ref"), str):
                continue
            if ref in first_seen:
                duplicates.setdefault(ref, [first_seen[ref]]).append(path)
            else:
                first_seen[ref] = path

        for ref, paths in duplicates.items():
            messages.append(
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=(
                        f"The identifier (bom-ref) {ref!r} is used by "
                        f"{len(paths)} entries ({', '.join(paths)}). Each "
                        "component and service needs its own identifier, "
                        "otherwise dependency entries that name it are ambiguous."
                    ),
                    rule_id="cyclonedx_semantic.duplicate_bom_ref",
                    field_path=f"{paths[1]}.bom-ref",
                    found_value=ref,
                    remediation=(
                        "Give every component and service a unique bom-ref, "
                        "then update the dependencies section to use the new "
                        "identifiers."
                    ),
                )
            )

        messages.extend(self._dangling_references(document, set(first_seen)))
        return CycloneDXValidationResult(is_valid=not messages, messages=messages)

    @staticmethod
    def _dangling_references(
        document: dict[str, Any], known_refs: set[str]
    ) -> list[ValidationMessage]:
        messages: list[ValidationMessage] = []
        if not isinstance(dependencies := document.get("dependencies"), list):
            return messages

        def report(ref: Any, path: str, role: str) -> None:
            if isinstance(ref, str) and ref not in known_refs:
                messages.append(
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=(
                            f"The dependency graph {role} {ref!r}, but no "
                            "component or service in the document has that "
                            "bom-ref."
                        ),
                        rule_id="cyclonedx_semantic.dangling_dependency_ref",
                        field_path=path,
                        found_value=ref,
                        remediation=(
                            "Add the missing component to the SBOM, or correct "
                            "the identifier in the dependencies section so it "
                            "matches an existing component's bom-ref."
                        ),
                    )
                )

        for index, entry in enumerate(dependencies):
            if not isinstance(entry, dict):
                continue
            base = f"$.dependencies[{index}]"
            report(entry.get("ref"), f"{base}.ref", "lists an entry for")
            for key in ("dependsOn", "provides"):
                if isinstance(targets := entry.get(key), list):
                    for target_index, target in enumerate(targets):
                        report(
                            target,
                            f"{base}.{key}[{target_index}]",
                            "points to",
                        )
        return messages


class JsonSchemaValidator:
    """Validate CycloneDX documents against version-specific JSON schemas."""

    def __init__(self) -> None:
        """Initialize the per-schema-version strict validator cache."""
        self._strict_validators: dict[SchemaVersion, JsonStrictValidator] = {}

    def _get_strict_validator(
        self, schema_version: SchemaVersion
    ) -> JsonStrictValidator:
        """Return the compiled strict validator for a schema version."""
        if schema_version not in self._strict_validators:
            self._strict_validators[schema_version] = JsonStrictValidator(
                schema_version
            )
        return self._strict_validators[schema_version]

    def validate(
        self, document: dict[str, Any], spec_version: str
    ) -> CycloneDXValidationResult:
        """Validate a parsed CycloneDX document against its declared schema."""
        if (schema_version := _SCHEMA_VERSIONS.get(spec_version)) is None:
            raise ValueError(f"Unsupported CycloneDX schema version: {spec_version}")

        validator = self._get_strict_validator(schema_version)
        try:
            # JsonStrictValidator exposes string-based validation publicly; serialize
            # here rather than relying on its private validator implementation.
            errors = validator.validate_str(json.dumps(document), all_errors=True)
        except (TypeError, ValueError) as error:
            return CycloneDXValidationResult(
                is_valid=False,
                messages=[
                    ValidationMessage(
                        severity=ValidationSeverity.ERROR,
                        message=f"Document is not JSON serializable: {error!s}",
                        rule_id="json_serialization_error",
                        field_path="$",
                    )
                ],
            )
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
            raw_error = getattr(error, "data", error)
            relevant_error = _most_relevant_error(raw_error)
            raw_error = getattr(relevant_error, "data", relevant_error)
            path = _format_json_path(
                getattr(raw_error, "absolute_path", getattr(raw_error, "path", None))
            )
            message = _format_error_message(raw_error, relevant_error)
            schema = getattr(raw_error, "schema", None)
            description = (
                schema.get("description") if isinstance(schema, dict) else None
            )
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


def _most_relevant_error(error: Any) -> Any:
    """Return the deepest actionable nested schema error, when available."""
    if not (context := getattr(error, "context", ())):
        return error

    candidates = list(_leaf_errors(context))
    deepest_path_length = max(
        len(getattr(candidate, "absolute_path", getattr(candidate, "path", ())))
        for candidate in candidates
    )
    deepest_candidates = [
        candidate
        for candidate in candidates
        if len(getattr(candidate, "absolute_path", getattr(candidate, "path", ())))
        == deepest_path_length
    ]
    return best_match(deepest_candidates)


def _leaf_errors(errors: Iterable[Any]) -> Iterable[Any]:
    """Yield leaf errors from a nested JSON Schema error tree."""
    for error in errors:
        if context := getattr(error, "context", ()):
            yield from _leaf_errors(context)
        else:
            yield error


def _format_error_message(raw_error: Any, fallback_error: Any) -> str:
    """Format schema errors without emitting massive enum definitions."""
    message = getattr(raw_error, "message", None) or str(fallback_error)
    if (enum_error := _find_enum_error(raw_error)) is not None:
        path = list(getattr(enum_error, "path", ()))
        if path[-2:] == ["license", "id"]:
            instance = getattr(enum_error, "instance", None)
            return repr(instance) + " is not a valid SPDX license ID"
        message = getattr(enum_error, "message", None) or message

    if len(message) > _MAX_ENUM_ERROR_LENGTH:
        return f"{message[: _MAX_ENUM_ERROR_LENGTH - 3]}..."
    return message


def _find_enum_error(error: Any) -> Any | None:
    """Find an enum validation error in a nested jsonschema error tree."""
    if getattr(error, "validator", None) == "enum":
        return error

    for context_error in getattr(error, "context", ()):
        if enum_error := _find_enum_error(context_error):
            return enum_error
    return None


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
