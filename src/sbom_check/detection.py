# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format and specification-version detection for SBOM JSON documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sbom_check.models import DocumentFormat, ValidationSeverity
from sbom_validator.engine import ValidatorEngine

if TYPE_CHECKING:
    from pathlib import Path


SUPPORTED_CYCLONEDX_VERSIONS = frozenset({"1.3", "1.4", "1.5", "1.6", "1.7"})
MINIMUM_CYCLONEDX_VERSION = "1.3"

SPDX3_CONTEXT_PREFIX = "https://spdx.org/rdf/3."
SPDX3_SUPPORTED_VERSION = "3.0.1"
_SPDX3_CONTEXT_ROOT = "https://spdx.org/rdf/"


@dataclass(frozen=True, slots=True)
class DetectedDocument:
    """Format metadata detected from a parsed JSON document."""

    format: DocumentFormat
    spec_version: str | None
    validator_class: type[ValidatorEngine]


class UnsupportedDocumentError(ValueError):
    """Raised when a JSON object is not a supported SBOM document."""

    def __init__(self, message: str, *, rule_id: str = "unsupported_format") -> None:
        super().__init__(message)
        self.rule_id = rule_id


def detect_document(data: Any) -> DetectedDocument:
    """Detect the supported SBOM format and declared specification version.

    Detection is deliberately limited to top-level format markers. It does not
    perform schema validation and never invokes an SBOM validator.

    Args:
        data: Parsed JSON value.

    Returns:
        Detected format and declared specification version.

    Raises:
        UnsupportedDocumentError: If the input is malformed, unsupported, or
            contains conflicting format markers.
    """
    if not isinstance(data, dict):
        raise UnsupportedDocumentError(
            "Unsupported input: the JSON document must be a top-level object"
        )

    # "creationInfo" and "dataLicense" are valid property names in BOTH
    # SPDX 2.3 and SPDX 3.0.1, so they cannot be used to identify SPDX 2
    # specifically. Only markers unique to the SPDX 2.x tag-value-derived
    # JSON shape are used here.
    has_spdx_marker = any(
        marker in data for marker in ("SPDXID", "documentNamespace", "spdxVersion")
    )
    has_spdx3_marker = _has_spdx3_context_marker(data.get("@context"))
    has_cyclonedx_marker = "bomFormat" in data

    if (has_spdx_marker or has_spdx3_marker) and has_cyclonedx_marker:
        raise UnsupportedDocumentError(
            "Unsupported input: document contains conflicting SPDX and "
            "CycloneDX format markers",
            rule_id="unsupported_format",
        )

    if has_spdx3_marker and has_spdx_marker:
        raise UnsupportedDocumentError(
            "Conflicting SPDX 2 and SPDX 3 format markers",
            rule_id="conflicting_format_markers",
        )

    if has_cyclonedx_marker:
        return _detect_cyclonedx(data)

    if has_spdx3_marker:
        return _detect_spdx3(data)

    if has_spdx_marker:
        return _detect_spdx(data)

    raise UnsupportedDocumentError(
        "Unsupported input: document does not declare SPDX or CycloneDX format",
        rule_id="unsupported_format",
    )


def _has_spdx3_context_marker(context: Any) -> bool:
    """Return whether a JSON-LD ``@context`` value carries an SPDX 3 marker."""
    if isinstance(context, str):
        return context.startswith(SPDX3_CONTEXT_PREFIX)
    if isinstance(context, list):
        return any(
            isinstance(item, str) and item.startswith(SPDX3_CONTEXT_PREFIX)
            for item in context
        )
    return False


def _detect_spdx(data: dict[str, Any]) -> DetectedDocument:
    version = data.get("spdxVersion")
    spec_version = (
        version.removeprefix("SPDX-") if isinstance(version, str) and version else None
    )
    # pylint: disable=import-outside-toplevel
    from spdx_validator.engine import ValidationEngine  # noqa: PLC0415
    # pylint: enable=import-outside-toplevel

    validator_class = ValidationEngine
    return DetectedDocument(DocumentFormat.SPDX, spec_version, validator_class)


def _detect_spdx3_version(data: dict[str, Any]) -> str:
    if (context := data.get("@context")) is None:
        raise UnsupportedDocumentError(
            "The SPDX 3 document is missing the required @context.",
            rule_id="spdx3_missing_context",
        )

    if isinstance(context, list):
        raise UnsupportedDocumentError(
            "Unsupported SPDX 3 input: array-valued '@context' is not "
            "supported by the underlying validator",
            rule_id="unsupported_spdx3_context_form",
        )

    if not isinstance(context, str):
        raise UnsupportedDocumentError(
            "Unsupported SPDX 3 input: '@context' must be a string",
            rule_id="unsupported_spdx3_context_form",
        )

    if not context.startswith(SPDX3_CONTEXT_PREFIX):
        raise UnsupportedDocumentError(
            f"Unsupported SPDX 3 context '{context}'",
            rule_id="unsupported_spdx_version",
        )

    remainder = context.removeprefix(_SPDX3_CONTEXT_ROOT)
    if (version := remainder.split("/", 1)[0]) != SPDX3_SUPPORTED_VERSION:
        raise UnsupportedDocumentError(
            f"Unsupported SPDX 3 version '{version}'; only "
            f"{SPDX3_SUPPORTED_VERSION} is supported",
            rule_id="unsupported_spdx_version",
        )

    return version


def _detect_spdx3(data: dict[str, Any]) -> DetectedDocument:
    spec_version = _detect_spdx3_version(data)
    return DetectedDocument(
        DocumentFormat.SPDX3, spec_version, _UnavailableSpdx3CoreValidator
    )


def _detect_cyclonedx(data: dict[str, Any]) -> DetectedDocument:
    if (bom_format := data.get("bomFormat")) != DocumentFormat.CYCLONEDX.value:
        if bom_format is None:
            message = "Unsupported CycloneDX input: 'bomFormat' is required"
        else:
            message = f"Unsupported SBOM format '{bom_format}'"
        raise UnsupportedDocumentError(message, rule_id="unsupported_format")

    version = data.get("specVersion")
    if not isinstance(version, str) or not version:
        raise UnsupportedDocumentError(
            "Unsupported CycloneDX input: 'specVersion' must be a non-empty string",
            rule_id="unsupported_version",
        )

    if version not in SUPPORTED_CYCLONEDX_VERSIONS:
        raise UnsupportedDocumentError(
            f"Unsupported CycloneDX version '{version}'; CycloneDX {version} "
            f"is below the supported minimum of {MINIMUM_CYCLONEDX_VERSION}"
            if _is_older_cyclonedx_version(version)
            else f"Unsupported CycloneDX version '{version}'; supported versions "
            f"are {', '.join(sorted(SUPPORTED_CYCLONEDX_VERSIONS))}",
            rule_id="unsupported_version",
        )

    # pylint: disable=import-outside-toplevel
    from cyclone_validator.engine import CycloneDXValidationEngine  # noqa: PLC0415
    # pylint: enable=import-outside-toplevel

    validator_class = CycloneDXValidationEngine
    return DetectedDocument(DocumentFormat.CYCLONEDX, version, validator_class)


SPDX3_CORE_VALIDATION_UNAVAILABLE_RULE_ID = "spdx3_core_validation_unavailable"


@dataclass(frozen=True, slots=True)
class _Spdx3CoreValidationUnavailableMessage:
    """Message reporting that SPDX 3 core validation could not run."""

    severity: ValidationSeverity = ValidationSeverity.ERROR
    message: str = (
        "SPDX 3.0.1 core validation is not available in this build, so the "
        "document could not be checked against the SPDX 3.0.1 specification."
    )
    rule_id: str = SPDX3_CORE_VALIDATION_UNAVAILABLE_RULE_ID
    remediation: str = (
        "Validate SPDX 3.0.1 conformance with a tool that implements the "
        "SPDX 3.0.1 schema and SHACL checks."
    )


@dataclass(frozen=True, slots=True)
class _UnavailableSpdx3CoreValidatorResult:
    """Result returned by :class:`_UnavailableSpdx3CoreValidator`."""

    is_valid: bool
    messages: list[Any]


class _UnavailableSpdx3CoreValidator(ValidatorEngine):
    """Placeholder standing in for the SPDX 3.0.1 core validator.

    SPDX 3.0.1 core (schema/SHACL) validation is out of scope for this
    change and is delivered separately. This placeholder performs no core
    validation and reports that fact as an error, so that Qualcomm profile
    validation can still run against SPDX 3 documents without the document
    appearing to have passed SPDX 3.0.1 conformance checks that never ran.
    """

    def __init__(
        self,
        _schema_path: str | Path | None = None,
        _enable_schema_validation: bool = True,
        _enable_semantic_validation: bool = True,
    ) -> None:
        self.format = DocumentFormat.SPDX3

    def validate(
        self, _document: dict[str, Any], _spec_version: str
    ) -> _UnavailableSpdx3CoreValidatorResult:
        return self._unavailable()

    def validate_json_string(
        self, _json_string: str
    ) -> _UnavailableSpdx3CoreValidatorResult:
        return self._unavailable()

    def validate_dict(
        self, _document: dict[str, Any]
    ) -> _UnavailableSpdx3CoreValidatorResult:
        return self._unavailable()

    def validate_file(
        self, _file_path: str | Path
    ) -> _UnavailableSpdx3CoreValidatorResult:
        return self._unavailable()

    @staticmethod
    def _unavailable() -> _UnavailableSpdx3CoreValidatorResult:
        """Report that SPDX 3 core validation did not run.

        Returns:
            _UnavailableSpdx3CoreValidatorResult: An invalid result
            carrying one message explaining that core validation was
            unavailable. Reporting ``is_valid=True`` here would let an
            SPDX 3 document pass as conformant when nothing was checked.
        """
        return _UnavailableSpdx3CoreValidatorResult(
            is_valid=False,
            messages=[_Spdx3CoreValidationUnavailableMessage()],
        )


def _is_older_cyclonedx_version(version: str) -> bool:
    """Return whether a well-formed CycloneDX version is below 1.3."""
    try:
        major, minor = (int(part) for part in version.split(".", 1))
    except (ValueError, TypeError):
        return False
    return (major, minor) < (1, 3)


__all__ = [
    "MINIMUM_CYCLONEDX_VERSION",
    "SPDX3_CONTEXT_PREFIX",
    "SPDX3_CORE_VALIDATION_UNAVAILABLE_RULE_ID",
    "SPDX3_SUPPORTED_VERSION",
    "SUPPORTED_CYCLONEDX_VERSIONS",
    "DetectedDocument",
    "DocumentFormat",
    "UnsupportedDocumentError",
    "detect_document",
]
