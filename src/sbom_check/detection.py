# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format and specification-version detection for SBOM JSON documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sbom_check.models import DocumentFormat

if TYPE_CHECKING:
    from sbom_validator.engine import ValidatorEngine

SPDX3_CONTEXT_PREFIX = "https://spdx.org/rdf/3."
SPDX2_SUPPORTED_VERSION = "SPDX-2.3"
SPDX3_SUPPORTED_VERSION = "3.0.1"

SUPPORTED_CYCLONEDX_VERSIONS = frozenset({"1.3", "1.4", "1.5", "1.6", "1.7"})
MINIMUM_CYCLONEDX_VERSION = "1.3"


@dataclass(frozen=True, slots=True)
class DetectedDocument:
    """Format metadata detected from a parsed JSON document."""

    format: DocumentFormat
    spec_version: str | None
    validator_class: type[ValidatorEngine]


class UnsupportedDocumentError(ValueError):
    """Raised when input is malformed or declares an unsupported format/version."""

    def __init__(self, message: str, *, rule_id: str = "unsupported_format") -> None:
        super().__init__(message)
        self.rule_id = rule_id


def _has_spdx3_context_marker(context: Any) -> bool:
    """Return whether a context string or context array declares SPDX 3."""
    if isinstance(context, str):
        return context.startswith(SPDX3_CONTEXT_PREFIX)

    if isinstance(context, list):
        return any(
            isinstance(item, str) and item.startswith(SPDX3_CONTEXT_PREFIX)
            for item in context
        )

    return False


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

    context = data.get("@context")
    has_spdx3_marker = _has_spdx3_context_marker(context)
    # These markers are specific to SPDX 2.x.  Properties such as
    # ``creationInfo`` and ``dataLicense`` are also valid SPDX 3 properties
    # and must not be used to identify an SPDX 2 document.
    has_spdx2_marker = any(
        marker in data
        for marker in (
            "SPDXID",
            "documentNamespace",
            "spdxVersion",
        )
    )

    if has_spdx3_marker and has_spdx2_marker:
        raise UnsupportedDocumentError(
            "Conflicting SPDX 2 and SPDX 3 format markers",
            rule_id="conflicting_format_markers",
        )

    has_cyclonedx_marker = "bomFormat" in data
    if (has_spdx2_marker and has_cyclonedx_marker) or (
        has_spdx3_marker and has_cyclonedx_marker
    ):
        raise UnsupportedDocumentError(
            "Unsupported input: document contains conflicting SPDX and "
            "CycloneDX format markers",
            rule_id="unsupported_format",
        )

    if has_spdx3_marker:
        return _detect_spdx3(data)

    if has_spdx2_marker:
        return _detect_spdx(data)

    if has_cyclonedx_marker:
        return _detect_cyclonedx(data)

    raise UnsupportedDocumentError(
        "Unsupported input: document does not declare SPDX or CycloneDX format",
        rule_id="unsupported_format",
    )


def _detect_spdx_version(data: dict[str, Any]) -> str:
    if "spdxVersion" not in data:
        raise UnsupportedDocumentError(
            "SPDX document is missing the required spdxVersion field.",
            rule_id="missing_spdx_version",
        )

    version = data["spdxVersion"]
    if not isinstance(version, str) or version != SPDX2_SUPPORTED_VERSION:
        raise UnsupportedDocumentError(
            f"Unsupported SPDX version: {version!r}; "
            f"only {SPDX2_SUPPORTED_VERSION} is supported",
            rule_id="unsupported_spdx_version",
        )

    return version.removeprefix("SPDX-")


def _detect_spdx3_version(data: dict[str, Any]) -> str:
    context = data.get("@context")
    if "@context" not in data:
        raise UnsupportedDocumentError(
            "The SPDX 3 document is missing the required @context.",
            rule_id="spdx3_missing_context",
        )

    if isinstance(context, list):
        raise UnsupportedDocumentError(
            "SPDX 3 documents with an array-valued @context are not supported "
            "by the underlying validator.",
            rule_id="unsupported_spdx3_context_form",
        )

    if not isinstance(context, str):
        raise UnsupportedDocumentError(
            "Unsupported @context format: expected a string.",
            rule_id="unsupported_spdx3_context_form",
        )

    if not context.startswith(SPDX3_CONTEXT_PREFIX):
        raise UnsupportedDocumentError(
            f"Unsupported SPDX 3 context: {context!r}; "
            f"only SPDX-{SPDX3_SUPPORTED_VERSION} is supported",
            rule_id="unsupported_spdx_version",
        )

    version, _, _ = context.removeprefix("https://spdx.org/rdf/").partition("/")
    if version != SPDX3_SUPPORTED_VERSION:
        raise UnsupportedDocumentError(
            f"Unsupported SPDX version: {version!r}; "
            f"only SPDX-{SPDX3_SUPPORTED_VERSION} is supported",
            rule_id="unsupported_spdx_version",
        )

    return version


def _detect_spdx(data: dict[str, Any]) -> DetectedDocument:
    spec_version = _detect_spdx_version(data)

    from spdx_validator.engine import ValidationEngine  # noqa: PLC0415  # pylint: disable=import-outside-toplevel

    return DetectedDocument(DocumentFormat.SPDX, spec_version, ValidationEngine)


def _detect_spdx3(data: dict[str, Any]) -> DetectedDocument:
    spec_version = _detect_spdx3_version(data)

    # Keep SPDX 3 dependencies out of SPDX 2.3-only startup paths.
    from spdx3_validator.engine import (  # noqa: PLC0415  # pylint: disable=import-outside-toplevel
        ValidationEngine as SPDX3ValidationEngine,
    )

    return DetectedDocument(DocumentFormat.SPDX3, spec_version, SPDX3ValidationEngine)


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


def _is_older_cyclonedx_version(version: str) -> bool:
    """Return whether a well-formed CycloneDX version is below 1.3."""
    try:
        major, minor = (int(part) for part in version.split(".", 1))
    except (ValueError, TypeError):
        return False
    return (major, minor) < (1, 3)


__all__ = [
    "MINIMUM_CYCLONEDX_VERSION",
    "SUPPORTED_CYCLONEDX_VERSIONS",
    "DetectedDocument",
    "DocumentFormat",
    "UnsupportedDocumentError",
    "detect_document",
]
