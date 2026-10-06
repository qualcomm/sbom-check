# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format and specification-version detection for SBOM JSON documents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cyclone_validator.engine import CycloneDXValidationEngine
from sbom_check.models import DocumentFormat
from spdx_validator.engine import ValidationEngine

if TYPE_CHECKING:
    from sbom_validator.engine import ValidatorEngine


SUPPORTED_CYCLONEDX_VERSIONS = frozenset({"1.3", "1.4", "1.5", "1.6", "1.7"})
MINIMUM_CYCLONEDX_VERSION = "1.3"


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

    has_spdx_marker = any(
        marker in data
        for marker in (
            "SPDXID",
            "documentNamespace",
            "creationInfo",
            "dataLicense",
            "spdxVersion",
        )
    )
    has_cyclonedx_marker = "bomFormat" in data or "specVersion" in data

    if has_spdx_marker and has_cyclonedx_marker:
        raise UnsupportedDocumentError(
            "Unsupported input: document contains conflicting SPDX and "
            "CycloneDX format markers",
            rule_id="unsupported_format",
        )

    if has_cyclonedx_marker:
        return _detect_cyclonedx(data)

    if has_spdx_marker:
        return _detect_spdx(data)

    raise UnsupportedDocumentError(
        "Unsupported input: document does not declare SPDX or CycloneDX format",
        rule_id="unsupported_format",
    )


def _detect_spdx(data: dict[str, Any]) -> DetectedDocument:
    version = data.get("spdxVersion")
    spec_version = (
        version.removeprefix("SPDX-")
        if isinstance(version, str) and version
        else None
    )
    return DetectedDocument(DocumentFormat.SPDX, spec_version, ValidationEngine)


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

    return DetectedDocument(DocumentFormat.CYCLONEDX, version, CycloneDXValidationEngine)


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
