# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
""""Tests for SBOM format and version detection."""

import pytest

from cyclone_validator.engine import CycloneDXValidationEngine
from sbom_check.detection import (
    DocumentFormat,
    UnsupportedDocumentError,
    detect_document,
)
from spdx_validator.engine import ValidationEngine


def test_detect_spdx_23() -> None:
    detected = detect_document({"spdxVersion": "SPDX-2.3"})
    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.3"
    assert detected.validator_class is ValidationEngine


@pytest.mark.parametrize("version", ["1.3", "1.4", "1.5", "1.6", "1.7"])
def test_detect_supported_cyclonedx_versions(version: str) -> None:
    detected = detect_document({"bomFormat": "CycloneDX", "specVersion": version})
    assert detected.format is DocumentFormat.CYCLONEDX
    assert detected.spec_version == version
    assert detected.validator_class is CycloneDXValidationEngine


@pytest.mark.parametrize("version", ["1.0", "1.1", "1.2"])
def test_reject_cyclonedx_versions_below_minimum(version: str) -> None:
    with pytest.raises(UnsupportedDocumentError, match="below the supported minimum"):
        detect_document({"bomFormat": "CycloneDX", "specVersion": version})


def test_reject_unknown_format() -> None:
    with pytest.raises(UnsupportedDocumentError, match="Unsupported SBOM format"):
        detect_document({"bomFormat": "UnknownSBOM", "specVersion": "1.0"})


def test_reject_missing_format_markers() -> None:
    with pytest.raises(UnsupportedDocumentError, match="does not declare"):
        detect_document({"name": "not-an-sbom"})


def test_reject_conflicting_format_markers() -> None:
    with pytest.raises(UnsupportedDocumentError, match="conflicting"):
        detect_document({
            "spdxVersion": "SPDX-2.3",
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
        })


@pytest.mark.parametrize("value", [None, [], "json", 42])
def test_reject_non_object_json(value: object) -> None:
    with pytest.raises(UnsupportedDocumentError, match="top-level object"):
        detect_document(value)


def test_reject_malformed_cyclonedx_version() -> None:
    with pytest.raises(UnsupportedDocumentError, match="must be a non-empty string"):
        detect_document({"bomFormat": "CycloneDX", "specVersion": None})


def test_detect_unsupported_spdx_version_for_validator() -> None:
    detected = detect_document({"spdxVersion": "SPDX-2.2"})

    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.2"
    assert detected.validator_class is ValidationEngine
