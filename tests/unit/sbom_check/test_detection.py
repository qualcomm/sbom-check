# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for SBOM format and version detection."""

import pytest

from cyclone_validator.engine import CycloneDXValidationEngine
from sbom_check.detection import (
    DocumentFormat,
    UnsupportedDocumentError,
    _detect_spdx3_version,
    detect_document,
)
from spdx_validator.engine import ValidationEngine

SPDX3_CONTEXT = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"


def test_detect_spdx_23() -> None:
    detected = detect_document({"spdxVersion": "SPDX-2.3"})
    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.3"
    assert detected.validator_class is ValidationEngine


def test_spdx_document_with_spec_version_extension_is_detected_as_spdx() -> None:
    detected = detect_document(
        {"spdxVersion": "SPDX-2.3", "specVersion": "extension-version"}
    )

    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.3"


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
        detect_document(
            {
                "spdxVersion": "SPDX-2.3",
                "bomFormat": "CycloneDX",
                "specVersion": "1.7",
            }
        )


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


def test_detect_spdx3_json_ld_document() -> None:
    detected = detect_document(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@graph": [{"type": "SpdxDocument"}],
        }
    )

    assert detected.format is DocumentFormat.SPDX3
    assert detected.spec_version == "3.0.1"


def test_spdx3_document_with_only_creation_info_is_not_misdetected_as_spdx2() -> None:
    detected = detect_document(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "creationInfo": {"created": "2026-01-01T00:00:00Z"},
        }
    )

    assert detected.format is DocumentFormat.SPDX3
    assert detected.spec_version == "3.0.1"


def test_spdx3_document_with_only_data_license_is_not_misdetected_as_spdx2() -> None:
    detected = detect_document(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "dataLicense": "CC0-1.0",
        }
    )

    assert detected.format is DocumentFormat.SPDX3
    assert detected.spec_version == "3.0.1"


def test_detect_spdx_23_still_detects_as_spdx2_regression() -> None:
    detected = detect_document(
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "spdxVersion": "SPDX-2.3",
            "creationInfo": {"created": "2026-01-01T00:00:00Z"},
            "dataLicense": "CC0-1.0",
        }
    )

    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.3"


def test_detect_cyclonedx_still_works_regression() -> None:
    detected = detect_document({"bomFormat": "CycloneDX", "specVersion": "1.6"})

    assert detected.format is DocumentFormat.CYCLONEDX
    assert detected.spec_version == "1.6"


def test_reject_conflicting_spdx2_and_spdx3_markers() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        detect_document(
            {
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "spdxVersion": "SPDX-2.3",
            }
        )

    assert exc_info.value.rule_id == "conflicting_format_markers"


def test_reject_array_valued_spdx3_context() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        detect_document(
            {"@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"]}
        )

    assert exc_info.value.rule_id == "unsupported_spdx3_context_form"


def test_reject_dict_valued_spdx3_context() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        detect_document(
            {
                "@context": {"foo": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"},
                "@graph": [],
            }
        )

    # A dict-valued @context has no SPDX 3 marker and no SPDX 2 marker, so
    # it falls through to the generic unsupported-format error.
    assert exc_info.value.rule_id == "unsupported_format"


def test_reject_unsupported_spdx3_version() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        detect_document({"@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"})

    assert exc_info.value.rule_id == "unsupported_spdx_version"


def test_reject_non_spdx_context_string_with_no_other_markers() -> None:
    with pytest.raises(UnsupportedDocumentError, match="does not declare"):
        detect_document({"@context": "https://example.com/ctx.jsonld"})


def test_unavailable_spdx3_core_validator_reports_that_it_did_not_run() -> None:
    """The placeholder must not report an unchecked document as valid.

    Returning is_valid=True would let an SPDX 3 document pass as SPDX
    3.0.1-conformant when no core validation ran at all.
    """
    from sbom_check.detection import (  # noqa: PLC0415
        SPDX3_CORE_VALIDATION_UNAVAILABLE_RULE_ID,
        _UnavailableSpdx3CoreValidator,  # pylint: disable=import-outside-toplevel
    )

    validator = _UnavailableSpdx3CoreValidator()
    result = validator.validate_dict({})

    assert result.is_valid is False
    assert len(result.messages) == 1
    assert result.messages[0].rule_id == SPDX3_CORE_VALIDATION_UNAVAILABLE_RULE_ID
    assert result.messages[0].remediation


def test_reject_conflicting_spdx3_and_cyclonedx_markers() -> None:
    """An SPDX 3 context alongside a CycloneDX marker is a conflict.

    SPDX 2 markers already conflict with CycloneDX; SPDX 3 must behave the
    same way rather than silently being detected as CycloneDX.
    """
    with pytest.raises(UnsupportedDocumentError, match="conflicting SPDX and"):
        detect_document(
            {
                "@context": SPDX3_CONTEXT,
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
            }
        )


def test_spdx3_version_helper_rejects_missing_context() -> None:
    """The version helper guards callers that bypass marker detection."""
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        _detect_spdx3_version({})

    assert exc_info.value.rule_id == "spdx3_missing_context"


def test_spdx3_version_helper_rejects_non_string_context() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        _detect_spdx3_version({"@context": 5})

    assert exc_info.value.rule_id == "unsupported_spdx3_context_form"


def test_spdx3_version_helper_rejects_array_context() -> None:
    with pytest.raises(UnsupportedDocumentError) as exc_info:
        _detect_spdx3_version({"@context": [SPDX3_CONTEXT]})

    assert exc_info.value.rule_id == "unsupported_spdx3_context_form"
