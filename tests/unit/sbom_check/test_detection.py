# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for SBOM format and version detection."""

import pytest

from sbom_check.detection import (
    DocumentFormat,
    UnsupportedDocumentError,
    detect_document,
    get_document_version,
)
from spdx3_validator.engine import ValidationEngine as SPDX3ValidationEngine
from spdx_validator.engine import ValidationEngine


def test_detect_spdx_23() -> None:
    detected = detect_document({"spdxVersion": "SPDX-2.3"})
    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.3"
    assert detected.validator_class is ValidationEngine


def test_detect_spdx_3_0_1():
    detected = detect_document(
        {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"}
    )

    assert detected.format is DocumentFormat.SPDX3
    assert detected.spec_version == "3.0.1"
    assert detected.validator_class is SPDX3ValidationEngine


@pytest.mark.parametrize(
    "context",
    [
        ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld"],
        [
            "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            {"ex": "https://example.com/"},
        ],
    ],
)
def test_reject_spdx3_array_context_with_accurate_error(context: list[object]) -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        detect_document({"@context": context})

    assert error_info.value.rule_id == "unsupported_spdx3_context_form"
    assert "array-valued @context" in str(error_info.value)


def test_detect_spdx3_single_object_with_shared_properties() -> None:
    detected = detect_document(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "type": "SpdxDocument",
            "spdxId": "https://example.com/doc",
            "creationInfo": "_:ci",
            "dataLicense": "https://example.com/license",
        }
    )

    assert detected.format is DocumentFormat.SPDX3
    assert detected.spec_version == "3.0.1"
    assert detected.validator_class is SPDX3ValidationEngine


def test_reject_conflicting_spdx2_and_spdx3_markers() -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        detect_document(
            {
                "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
            }
        )

    assert error_info.value.rule_id == "conflicting_format_markers"
    assert "Conflicting SPDX 2 and SPDX 3 format markers" in str(error_info.value)


@pytest.mark.parametrize(
    "context",
    [
        "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "https://spdx.org/rdf/3.9.9/spdx-context.jsonld",
    ],
)
def test_reject_unsupported_spdx3_version(context: str) -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        detect_document({"@context": context})

    assert error_info.value.rule_id == "unsupported_spdx_version"
    assert "only SPDX-3.0.1 is supported" in str(error_info.value)


@pytest.mark.parametrize(
    ("document", "rule_id"),
    [
        ({}, "spdx3_missing_context"),
        ({"@context": {"spdx": "3.0.1"}}, "unsupported_spdx3_context_form"),
        (
            {"@context": "https://spdx.org/rdf/4.0.0/spdx-context.jsonld"},
            "unsupported_spdx_version",
        ),
    ],
)
def test_reject_invalid_spdx3_context(
    document: dict[str, object], rule_id: str
) -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        get_document_version(DocumentFormat.SPDX3, document)

    assert error_info.value.rule_id == rule_id


def test_reject_spdx3_graph_without_context():
    with pytest.raises(UnsupportedDocumentError, match="does not declare"):
        detect_document({"@graph": []})


def test_reject_missing_format_markers() -> None:
    with pytest.raises(UnsupportedDocumentError, match="does not declare"):
        detect_document({"name": "not-an-sbom"})


@pytest.mark.parametrize("value", [None, [], "json", 42])
def test_reject_non_object_json(value: object) -> None:
    with pytest.raises(UnsupportedDocumentError, match="top-level object"):
        detect_document(value)


@pytest.mark.parametrize(
    "document",
    [
        {"spdxVersion": "SPDX-2.2"},
        {"spdxVersion": "SPDX-9.9"},
        {"spdxVersion": "2.3"},
        {"spdxVersion": None},
    ],
)
def test_reject_unsupported_spdx_version(document: dict[str, object]) -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        detect_document(document)

    assert error_info.value.rule_id == "unsupported_spdx_version"
    assert "only SPDX-2.3 is supported" in str(error_info.value)


def test_reject_missing_spdx_version() -> None:
    with pytest.raises(UnsupportedDocumentError) as error_info:
        detect_document({"SPDXID": "SPDXRef-DOCUMENT"})

    assert error_info.value.rule_id == "missing_spdx_version"
    assert "missing the required spdxVersion field" in str(error_info.value)
