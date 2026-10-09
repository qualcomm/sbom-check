# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for SBOM format and version detection."""

import pytest

from sbom_check.detection import (
    DocumentFormat,
    UnsupportedDocumentError,
    detect_document,
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


def test_detect_spdx_version_dispatches_to_spdx_validator() -> None:
    detected = detect_document({"spdxVersion": "SPDX-2.2"})

    assert detected.format is DocumentFormat.SPDX
    assert detected.spec_version == "2.2"
    assert detected.validator_class is ValidationEngine
