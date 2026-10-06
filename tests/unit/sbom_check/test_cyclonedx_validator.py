# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the CycloneDX schema validator adapter."""

import pytest

from cyclone_validator import CycloneDXValidator


def test_validates_minimal_supported_documents() -> None:
    validator = CycloneDXValidator()

    for version in ("1.3", "1.4", "1.5", "1.6", "1.7"):
        result = validator.validate(
            {"bomFormat": "CycloneDX", "specVersion": version},
            version,
        )
        assert result.is_valid
        assert result.messages == []


def test_returns_all_schema_errors_with_paths_and_descriptions() -> None:
    result = CycloneDXValidator().validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "components": [{"type": "invalid", "name": 123}],
        },
        "1.7",
    )

    assert not result.is_valid
    assert len(result.messages) == 2
    assert {message.field_path for message in result.messages} == {
        "$.components[0].type",
        "$.components[0].name",
    }
    assert all(message.rule_id == "cyclonedx_schema_error" for message in result.messages)
    assert any("Component Type" in message.message for message in result.messages)
    assert any("Component Name" in message.message for message in result.messages)


def test_rejects_unknown_schema_version() -> None:
    with pytest.raises(ValueError, match="Unsupported CycloneDX schema version"):
        CycloneDXValidator().validate(
            {"bomFormat": "CycloneDX", "specVersion": "1.2"},
            "1.2",
        )


def test_validation_rejects_additional_properties() -> None:
    result = CycloneDXValidator().validate(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "additionalSupplierField": "accepted",
        },
        "1.7",
    )

    assert not result.is_valid
    assert len(result.messages) == 1
    assert result.messages[0].severity.value == "ERROR"
    assert result.messages[0].rule_id == "cyclonedx_schema_error"
    assert result.messages[0].field_path == "$"
