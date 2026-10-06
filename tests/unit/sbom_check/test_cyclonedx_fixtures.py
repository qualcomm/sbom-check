# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Regression tests for the CycloneDX fixture corpus."""

import json
from pathlib import Path

import pytest
from cyclonedx.schema import SchemaVersion

from cyclone_validator import CycloneDXValidationEngine, JsonSchemaValidator
from cyclone_validator import validators as cyclone_validators

FIXTURES = Path(__file__).parents[2] / "fixtures" / "cyclonedx"
EXPECTED_SCHEMA_VERSIONS = {
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}
VERSION_SPECIFIC_BOUNDARIES = (("1.5", "1.4"), ("1.6", "1.5"), ("1.7", "1.6"))
EXPECTED_VALID_SCHEMA_RESULTS = {
    "1.3": (True, True, True, True, True),
    "1.4": (True, True, True, True, True),
    "1.5": (True, False, True, True, True),
    "1.6": (True, False, False, True, True),
    "1.7": (True, False, False, False, True),
}
EXPECTED_INVALID_SCHEMA_RESULTS = {
    "1.3": (False, False, False, False, False),
    "1.4": (False, False, False, False, False),
    "1.5": (False, False, False, False, False),
    "1.6": (False, False, False, False, False),
    "1.7": (True, False, False, False, False),
}
VERSIONS = ("1.3", "1.4", "1.5", "1.6", "1.7")
SCHEMA_PAIRS = tuple((fixture, schema) for fixture in VERSIONS for schema in VERSIONS)
EXPECTED_INVALID_PATHS = {
    "1.3": {"$.components[0].type"},
    "1.4": {"$.components[0]"},
    "1.5": {"$.components[1].purl"},
    "1.6": {"$.components[0].version"},
    "1.7": {"$.citations[0].timestamp"},
}


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("version", VERSIONS)
def test_valid_fixture_passes_declared_schema(version: str) -> None:
    """Each supported version is validated against its declared schema."""
    document = _load_fixture(f"valid-{version}.json")

    result = JsonSchemaValidator().validate(document, version)

    assert result.is_valid
    assert result.messages == []


@pytest.mark.parametrize("version", VERSIONS)
def test_invalid_fixture_reports_all_schema_failures(version: str) -> None:
    """Each invalid fixture reports both component defects with paths."""
    document = _load_fixture(f"invalid-{version}.json")

    result = CycloneDXValidationEngine().validate_dict(document)

    assert not result.is_valid
    assert {message.field_path for message in result.messages} >= EXPECTED_INVALID_PATHS[version]
    assert all(message.rule_id == "cyclonedx_schema_error" for message in result.messages if message.rule_id != "semantic_validation_skipped")


@pytest.mark.parametrize(("fixture_version", "schema_version"), SCHEMA_PAIRS)
def test_valid_fixture_schema_compatibility_matrix(
    fixture_version: str, schema_version: str
) -> None:
    """Check every valid fixture against every supported schema."""
    document = _load_fixture(f"valid-{fixture_version}.json")
    result = JsonSchemaValidator().validate(document, schema_version)
    expected = EXPECTED_VALID_SCHEMA_RESULTS[fixture_version][
        VERSIONS.index(schema_version)
    ]

    assert result.is_valid is expected


@pytest.mark.parametrize(("fixture_version", "schema_version"), SCHEMA_PAIRS)
def test_invalid_fixture_schema_compatibility_matrix(
    fixture_version: str, schema_version: str
) -> None:
    """Check every invalid fixture against every supported schema."""
    document = _load_fixture(f"invalid-{fixture_version}.json")
    result = JsonSchemaValidator().validate(document, schema_version)
    expected = EXPECTED_INVALID_SCHEMA_RESULTS[fixture_version][
        VERSIONS.index(schema_version)
    ]

    assert result.is_valid is expected


@pytest.mark.parametrize("version", VERSIONS)
def test_engine_uses_declared_schema_for_each_version(
    monkeypatch: pytest.MonkeyPatch, version: str
) -> None:
    """The engine selects the schema matching every supported version."""
    document = _load_fixture(f"valid-{version}.json")
    selected_versions = []
    original_factory = cyclone_validators.make_schemabased_validator

    def spy_factory(output_format, schema_version):
        selected_versions.append(schema_version)
        return original_factory(output_format, schema_version)

    monkeypatch.setattr(
        cyclone_validators, "make_schemabased_validator", spy_factory
    )

    result = CycloneDXValidationEngine().validate_dict(document)

    assert result.is_valid
    assert selected_versions == [EXPECTED_SCHEMA_VERSIONS[version]]


@pytest.mark.parametrize(("version", "older_version"), VERSION_SPECIFIC_BOUNDARIES)
def test_version_specific_fixture_rejects_previous_schema(
    version: str, older_version: str
) -> None:
    """Version-specific fixture features are rejected by the prior schema."""
    document = _load_fixture(f"valid-{version}.json")
    validator = JsonSchemaValidator()

    assert validator.validate(document, version).is_valid
    assert not validator.validate(document, older_version).is_valid


def test_representative_scancode_fixture_passes() -> None:
    """The representative ScanCode-shaped document remains schema-valid."""
    document = _load_fixture("representative-scancode-1.3.json")

    result = CycloneDXValidationEngine().validate_dict(document)

    assert result.is_valid
    assert result.messages == []
