# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Qualcomm CycloneDX completeness profile and semantic integrity checks."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cyclone_validator import SemanticValidator
from sbom_check.config.loader import ConfigLoader
from sbom_check.config.models import (
    CYCLONEDX_CHECKS,
    CycloneDXRequirementsConfig,
    SbomCheckConfig,
)
from sbom_check.engine import SbomCheckEngine
from sbom_check.models import ProfileStatus, ValidationSeverity

FIXTURES = Path(__file__).parents[2] / "fixtures" / "cyclonedx"


def _complete() -> dict[str, Any]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000001",
        "version": 1,
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "tools": {"components": [{"type": "application", "name": "gen"}]},
            "component": {
                "type": "application",
                "bom-ref": "app",
                "name": "app",
                "version": "1.0",
            },
        },
        "components": [
            {
                "type": "library",
                "bom-ref": "pkg:pypi/requests@2.32.0",
                "name": "requests",
                "version": "2.32.0",
                "supplier": {"name": "Python Software Foundation"},
                "purl": "pkg:pypi/requests@2.32.0",
            }
        ],
        "dependencies": [{"ref": "app", "dependsOn": ["pkg:pypi/requests@2.32.0"]}],
    }


def _rules(result: Any) -> list[str]:
    return [message.rule_id for message in result.messages]


def _validate(document: dict[str, Any], **kwargs: Any) -> Any:
    return SbomCheckEngine(**kwargs).validate_dict(document)


def test_complete_document_passes_profile() -> None:
    result = _validate(_complete())

    assert result.messages == []
    assert result.overall_valid
    assert result.profile_status is ProfileStatus.PASSED
    assert result.profile_name == "Default SBOM Requirements"


def test_document_with_no_components_fails_with_specific_message() -> None:
    document = _complete()
    del document["components"]
    document["dependencies"] = []

    result = _validate(document)

    assert result.core_valid
    assert not result.overall_valid
    assert result.profile_status is ProfileStatus.FAILED
    assert _rules(result) == ["cyclonedx_completeness.no_components"]
    assert "no components" in result.messages[0].message
    assert "metadata alone" in result.messages[0].message


@pytest.mark.parametrize(
    "dependencies", [None, [], [{"ref": "app"}], [{"ref": "app", "dependsOn": []}]]
)
def test_components_without_dependency_graph_fail(dependencies: Any) -> None:
    document = _complete()
    if dependencies is None:
        del document["dependencies"]
    else:
        document["dependencies"] = dependencies

    result = _validate(document)

    assert _rules(result) == ["cyclonedx_completeness.missing_dependency_graph"]
    assert "depend" in result.messages[0].message


def test_duplicate_bom_refs_report_every_location() -> None:
    document = _complete()
    duplicate = deepcopy(document["components"][0])
    document["components"].append(duplicate)
    document["components"][0]["components"] = [deepcopy(duplicate)]

    result = SemanticValidator().validate(document, "1.6")

    assert not result.is_valid
    assert [message.rule_id for message in result.messages] == [
        "cyclonedx_semantic.duplicate_bom_ref"
    ]
    message = result.messages[0].message
    assert "pkg:pypi/requests@2.32.0" in message
    assert "$.components[0]" in message
    assert "$.components[0].components[0]" in message
    assert "$.components[1]" in message


def test_duplicate_between_component_and_metadata_component() -> None:
    document = _complete()
    document["components"][0]["bom-ref"] = "app"
    document["dependencies"] = [{"ref": "app", "dependsOn": ["app"]}]

    result = SemanticValidator().validate(document, "1.6")

    assert [message.rule_id for message in result.messages] == [
        "cyclonedx_semantic.duplicate_bom_ref"
    ]


def test_dangling_ref_and_depends_on_are_reported() -> None:
    document = _complete()
    document["dependencies"] = [
        {"ref": "ghost", "dependsOn": ["pkg:pypi/requests@2.32.0"]},
        {"ref": "app", "dependsOn": ["missing-a", "pkg:pypi/requests@2.32.0"]},
    ]

    result = SemanticValidator().validate(document, "1.6")

    assert not result.is_valid
    assert {(m.found_value, m.field_path) for m in result.messages} == {
        ("ghost", "$.dependencies[0].ref"),
        ("missing-a", "$.dependencies[1].dependsOn[0]"),
    }
    assert all(
        m.rule_id == "cyclonedx_semantic.dangling_dependency_ref"
        for m in result.messages
    )


def test_dependency_on_service_and_nested_component_resolves() -> None:
    document = _complete()
    document["services"] = [{"bom-ref": "svc", "name": "api"}]
    document["components"][0]["components"] = [
        {"type": "file", "bom-ref": "nested", "name": "x"}
    ]
    document["dependencies"].append({"ref": "svc", "dependsOn": ["nested"]})

    assert SemanticValidator().validate(document, "1.6").is_valid


def test_semantic_failures_are_hard_errors_even_with_relaxed_profile() -> None:
    document = _complete()
    document["dependencies"][0]["dependsOn"].append("ghost")
    config = SbomCheckConfig.create_qualcomm_cyclonedx()
    config.cyclonedx_requirements = CycloneDXRequirementsConfig(
        severities=dict.fromkeys(CYCLONEDX_CHECKS, "OFF")
    )

    result = _validate(document, config=config)

    assert not result.core_valid
    assert not result.overall_valid
    assert result.messages[0].severity is ValidationSeverity.ERROR
    assert result.messages[0].found_value == "ghost"
    assert "bom-ref" in (result.messages[0].remediation or "")


@pytest.mark.parametrize(
    ("purl", "reason"),
    [
        ("pkg:maven/commons-lang3@3.14", "Namespace is required"),
        ("not-a-purl", "scheme"),
        ("pkg:notarealtype/x@1", "type"),
    ],
)
def test_invalid_purl_is_warning_with_vulnerability_explanation(
    purl: str, reason: str
) -> None:
    document = _complete()
    document["components"][0]["purl"] = purl

    result = _validate(document)

    assert _rules(result) == ["cyclonedx_completeness.invalid_purl"]
    message = result.messages[0]
    assert message.severity is ValidationSeverity.WARNING
    assert reason in message.message
    assert "silently missed" in message.message
    assert result.overall_valid


def test_missing_component_fields_name_the_component() -> None:
    document = _complete()
    component = document["components"][0]
    del component["supplier"]
    del component["purl"]

    result = _validate(document)

    assert sorted(m.field_path for m in result.messages) == [
        "$.components[0].purl",
        "$.components[0].supplier.name",
    ]
    assert all("'requests@2.32.0'" in m.message for m in result.messages)
    assert all(m.remediation for m in result.messages)


def test_nested_components_are_checked() -> None:
    document = _complete()
    document["components"][0]["components"] = [
        {"type": "file", "bom-ref": "nested", "name": "x"}
    ]
    document["dependencies"].append({"ref": "nested", "dependsOn": []})

    paths = {m.field_path for m in _validate(document).messages}

    assert "$.components[0].components[0].version" in paths


@pytest.mark.parametrize(
    "field", ["serialNumber", "version", "metadata.timestamp", "metadata.tools"]
)
def test_missing_document_fields(field: str) -> None:
    document = _complete()
    parent, _, leaf = field.rpartition(".")
    (document[parent] if parent else document).pop(leaf)

    result = _validate(document)

    assert _rules(result) == ["cyclonedx_completeness.missing_document_field"]
    assert result.messages[0].field_path == f"$.{field}"


@pytest.mark.parametrize("tools", [[], {}, {"components": [], "services": []}])
def test_empty_tools_count_as_missing(tools: Any) -> None:
    document = _complete()
    document["metadata"]["tools"] = tools

    assert _rules(_validate(document)) == [
        "cyclonedx_completeness.missing_document_field"
    ]


def test_legacy_tools_array_is_accepted() -> None:
    document = _complete()
    document["specVersion"] = "1.4"
    document["metadata"]["tools"] = [{"vendor": "x", "name": "gen", "version": "1"}]

    assert _validate(document).messages == []


def test_minimum_version_is_read_from_profile() -> None:
    document = _complete()
    document["specVersion"] = "1.4"
    document["metadata"]["tools"] = [{"name": "gen"}]
    config = SbomCheckConfig.create_qualcomm_cyclonedx()
    config.cyclonedx_requirements = CycloneDXRequirementsConfig(
        minimum_spec_version="1.5"
    )

    result = _validate(document, config=config)

    assert _rules(result) == ["cyclonedx_completeness.below_minimum_spec_version"]
    assert result.messages[0].severity is ValidationSeverity.ERROR
    assert not result.overall_valid


def test_lower_floor_with_warning_accepts_cyclonedx_1_2() -> None:
    document = _complete()
    document["specVersion"] = "1.2"
    document["metadata"]["tools"] = [{"name": "gen"}]
    config = SbomCheckConfig.create_qualcomm_cyclonedx()
    config.cyclonedx_requirements = CycloneDXRequirementsConfig(
        minimum_spec_version="1.3",
        severities={"below_minimum_spec_version": "WARNING"},
    )

    result = _validate(document, config=config)

    assert result.core_valid, result.messages
    assert _rules(result) == ["cyclonedx_completeness.below_minimum_spec_version"]
    assert result.messages[0].severity is ValidationSeverity.WARNING
    assert result.overall_valid


def test_profile_without_cyclonedx_section_keeps_hard_1_3_floor() -> None:
    document = _complete()
    document["specVersion"] = "1.2"

    result = _validate(document, profile_name="basic_spdx")

    assert result.messages[0].rule_id == "unsupported_version"
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE


def test_profile_without_cyclonedx_section_is_not_applicable() -> None:
    document = _complete()
    del document["components"]
    del document["dependencies"]

    result = _validate(document, profile_name="basic_spdx")

    assert result.overall_valid
    assert result.profile_status is ProfileStatus.NOT_APPLICABLE


def test_severity_override_can_disable_or_escalate_checks() -> None:
    document = _complete()
    document["components"][0]["purl"] = "not-a-purl"
    del document["components"][0]["supplier"]
    config = SbomCheckConfig.create_qualcomm_cyclonedx()
    config.cyclonedx_requirements = CycloneDXRequirementsConfig(
        severities={"invalid_purl": "ERROR", "missing_component_field": "OFF"}
    )

    result = _validate(document, config=config)

    assert _rules(result) == ["cyclonedx_completeness.invalid_purl"]
    assert result.messages[0].severity is ValidationSeverity.ERROR


def test_unknown_severity_key_is_rejected() -> None:
    with pytest.raises(ValidationError, match="Unknown CycloneDX check"):
        CycloneDXRequirementsConfig(severities={"invalid_prul": "ERROR"})


def test_malformed_minimum_version_is_rejected() -> None:
    with pytest.raises(ValidationError, match="minimum_spec_version"):
        CycloneDXRequirementsConfig(minimum_spec_version="v1.3")


def test_qualcomm_cyclonedx_profile_is_selectable() -> None:
    loader = ConfigLoader()

    assert "qualcomm_cyclonedx" in loader.list_profiles()
    config = loader.load_profile("qualcomm_cyclonedx")
    assert config.cyclonedx_requirements is not None
    # SPDX side of this profile stays at basic validation.
    assert config.package_requirements.required_fields == []


def test_vendor_override_file_changes_only_what_it_lists(tmp_path: Path) -> None:
    override = tmp_path / "vendor.yaml"
    override.write_text(
        "metadata: {name: Vendor X, version: '1'}\n"
        "cyclonedx_requirements:\n"
        "  component_required_fields: [name, version, purl, bom-ref, type]\n"
        "  severities: {invalid_purl: ERROR}\n"
    )

    config = ConfigLoader().load_with_profile("default", override)

    cdx = config.cyclonedx_requirements
    assert cdx is not None
    assert "supplier.name" not in cdx.component_required_fields
    assert cdx.severity("invalid_purl") == "ERROR"
    assert cdx.severity("no_components") == "ERROR"
    assert cdx.minimum_spec_version == "1.3"
    # A partial override must not wipe the SPDX defaults it did not mention.
    assert "supplier" in config.package_requirements.required_fields
    assert "spdxVersion" in config.document_requirements.required_fields


def test_override_can_turn_cyclonedx_profile_off(tmp_path: Path) -> None:
    override = tmp_path / "off.yaml"
    override.write_text(
        "metadata: {name: Disabled, version: '1'}\ncyclonedx_requirements: null\n"
    )

    config = ConfigLoader().load_with_profile("default", override)

    assert config.cyclonedx_requirements is None


def test_representative_scancode_document_gets_actionable_messages() -> None:
    document = json.loads((FIXTURES / "representative-scancode-1.3.json").read_text())

    result = _validate(document)

    assert result.core_valid
    assert not result.overall_valid
    assert {m.field_path for m in result.messages} == {
        "$.components[0].supplier.name",
        "$.components[1].supplier.name",
    }
    assert all("supplier" in (m.remediation or "") for m in result.messages)


def test_scancode_metadata_only_document_fails_on_missing_content() -> None:
    document = json.loads((FIXTURES / "representative-scancode-1.3.json").read_text())
    del document["components"]
    del document["dependencies"]

    result = _validate(document)

    assert _rules(result) == ["cyclonedx_completeness.no_components"]


def test_severity_overrides_merge_per_check_across_layers(tmp_path: Path) -> None:
    first = tmp_path / "first.yaml"
    first.write_text(
        "metadata: {name: First, version: '1'}\n"
        "cyclonedx_requirements: {severities: {invalid_purl: ERROR}}\n"
    )
    config = ConfigLoader().load_with_profile(
        "default",
        first,
        overrides={
            "cyclonedx_requirements": {"severities": {"no_components": "WARNING"}}
        },
    )

    cdx = config.cyclonedx_requirements
    assert cdx is not None
    assert cdx.severity("invalid_purl") == "ERROR"
    assert cdx.severity("no_components") == "WARNING"
    assert cdx.severity("missing_dependency_graph") == "ERROR"
