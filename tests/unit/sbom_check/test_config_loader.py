# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for configuration loader."""

import pytest
from pydantic import ValidationError

from sbom_check.config.loader import ConfigLoader
from sbom_check.config.models import CompletenessCheckRule, SbomCheckConfig
from sbom_check.models import ValidationSeverity


def test_config_loader_initialization():
    """Test that ConfigLoader initializes correctly."""
    loader = ConfigLoader()
    assert loader is not None
    assert len(loader.list_profiles()) >= 2  # At least basic_spdx and default


def test_list_profiles():
    """Test listing available profiles."""
    loader = ConfigLoader()
    profiles = loader.list_profiles()

    assert "basic_spdx" in profiles
    assert "default" in profiles
    assert isinstance(profiles, list)


def test_load_basic_spdx_profile():
    """Test loading the basic SPDX profile."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    assert isinstance(config, SbomCheckConfig)
    assert config.metadata.name == "Basic SPDX 2.3 Compliance"
    assert config.spdx_validation.enable_schema_validation is True
    assert config.spdx_validation.enable_semantic_validation is True


def test_load_default_profile():
    """Test loading the default profile."""
    loader = ConfigLoader()
    config = loader.load_profile("default")

    assert isinstance(config, SbomCheckConfig)
    assert config.metadata.name == "Default SBOM Requirements"
    assert config.package_requirements.build_tools.require_build_tools is True
    assert len(config.document_requirements.required_fields) > 0


def test_load_nonexistent_profile():
    """Test loading a non-existent profile raises ValueError."""
    loader = ConfigLoader()

    with pytest.raises(ValueError, match="Unknown profile"):
        loader.load_profile("nonexistent")


def test_generate_template():
    """Test generating configuration template."""
    loader = ConfigLoader()
    template = loader.generate_template("basic_spdx", include_comments=True)

    assert isinstance(template, str)
    assert "SBOM-Check Configuration Template" in template
    assert "metadata:" in template
    assert "spdx_validation:" in template


def test_generate_template_without_comments():
    """Test generating configuration template without comments."""
    loader = ConfigLoader()
    template = loader.generate_template("basic_spdx", include_comments=False)

    assert isinstance(template, str)
    assert "SBOM-Check Configuration Template" not in template
    assert "metadata:" in template


def test_save_and_load_config(tmp_path):
    """Test saving and loading configuration."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    # Save config
    config_file = tmp_path / "test_config.yaml"
    loader.save_to_file(config, config_file, "yaml")

    assert config_file.exists()

    # Load config back
    loaded_config = loader.load_from_file(config_file)

    assert loaded_config.metadata.name == config.metadata.name
    assert loaded_config.metadata.version == config.metadata.version


def test_load_from_nonexistent_file():
    """Test loading from non-existent file raises FileNotFoundError."""
    loader = ConfigLoader()

    with pytest.raises(FileNotFoundError):
        loader.load_from_file("nonexistent.yaml")


def test_validate_config_file_valid(tmp_path):
    """Test validating a valid configuration file."""
    loader = ConfigLoader()
    config = loader.load_profile("basic_spdx")

    # Save valid config
    config_file = tmp_path / "valid_config.yaml"
    loader.save_to_file(config, config_file, "yaml")

    # Validate it
    is_valid, errors = loader.validate_config_file(config_file)

    assert is_valid is True
    assert len(errors) == 0


def test_validate_config_file_invalid(tmp_path):
    """Test validating an invalid configuration file."""
    loader = ConfigLoader()

    # Create invalid config file (missing required fields)
    config_file = tmp_path / "invalid_config.yaml"
    with config_file.open("w") as f:
        f.write("metadata:\n  name: ''\n  version: ''")

    # Validate it
    is_valid, errors = loader.validate_config_file(config_file)

    assert is_valid is False
    assert len(errors) > 0
    assert "Configuration metadata.name is required" in errors[0]


def test_load_with_profile_basic():
    """Test loading with profile only."""
    loader = ConfigLoader()
    config = loader.load_with_profile("basic_spdx")

    assert config.metadata.name == "Basic SPDX 2.3 Compliance"


def test_load_with_profile_and_overrides():
    """Test loading with profile and overrides."""
    loader = ConfigLoader()

    overrides = {"spdx_validation": {"require_zero_validation_warnings": True}}

    config = loader.load_with_profile("basic_spdx", overrides=overrides)

    assert config.metadata.name == "Basic SPDX 2.3 Compliance"
    assert config.spdx_validation.require_zero_validation_warnings is True


def test_legacy_boolean_true_completeness_check_coerces_to_enabled_rule():
    """Backward-compat guarantee: legacy {'require_x': true} still loads and coerces
    to a CompletenessCheckRule with enabled is True."""
    config = SbomCheckConfig(
        metadata={"name": "n", "version": "1.0"},
        compliance_requirements={"completeness_checks": {"require_x": True}},
    )

    rule = config.compliance_requirements.completeness_checks["require_x"]

    assert isinstance(rule, CompletenessCheckRule)
    assert rule.enabled is True


def test_legacy_boolean_false_completeness_check_coerces_to_disabled_rule():
    """Backward-compat guarantee: legacy {'require_x': false} coerces to enabled is False."""
    config = SbomCheckConfig(
        metadata={"name": "n", "version": "1.0"},
        compliance_requirements={"completeness_checks": {"require_x": False}},
    )

    rule = config.compliance_requirements.completeness_checks["require_x"]

    assert isinstance(rule, CompletenessCheckRule)
    assert rule.enabled is False


def test_structured_completeness_check_shape_loads_with_all_fields_intact():
    """The new structured shape loads with severity/spdx_versions/description/
    remediation intact."""
    config = SbomCheckConfig(
        metadata={"name": "n", "version": "1.0"},
        compliance_requirements={
            "completeness_checks": {
                "require_x": {
                    "enabled": True,
                    "severity": "WARNING",
                    "spdx_versions": ["3.0.1"],
                    "description": "desc",
                    "remediation": "fix it",
                    "supported": False,
                }
            }
        },
    )

    rule = config.compliance_requirements.completeness_checks["require_x"]

    assert rule.severity is ValidationSeverity.WARNING
    assert rule.spdx_versions == ["3.0.1"]
    assert rule.description == "desc"
    assert rule.remediation == "fix it"
    assert rule.supported is False


def test_applies_to_version_true_and_false_cases():
    """applies_to_version is True only when spec_version is non-None and configured."""
    rule = CompletenessCheckRule(spdx_versions=["2.3"])

    assert rule.applies_to_version("2.3") is True
    assert rule.applies_to_version("3.0.1") is False
    assert rule.applies_to_version(None) is False


def test_invalid_severity_string_is_rejected():
    """An invalid severity string is rejected."""
    with pytest.raises(ValidationError):
        CompletenessCheckRule(severity="CRITICAL")


@pytest.mark.parametrize("format_type", ["yaml", "json"])
def test_saved_config_with_severity_can_be_reloaded(tmp_path, format_type):
    """A saved config containing a severity enum must load back.

    Regression: model_dump() without mode="json" emits ValidationSeverity
    enum objects, which yaml.dump writes as Python object tags that
    yaml.safe_load refuses to read, breaking the save/reload round-trip.
    """
    config = SbomCheckConfig.model_validate(
        {
            "metadata": {"name": "Round Trip", "version": "1.0"},
            "compliance_requirements": {
                "completeness_checks": {
                    "spdx3_completeness.package_supplier": {
                        "enabled": True,
                        "severity": "WARNING",
                        "spdx_versions": ["3.0.1"],
                        "remediation": "Add a suppliedBy reference.",
                    }
                }
            },
        }
    )
    output_path = tmp_path / f"config.{format_type}"
    loader = ConfigLoader()

    loader.save_to_file(config, output_path, format_type)
    reloaded = loader.load_from_file(output_path)

    rule = reloaded.compliance_requirements.completeness_checks[
        "spdx3_completeness.package_supplier"
    ]
    assert rule.severity is ValidationSeverity.WARNING
    assert rule.spdx_versions == ["3.0.1"]
    assert rule.remediation == "Add a suppliedBy reference."


def test_create_default_populates_all_21_spdx3_completeness_checks():
    """create_default() enables all 21 approved SPDX 3.0.1 completeness rules."""
    config = SbomCheckConfig.create_default()
    checks = config.compliance_requirements.completeness_checks

    expected_rule_ids = {
        "spdx3_completeness.document_name",
        "spdx3_completeness.document_identifier",
        "spdx3_completeness.creation_timestamp",
        "spdx3_completeness.creators",
        "spdx3_completeness.spec_version",
        "spdx3_completeness.data_license",
        "spdx3_completeness.package_name",
        "spdx3_completeness.package_identifier",
        "spdx3_completeness.package_version",
        "spdx3_completeness.package_download_location",
        "spdx3_completeness.package_supplier",
        "spdx3_completeness.license_concluded",
        "spdx3_completeness.license_declared",
        "spdx3_completeness.document_describes",
        "spdx3_completeness.package_homepage",
        "spdx3_completeness.copyright_text",
        "spdx3_completeness.package_cpe",
        "spdx3_completeness.no_isolated_elements",
        "spdx3_completeness.dependency_relationships",
        "spdx3_completeness.license_list_version",
        "spdx3_completeness.package_verification_code",
    }

    assert set(checks.keys()) == expected_rule_ids
    assert len(checks) == 21
    for rule_id, rule in checks.items():
        assert rule.enabled is True, rule_id
        assert rule.supported is True, rule_id


def test_default_spdx3_completeness_checks_do_not_apply_to_spdx_2_3():
    """Every default SPDX 3.0.1 completeness entry is scoped to 3.0.1 only,
    so SPDX 2.3 documents keep producing byte-identical results (non-regression)."""
    config = SbomCheckConfig.create_default()
    checks = config.compliance_requirements.completeness_checks

    assert len(checks) == 21
    for rule_id, rule in checks.items():
        assert rule.spdx_versions == ["3.0.1"], rule_id
        assert rule.applies_to_version("2.3") is False, rule_id
        assert rule.applies_to_version("3.0.1") is True, rule_id


def test_default_spdx3_completeness_checks_error_and_warning_sets_match_matrix():
    """Severities assigned in create_default() match the completeness matrix's
    Section 6 proposed ERROR/WARNING split exactly."""
    config = SbomCheckConfig.create_default()
    checks = config.compliance_requirements.completeness_checks

    expected_error = {
        "spdx3_completeness.document_name",
        "spdx3_completeness.document_identifier",
        "spdx3_completeness.creation_timestamp",
        "spdx3_completeness.creators",
        "spdx3_completeness.spec_version",
        "spdx3_completeness.data_license",
        "spdx3_completeness.package_name",
        "spdx3_completeness.package_identifier",
        "spdx3_completeness.package_version",
        "spdx3_completeness.package_download_location",
        "spdx3_completeness.package_supplier",
        "spdx3_completeness.license_concluded",
        "spdx3_completeness.license_declared",
        "spdx3_completeness.document_describes",
    }
    expected_warning = {
        "spdx3_completeness.package_homepage",
        "spdx3_completeness.copyright_text",
        "spdx3_completeness.package_cpe",
        "spdx3_completeness.no_isolated_elements",
        "spdx3_completeness.dependency_relationships",
        "spdx3_completeness.license_list_version",
        "spdx3_completeness.package_verification_code",
    }

    actual_error = {
        rule_id
        for rule_id, rule in checks.items()
        if rule.severity is ValidationSeverity.ERROR
    }
    actual_warning = {
        rule_id
        for rule_id, rule in checks.items()
        if rule.severity is ValidationSeverity.WARNING
    }

    assert actual_error == expected_error
    assert actual_warning == expected_warning
    assert expected_error | expected_warning == set(checks.keys())


def test_default_spdx3_completeness_checks_have_description_and_remediation():
    """Every default SPDX 3.0.1 completeness entry carries supplier-facing
    description and remediation text."""
    config = SbomCheckConfig.create_default()
    checks = config.compliance_requirements.completeness_checks

    assert len(checks) == 21
    for rule_id, rule in checks.items():
        assert rule.description, rule_id
        assert rule.description.strip(), rule_id
        assert rule.remediation, rule_id
        assert rule.remediation.strip(), rule_id


def test_create_basic_spdx_has_no_completeness_checks():
    """create_basic_spdx() stays core-specification-only: no completeness checks."""
    config = SbomCheckConfig.create_basic_spdx()

    assert config.compliance_requirements.completeness_checks == {}


@pytest.mark.parametrize("format_type", ["yaml", "json"])
def test_default_config_spdx3_completeness_checks_survive_round_trip(
    tmp_path, format_type
):
    """create_default()'s SPDX 3.0.1 completeness checks survive a save/load
    round-trip through ConfigLoader in both yaml and json."""
    loader = ConfigLoader()
    config = SbomCheckConfig.create_default()

    output_path = tmp_path / f"config.{format_type}"
    loader.save_to_file(config, output_path, format_type)
    reloaded = loader.load_from_file(output_path)

    original_checks = config.compliance_requirements.completeness_checks
    reloaded_checks = reloaded.compliance_requirements.completeness_checks

    assert set(reloaded_checks.keys()) == set(original_checks.keys())
    assert len(reloaded_checks) == 21
    for rule_id, original_rule in original_checks.items():
        reloaded_rule = reloaded_checks[rule_id]
        assert reloaded_rule.enabled == original_rule.enabled, rule_id
        assert reloaded_rule.supported == original_rule.supported, rule_id
        assert reloaded_rule.severity == original_rule.severity, rule_id
        assert reloaded_rule.spdx_versions == original_rule.spdx_versions, rule_id
        assert reloaded_rule.description == original_rule.description, rule_id
        assert reloaded_rule.remediation == original_rule.remediation, rule_id


def test_merge_with_preserves_unoverridden_default_spdx3_completeness_checks():
    """A user config overriding ONE rule's severity still leaves the other 20
    default SPDX 3.0.1 completeness checks intact after merge_with (guards the
    shallow-merge behavior of ComplianceRequirementsConfig.completeness_checks)."""
    base = SbomCheckConfig.create_default()
    override = SbomCheckConfig(
        metadata={"name": "n", "version": "1.0"},
        compliance_requirements={
            "completeness_checks": {
                "spdx3_completeness.package_homepage": {
                    "severity": "ERROR",
                }
            }
        },
    )

    merged = base.merge_with(override)
    checks = merged.compliance_requirements.completeness_checks

    # The overridden rule took the override's severity.
    assert checks["spdx3_completeness.package_homepage"].severity == (
        ValidationSeverity.ERROR
    )

    # NOTE: merge_with() merges `completeness_checks` as a whole dict value
    # (model_dump() -> plain dict -> recursive dict merge), and
    # merge_dicts() only recurses into keys present in BOTH base and
    # override dicts. Since override's completeness_checks dict contains
    # only "spdx3_completeness.package_homepage", that single key is
    # replaced wholesale, and the override dict otherwise does not
    # contain any of the other 20 rule_id keys to collide with -- so the
    # other 20 keys from base pass through unchanged. This test asserts
    # that ACTUAL (correct, as it happens) behavior.
    base_checks = base.compliance_requirements.completeness_checks
    for rule_id, base_rule in base_checks.items():
        if rule_id == "spdx3_completeness.package_homepage":
            continue
        merged_rule = checks[rule_id]
        assert merged_rule.enabled == base_rule.enabled, rule_id
        assert merged_rule.supported == base_rule.supported, rule_id
        assert merged_rule.severity == base_rule.severity, rule_id
        assert merged_rule.spdx_versions == base_rule.spdx_versions, rule_id
        assert merged_rule.description == base_rule.description, rule_id
        assert merged_rule.remediation == base_rule.remediation, rule_id

    assert len(checks) == 21


def test_saved_config_contains_no_python_object_tags(tmp_path):
    """Serialized YAML must be plain data, loadable by any YAML parser."""
    config = SbomCheckConfig.model_validate(
        {
            "metadata": {"name": "Plain", "version": "1.0"},
            "compliance_requirements": {
                "completeness_checks": {"check": {"severity": "INFO"}}
            },
        }
    )
    output_path = tmp_path / "config.yaml"

    ConfigLoader().save_to_file(config, output_path)

    assert "python/object" not in output_path.read_text(encoding="utf-8")


def test_validate_config_file_rejects_unknown_completeness_rule(tmp_path):
    """A mistyped SPDX 3.0.1 rule ID must be reported, not accepted."""
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "metadata:\n"
        "  name: Typo\n"
        "  version: '1.0'\n"
        "compliance_requirements:\n"
        "  completeness_checks:\n"
        "    spdx3_completeness.package_supplierr:\n"
        "      enabled: false\n",
        encoding="utf-8",
    )

    is_valid, errors = ConfigLoader().validate_config_file(config_path)

    assert is_valid is False
    assert any("package_supplierr" in error for error in errors)


def test_validate_config_file_accepts_legacy_completeness_keys(tmp_path):
    """Legacy boolean keys must not be reported as unknown rules."""
    config_path = tmp_path / "legacy.yaml"
    config_path.write_text(
        "metadata:\n"
        "  name: Legacy\n"
        "  version: '1.0'\n"
        "compliance_requirements:\n"
        "  completeness_checks:\n"
        "    require_package_identifier: true\n",
        encoding="utf-8",
    )

    is_valid, errors = ConfigLoader().validate_config_file(config_path)

    assert is_valid is True
    assert errors == []
