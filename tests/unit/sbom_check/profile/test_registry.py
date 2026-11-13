# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the completeness rule registry."""

from __future__ import annotations

import re

import pytest

from sbom_check.config.models import (
    CompletenessCheckRule,
    ComplianceRequirementsConfig,
    SbomCheckConfig,
)
from sbom_check.models import (
    DocumentFormat,
    RuleOutcome,
    ValidationMessage,
    ValidationSeverity,
)
from sbom_check.profile.registry import ProfileRule, ProfileRuleRegistry, RuleContext


class PassingRule:
    """A fake rule that always passes."""

    rule_id = "fake.passing"
    description = "Always passes"
    spdx_versions = ("2.3", "3.0.1")

    def __init__(self) -> None:
        self.evaluated = False

    def evaluate(self, document, context):
        self.evaluated = True
        return []


class FailingRule:
    """A fake rule that always fails with one ERROR message."""

    rule_id = "fake.failing"
    description = "Always fails"
    spdx_versions = ("2.3", "3.0.1")

    def __init__(self) -> None:
        self.evaluated = False

    def evaluate(self, document, context):
        self.evaluated = True
        return [
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message="something is missing",
                rule_id=self.rule_id,
            )
        ]


class RaisingRule:
    """A fake rule that raises during evaluation."""

    rule_id = "fake.raising"
    description = "Always raises"
    spdx_versions = ("2.3", "3.0.1")

    def __init__(self) -> None:
        self.evaluated = False

    def evaluate(self, document, context):
        self.evaluated = True
        raise RuntimeError("boom")


class LegacyVersionRule:
    """A fake rule whose implementation only covers SPDX 2.3."""

    rule_id = "fake.legacy_version_only"
    description = "Only implemented for 2.3"
    spdx_versions = ("2.3",)

    def __init__(self) -> None:
        self.evaluated = False

    def evaluate(self, document, context):
        self.evaluated = True
        return []


def _config_with(**completeness_checks: CompletenessCheckRule) -> SbomCheckConfig:
    config = SbomCheckConfig.create_basic_spdx()
    config.compliance_requirements = ComplianceRequirementsConfig(
        completeness_checks=completeness_checks
    )
    return config


def _context(spec_version: str, config: SbomCheckConfig) -> RuleContext:
    return RuleContext(
        spec_version=spec_version, document_format=DocumentFormat.SPDX, config=config
    )


def test_protocol_runtime_checkable():
    """A conforming fake rule satisfies the ProfileRule protocol."""
    assert isinstance(PassingRule(), ProfileRule)


def test_register_get_and_rules_preserve_insertion_order():
    """register/get/rules() work and preserve registration order."""
    registry = ProfileRuleRegistry()
    rule_a = PassingRule()
    rule_b = FailingRule()
    registry.register(rule_a)
    registry.register(rule_b)

    assert registry.get("fake.passing") is rule_a
    assert registry.get("fake.failing") is rule_b
    assert registry.get("does.not.exist") is None
    assert registry.rules() == [rule_a, rule_b]


def test_register_duplicate_rule_id_raises_value_error_naming_id():
    """Registering a duplicate rule_id raises ValueError naming the id."""
    registry = ProfileRuleRegistry()
    registry.register(PassingRule())

    with pytest.raises(ValueError, match=re.escape("fake.passing")):
        registry.register(PassingRule())


def test_passing_rule_yields_passed_coverage_and_no_messages():
    """A passing rule yields PASSED coverage and emits no messages."""
    registry = ProfileRuleRegistry()
    registry.register(PassingRule())
    config = _config_with()

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert messages == []
    assert len(coverage) == 1
    assert coverage[0].outcome is RuleOutcome.PASSED
    assert coverage[0].blocks_completeness is False


def test_failing_rule_yields_failed_coverage_and_its_message():
    """A failing rule yields FAILED coverage and its message."""
    registry = ProfileRuleRegistry()
    registry.register(FailingRule())
    config = _config_with()

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert len(messages) == 1
    assert messages[0].message == "something is missing"
    assert coverage[0].outcome is RuleOutcome.FAILED
    assert coverage[0].blocks_completeness is False


def test_disabled_rule_is_skipped_and_never_evaluated_and_does_not_block():
    """enabled: false yields SKIPPED, the rule never runs, and it does not block."""
    registry = ProfileRuleRegistry()
    rule = PassingRule()
    registry.register(rule)
    config = _config_with(**{rule.rule_id: CompletenessCheckRule(enabled=False)})

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert rule.evaluated is False
    assert messages == []
    assert coverage[0].outcome is RuleOutcome.SKIPPED
    assert coverage[0].blocks_completeness is False


def test_spec_version_outside_configured_versions_is_not_applicable_and_does_not_block():
    """A spec version outside cfg.spdx_versions yields NOT_APPLICABLE and does not block."""
    registry = ProfileRuleRegistry()
    rule = PassingRule()
    registry.register(rule)
    config = _config_with(
        **{rule.rule_id: CompletenessCheckRule(spdx_versions=["2.3"])}
    )

    messages, coverage = registry.run(document={}, context=_context("3.0.1", config))

    assert rule.evaluated is False
    assert messages == []
    assert coverage[0].outcome is RuleOutcome.NOT_APPLICABLE
    assert coverage[0].blocks_completeness is False


def test_rule_without_implementation_for_version_is_unsupported_and_blocks():
    """A rule lacking an implementation for the doc's version is UNSUPPORTED and blocks."""
    registry = ProfileRuleRegistry()
    rule = LegacyVersionRule()
    registry.register(rule)
    config = _config_with()

    messages, coverage = registry.run(document={}, context=_context("3.0.1", config))

    assert rule.evaluated is False
    assert messages == []
    assert coverage[0].outcome is RuleOutcome.UNSUPPORTED
    assert coverage[0].blocks_completeness is True


def test_unsupported_config_flag_is_unsupported_and_blocks():
    """supported: false yields UNSUPPORTED and blocks completeness."""
    registry = ProfileRuleRegistry()
    rule = PassingRule()
    registry.register(rule)
    config = _config_with(**{rule.rule_id: CompletenessCheckRule(supported=False)})

    _messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert rule.evaluated is False
    assert coverage[0].outcome is RuleOutcome.UNSUPPORTED
    assert coverage[0].blocks_completeness is True


def test_raising_rule_is_unsupported_blocks_and_emits_exactly_one_error_message():
    """A rule that raises is recorded UNSUPPORTED, blocks, and emits one ERROR message
    rather than being treated as a silent pass."""
    registry = ProfileRuleRegistry()
    rule = RaisingRule()
    registry.register(rule)
    config = _config_with()

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert rule.evaluated is True
    assert len(messages) == 1
    assert messages[0].severity is ValidationSeverity.ERROR
    assert rule.rule_id in messages[0].message
    assert coverage[0].outcome is RuleOutcome.UNSUPPORTED
    assert coverage[0].blocks_completeness is True


def test_configured_severity_overrides_rule_reported_severity():
    """A rule returns ERROR but config says WARNING: emitted message and coverage are WARNING."""
    registry = ProfileRuleRegistry()
    rule = FailingRule()
    registry.register(rule)
    config = _config_with(
        **{rule.rule_id: CompletenessCheckRule(severity=ValidationSeverity.WARNING)}
    )

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert messages[0].severity is ValidationSeverity.WARNING
    assert coverage[0].severity is ValidationSeverity.WARNING


def test_configured_remediation_and_description_fill_in_when_rule_omitted_them():
    """Configured remediation/description fill in when the rule left them unset."""
    registry = ProfileRuleRegistry()
    rule = FailingRule()
    registry.register(rule)
    config = _config_with(
        **{
            rule.rule_id: CompletenessCheckRule(
                description="Configured description",
                remediation="Configured remediation",
            )
        }
    )

    messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert messages[0].remediation == "Configured remediation"
    assert coverage[0].description == "Configured description"


def test_rule_with_no_config_entry_runs_under_implicit_defaults():
    """A rule with no config entry at all runs under implicit defaults (enabled, ERROR)."""
    registry = ProfileRuleRegistry()
    rule = PassingRule()
    registry.register(rule)
    config = _config_with()

    _messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert rule.evaluated is True
    assert coverage[0].outcome is RuleOutcome.PASSED


def test_configured_rule_that_is_not_registered_is_reported_unsupported():
    """A mistyped rule ID must not silently have no effect.

    An operator who believes they disabled or downgraded a rule should
    not instead get its default behaviour with no warning, so an
    unrecognised rule ID fails closed.
    """
    registry = ProfileRuleRegistry()
    registry.register(PassingRule())
    config = _config_with(**{"spdx3_completeness.typoed_rule": CompletenessCheckRule()})

    _messages, coverage = registry.run(document={}, context=_context("2.3", config))

    unknown = [e for e in coverage if e.rule_id == "spdx3_completeness.typoed_rule"]
    assert len(unknown) == 1
    assert unknown[0].outcome is RuleOutcome.UNSUPPORTED
    assert unknown[0].blocks_completeness is True
    assert "typo" in (unknown[0].reason or "")


def test_legacy_completeness_keys_are_not_treated_as_typos():
    """Legacy boolean-style keys predate the registry and never ran."""
    registry = ProfileRuleRegistry()
    registry.register(PassingRule())
    config = _config_with(**{"require_package_identifier": CompletenessCheckRule()})

    _messages, coverage = registry.run(document={}, context=_context("2.3", config))

    assert [e for e in coverage if e.blocks_completeness] == []
