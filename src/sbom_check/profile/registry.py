# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Version-aware registry for SPDX completeness rules.

Rules are registered once and run per-document. Each rule's config entry
decides whether it is enabled, which spec versions it applies to, and
how loud its findings are reported. A rule that cannot be evaluated
(no implementation for the document's version, or explicitly marked
unsupported, or raising during evaluation) is recorded as
``RuleOutcome.UNSUPPORTED`` rather than silently skipped, so completeness
fails closed instead of passing by omission.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from sbom_check.models import (
    DocumentFormat,
    RuleCoverage,
    RuleOutcome,
    ValidationMessage,
    ValidationSeverity,
)

if TYPE_CHECKING:
    from sbom_check.config.models import SbomCheckConfig


@runtime_checkable
class ProfileRule(Protocol):
    """Interface implemented by a single completeness rule."""

    rule_id: str
    description: str
    spdx_versions: tuple[str, ...]

    def evaluate(self, document: Any, context: RuleContext) -> list[ValidationMessage]:
        """Evaluate this rule against a document.

        Args:
            document: The parsed SBOM document to inspect.
            context: Execution context carrying the document's spec
                version, format, and effective configuration.

        Returns:
            list[ValidationMessage]: Messages describing failures. An
            empty list means the rule passed.
        """


@dataclass(frozen=True)
class RuleContext:
    """Execution context passed to every rule during evaluation."""

    spec_version: str | None
    document_format: DocumentFormat
    config: SbomCheckConfig


class ProfileRuleRegistry:
    """Insertion-ordered registry of completeness rules."""

    def __init__(self) -> None:
        """Initialize an empty, insertion-ordered rule registry."""
        self._rules: dict[str, ProfileRule] = {}
        self._pending: dict[str, str] = {}

    def register(self, rule: ProfileRule) -> None:
        """Register a rule.

        Args:
            rule: The rule to register.

        Raises:
            ValueError: If a rule with the same ``rule_id`` is already
                registered.
        """
        if rule.rule_id in self._rules:
            raise ValueError(f"Rule with id {rule.rule_id!r} is already registered")
        self._rules[rule.rule_id] = rule

    def register_pending_decision(self, rule_id: str, description: str) -> None:
        """Record a requirement that is defined but awaits an owner decision.

        A pending requirement has no implementation. It is listed so that
        every run reports it in coverage, rather than leaving it out and
        letting a result look complete without mentioning it.

        Args:
            rule_id: The stable rule identifier reserved for the requirement.
            description: What the requirement would check.

        Raises:
            ValueError: If ``rule_id`` is already registered as a rule or
                as a pending requirement.
        """
        if rule_id in self._rules or rule_id in self._pending:
            raise ValueError(f"Rule with id {rule_id!r} is already registered")
        self._pending[rule_id] = description

    def pending_decision_ids(self) -> list[str]:
        """List requirement ids awaiting an owner decision, in registration order.

        Returns:
            list[str]: The pending requirement ids.
        """
        return list(self._pending)

    def get(self, rule_id: str) -> ProfileRule | None:
        """Look up a registered rule by id.

        Args:
            rule_id: The stable rule identifier.

        Returns:
            ProfileRule | None: The matching rule, or None if not found.
        """
        return self._rules.get(rule_id)

    def rules(self) -> list[ProfileRule]:
        """List all registered rules in registration order.

        Returns:
            list[ProfileRule]: Registered rules in registration order.
        """
        return list(self._rules.values())

    def _unknown_rule_coverage(self, context: RuleContext) -> list[RuleCoverage]:
        """Report configured rule IDs that match no registered rule.

        An unrecognised ID is almost always a typo. Reporting it as
        unsupported fails closed, because an operator who believes they
        disabled or downgraded a rule should not silently get its default
        behaviour instead.

        Args:
            context: Execution context carrying the effective config.

        Returns:
            list[RuleCoverage]: One unsupported entry per unrecognised
            ``spdx3_completeness.*`` key. Legacy boolean-style keys
            predate the registry and were never executed, so they are not
            treated as typos.
        """
        configured = set(context.config.compliance_requirements.completeness_checks)
        return [
            RuleCoverage(
                rule_id=unknown,
                outcome=RuleOutcome.UNSUPPORTED,
                severity=None,
                description=None,
                reason=(
                    "configured rule is not registered; check the rule ID for a typo"
                ),
            )
            for unknown in sorted(configured - set(self._rules) - set(self._pending))
            if unknown.startswith("spdx3_completeness.")
        ]

    def _pending_decision_coverage(self, context: RuleContext) -> list[RuleCoverage]:
        """Report every requirement that awaits an owner decision.

        Each pending requirement gets an entry so results show it was not
        checked and why. By default the entry is ``skipped`` and does not
        block, because whether a pending requirement should block is
        itself one of the open owner decisions. A profile that explicitly
        enables a pending ID asked for a check that cannot run, so that
        case is ``unsupported`` and fails closed, like any other enabled
        rule with no implementation.

        Args:
            context: Execution context carrying the effective config.

        Returns:
            list[RuleCoverage]: One entry per pending requirement.
        """
        checks = context.config.compliance_requirements.completeness_checks
        coverage: list[RuleCoverage] = []
        for rule_id, description in self._pending.items():
            cfg = checks.get(rule_id)
            if cfg is not None and cfg.enabled:
                coverage.append(
                    RuleCoverage(
                        rule_id=rule_id,
                        outcome=RuleOutcome.UNSUPPORTED,
                        severity=cfg.severity,
                        description=cfg.description or description,
                        reason=(
                            "enabled by configuration, but not implemented: "
                            "the requirement is pending a decision by the "
                            "Qualcomm SBOM owners"
                        ),
                    )
                )
                continue
            coverage.append(
                RuleCoverage(
                    rule_id=rule_id,
                    outcome=RuleOutcome.SKIPPED,
                    severity=None,
                    description=description,
                    reason=(
                        "pending decision: the requirement mapping awaits a "
                        "decision by the Qualcomm SBOM owners, so this "
                        "document was not checked against it"
                    ),
                )
            )
        return coverage

    def run(
        self, document: Any, context: RuleContext
    ) -> tuple[list[ValidationMessage], list[RuleCoverage]]:
        """Run all registered rules against a document.

        For each registered rule, and each requirement pending an owner
        decision, exactly one ``RuleCoverage`` entry is produced. Precedence: disabled config skips evaluation (does not
        block completeness); not applicable to the document's spec
        version is recorded as not-applicable (does not block); no rule
        implementation for the version, or an explicit
        ``supported=False`` config, is recorded as unsupported (blocks
        completeness); otherwise the rule is evaluated, with any
        exception also recorded as unsupported plus an ERROR message.

        Args:
            document: The parsed SBOM document to validate.
            context: Execution context for this run.

        Returns:
            tuple[list[ValidationMessage], list[RuleCoverage]]: All
            messages produced (with severity/remediation/description
            overridden per configuration) and one coverage entry per
            rule.
        """
        all_messages: list[ValidationMessage] = []
        coverage_list: list[RuleCoverage] = []

        coverage_list.extend(self._unknown_rule_coverage(context))
        coverage_list.extend(self._pending_decision_coverage(context))

        for rule in self.rules():
            cfg = context.config.compliance_requirements.completeness_checks.get(
                rule.rule_id
            )
            if cfg is None:
                # A profile that does not list a rule has not opted into
                # it. Falling back to CompletenessCheckRule() would run
                # every rule at its ERROR default, which would make
                # core-only profiles such as basic_spdx report profile
                # completeness failures they never asked for.
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.SKIPPED,
                        severity=None,
                        description=rule.description,
                        reason="not enabled by the active profile",
                    )
                )
                continue

            if not cfg.enabled:
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.SKIPPED,
                        severity=None,
                        description=cfg.description or rule.description,
                        reason="disabled by configuration",
                    )
                )
                continue

            if not cfg.applies_to_version(context.spec_version):
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.NOT_APPLICABLE,
                        severity=None,
                        description=cfg.description or rule.description,
                        reason=(
                            "rule is not applicable to spec version "
                            f"{context.spec_version!r}"
                        ),
                    )
                )
                continue

            if context.spec_version not in rule.spdx_versions:
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.UNSUPPORTED,
                        severity=cfg.severity,
                        description=cfg.description or rule.description,
                        reason=(
                            "no implementation of this rule for spec version "
                            f"{context.spec_version!r}"
                        ),
                    )
                )
                continue

            if not cfg.supported:
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.UNSUPPORTED,
                        severity=cfg.severity,
                        description=cfg.description or rule.description,
                        reason="no approved mapping for this specification version",
                    )
                )
                continue

            try:
                messages = rule.evaluate(document, context)
            except Exception as exc:  # pylint: disable=broad-except
                # A rule that raises must never be treated as a silent
                # pass; record it as unsupported (fails closed) and emit
                # an explicit ERROR message naming the failure.
                error_message = ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=f"Rule {rule.rule_id} failed to evaluate: {exc}",
                    rule_id=rule.rule_id,
                )
                all_messages.append(error_message)
                coverage_list.append(
                    RuleCoverage(
                        rule_id=rule.rule_id,
                        outcome=RuleOutcome.UNSUPPORTED,
                        severity=cfg.severity,
                        description=cfg.description or rule.description,
                        reason=str(exc),
                    )
                )
                continue

            updated_messages = []
            for message in messages:
                updates: dict[str, Any] = {"severity": cfg.severity}
                # Configuration wins over the rule's built-in text. Rules
                # always supply a remediation, so deferring to the rule
                # whenever one exists would make a configured remediation
                # unreachable.
                if cfg.remediation is not None:
                    updates["remediation"] = cfg.remediation
                updated_messages.append(message.model_copy(update=updates))
            all_messages.extend(updated_messages)

            outcome = RuleOutcome.FAILED if updated_messages else RuleOutcome.PASSED
            coverage_list.append(
                RuleCoverage(
                    rule_id=rule.rule_id,
                    outcome=outcome,
                    severity=cfg.severity,
                    description=cfg.description or rule.description,
                    reason=None,
                )
            )

        return all_messages, coverage_list
