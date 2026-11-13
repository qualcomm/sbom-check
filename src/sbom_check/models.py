# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Core data models for SBOM-Check validation results and messages."""

from __future__ import annotations

from enum import Enum
from typing import Any
from warnings import warn as warn_deprecated

from pydantic import BaseModel, Field


class ValidationSeverity(str, Enum):
    """Severity levels for validation messages."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


class DocumentFormat(str, Enum):
    """Supported SBOM document formats."""

    SPDX = "SPDX"
    SPDX3 = "SPDX3"
    CYCLONEDX = "CycloneDX"
    UNKNOWN = "unknown"


class ProfileStatus(str, Enum):
    """Applicability and outcome of profile validation."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"
    SKIPPED = "skipped"
    UNSUPPORTED = "unsupported"


class RuleOutcome(str, Enum):
    """Outcome of attempting to evaluate a single completeness rule.

    ``UNSUPPORTED`` means the rule has no mapping for the document's
    version or could not be evaluated at all. It must never be treated
    as a pass: a document cannot be reported as complete when a
    required rule never actually ran.
    """

    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    UNSUPPORTED = "unsupported"


class ValidationMessage(BaseModel):
    """A single validation message with context and metadata."""

    severity: ValidationSeverity
    message: str
    rule_id: str | None = None
    field_path: str | None = None
    section_reference: str | None = None
    found_value: Any | None = None
    expected_value: Any | None = None
    remediation: str | None = None

    def __str__(self) -> str:
        """Return a human-readable string representation."""
        parts = [f"{self.severity.value}: {self.message}"]

        if self.field_path:
            parts.append(f"Field: {self.field_path}")

        if self.found_value is not None:
            parts.append(f"Found: {self.found_value}")

        if self.expected_value is not None:
            parts.append(f"Expected: {self.expected_value}")

        if self.section_reference:
            parts.append(f"Reference: {self.section_reference}")

        if self.remediation:
            parts.append(f"Remediation: {self.remediation}")

        return "\n  ".join(parts)


class ValidationSummary(BaseModel):
    """Summary statistics for validation results."""

    total_rules: int = 0
    passed_rules: int = 0
    failed_rules: int = 0
    errors: int = 0
    warnings: int = 0
    info: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate the success rate as a percentage."""
        if self.total_rules == 0:
            return 0.0
        return (self.passed_rules / self.total_rules) * 100


class RuleCoverage(BaseModel):
    """Record of whether and how a single completeness rule was executed."""

    rule_id: str
    outcome: RuleOutcome
    severity: ValidationSeverity | None = None
    description: str | None = None
    reason: str | None = None

    @property
    def blocks_completeness(self) -> bool:
        """Return whether this entry must prevent a document from passing as complete.

        An ``UNSUPPORTED`` outcome means a required rule was never
        actually evaluated. Such a rule must fail closed rather than be
        silently ignored, otherwise a document could be reported as
        "complete" when a required completeness check never ran.

        Returns:
            bool: True when ``outcome`` is ``RuleOutcome.UNSUPPORTED``.
        """
        return self.outcome is RuleOutcome.UNSUPPORTED


class SbomCheckResult(BaseModel):
    """Complete validation result combining core validation and profile results."""

    overall_valid: bool
    spdx_valid: bool | None
    profile_valid: bool | None
    core_valid: bool = False
    profile_status: ProfileStatus = ProfileStatus.NOT_APPLICABLE
    messages: list[ValidationMessage] = Field(default_factory=list)
    summary: ValidationSummary = Field(default_factory=ValidationSummary)
    profile_name: str | None = None
    file_path: str | None = None
    document_format: DocumentFormat = DocumentFormat.UNKNOWN
    spec_version: str | None = None
    rule_coverage: list[RuleCoverage] = Field(default_factory=list)

    @classmethod
    def combine(  # pylint: disable=too-many-positional-arguments,too-many-locals  # noqa: PLR0917,RUF100
        cls,
        core_result: Any = None,  # core validator result
        profile_result: SbomCheckResult | None = None,
        profile_name: str | None = None,
        file_path: str | None = None,
        document_format: DocumentFormat = DocumentFormat.SPDX,
        spec_version: str | None = "2.3",
        *,
        spdx_result: Any = None,
        profile_rule_coverage: list[RuleCoverage] | None = None,
    ) -> SbomCheckResult:
        """Combine core validation result with profile validation result.

        ``spdx_result`` is deprecated; use ``core_result`` instead.

        Args:
            core_result: Result object from the core validator, exposing
                ``is_valid`` and ``messages``.
            profile_result: Previously combined profile validation result,
                if any.
            profile_name: Name of the profile that was applied.
            file_path: Path of the document that was validated.
            document_format: Format of the document that was validated.
            spec_version: Specification version of the document.
            spdx_result: Deprecated alias for ``core_result``.
            profile_rule_coverage: Execution records for individual
                completeness rules evaluated for this document. Any entry
                whose ``blocks_completeness`` is True (i.e. an
                ``UNSUPPORTED`` outcome) forces ``overall_valid`` to False
                and, when the profile would otherwise be ``PASSED``,
                downgrades ``profile_status`` to ``SKIPPED``.

        Returns:
            SbomCheckResult: The combined validation result.

        Raises:
            TypeError: If both or neither of ``core_result`` and
                ``spdx_result`` are provided.
        """
        if core_result is not None and spdx_result is not None:
            raise TypeError("Pass either core_result or spdx_result, not both")
        if spdx_result is not None:
            warn_deprecated(
                "spdx_result is deprecated; use core_result instead",
                DeprecationWarning,
                stacklevel=2,
            )
            core_result = spdx_result
        if core_result is None:
            raise TypeError("Missing required argument: core_result")
        # Convert and collect all messages
        messages = cls._convert_validation_messages(core_result)
        if profile_result:
            messages.extend(profile_result.messages)

        # Calculate summary statistics
        summary = cls._calculate_summary(messages)

        rule_coverage = profile_rule_coverage or []
        has_unevaluated_rules = any(
            coverage.blocks_completeness for coverage in rule_coverage
        )

        # Determine validity
        core_valid = getattr(core_result, "is_valid", False)
        is_spdx_document = document_format in (
            DocumentFormat.SPDX,
            DocumentFormat.SPDX3,
        )
        spdx_valid = core_valid if is_spdx_document else None
        profile_valid: bool | None
        if is_spdx_document:
            profile_valid = profile_result.overall_valid if profile_result else True
            profile_status = cls._resolve_profile_status(
                profile_valid, has_unevaluated_rules
            )
        else:
            profile_valid = profile_result.overall_valid if profile_result else None
            profile_status = ProfileStatus.NOT_APPLICABLE
        overall_valid = (
            core_valid
            and (profile_result is None or profile_result.overall_valid)
            and summary.errors == 0
            and not has_unevaluated_rules
        )
        return cls(
            overall_valid=overall_valid,
            spdx_valid=spdx_valid,
            profile_valid=profile_valid,
            core_valid=core_valid,
            profile_status=profile_status,
            messages=messages,
            summary=summary,
            profile_name=profile_name if is_spdx_document else None,
            file_path=file_path,
            document_format=document_format,
            spec_version=spec_version,
            rule_coverage=rule_coverage,
        )

    @classmethod
    def _resolve_profile_status(
        cls, profile_valid: bool, has_unevaluated_rules: bool
    ) -> ProfileStatus:
        """Resolve the profile status for an SPDX document.

        Args:
            profile_valid: Whether the profile result (if any) was valid.
            has_unevaluated_rules: Whether any required rule was never
                actually evaluated, in which case the profile must not
                be reported as PASSED.

        Returns:
            ProfileStatus: SKIPPED when a required rule was never
            evaluated, otherwise PASSED or FAILED based on
            ``profile_valid``.
        """
        if has_unevaluated_rules and profile_valid:
            return ProfileStatus.SKIPPED
        return ProfileStatus.PASSED if profile_valid else ProfileStatus.FAILED

    @classmethod
    def _convert_validation_messages(cls, core_result: Any) -> list[ValidationMessage]:
        """Convert validation messages to our format."""
        messages: list[ValidationMessage] = []

        if hasattr(core_result, "messages"):
            for raw_message in core_result.messages:
                # Determine severity level
                if hasattr(raw_message, "severity"):
                    severity_value = raw_message.severity.value.upper()
                    if severity_value == "WARNING":
                        severity_level = ValidationSeverity.WARNING
                    elif severity_value == "INFO":
                        severity_level = ValidationSeverity.INFO
                    else:
                        severity_level = ValidationSeverity.ERROR
                else:
                    severity_level = ValidationSeverity.ERROR

                converted_message = ValidationMessage(
                    severity=severity_level,
                    message=raw_message.message,
                    rule_id=getattr(raw_message, "rule_id", None),
                    field_path=getattr(
                        raw_message, "field_path", getattr(raw_message, "path", None)
                    ),
                )
                messages.append(converted_message)

        return messages

    @classmethod
    def _calculate_summary(cls, messages: list[ValidationMessage]) -> ValidationSummary:
        """Calculate summary statistics from messages."""
        errors = warnings = info = failed_rules = 0

        for msg in messages:
            if msg.severity == ValidationSeverity.ERROR:
                errors += 1
                failed_rules += 1
            elif msg.severity == ValidationSeverity.WARNING:
                warnings += 1
            elif msg.severity == ValidationSeverity.INFO:
                info += 1

        return ValidationSummary(
            errors=errors,
            warnings=warnings,
            info=info,
            failed_rules=failed_rules,
        )

    def add_message(  # pylint: disable=too-many-positional-arguments  # noqa: PLR0917,RUF100
        self,
        severity: ValidationSeverity,
        message: str,
        rule_id: str | None = None,
        field_path: str | None = None,
        section_reference: str | None = None,
        found_value: Any | None = None,
        expected_value: Any | None = None,
        remediation: str | None = None,
    ) -> None:
        """Add a validation message to the result."""
        msg = ValidationMessage(
            severity=severity,
            message=message,
            rule_id=rule_id,
            field_path=field_path,
            section_reference=section_reference,
            found_value=found_value,
            expected_value=expected_value,
            remediation=remediation,
        )
        # Add message to the list
        messages_list = list(self.messages)
        messages_list.append(msg)
        self.messages = messages_list

        # Update summary by creating a new one with updated values
        current_summary = self.summary
        if severity == ValidationSeverity.ERROR:
            self.summary = ValidationSummary(
                total_rules=current_summary.total_rules,
                passed_rules=current_summary.passed_rules,
                failed_rules=current_summary.failed_rules + 1,
                errors=current_summary.errors + 1,
                warnings=current_summary.warnings,
                info=current_summary.info,
            )
            self.overall_valid = False
            self.profile_valid = False
        elif severity == ValidationSeverity.WARNING:
            self.summary = ValidationSummary(
                total_rules=current_summary.total_rules,
                passed_rules=current_summary.passed_rules,
                failed_rules=current_summary.failed_rules,
                errors=current_summary.errors,
                warnings=current_summary.warnings + 1,
                info=current_summary.info,
            )
        elif severity == ValidationSeverity.INFO:
            self.summary = ValidationSummary(
                total_rules=current_summary.total_rules,
                passed_rules=current_summary.passed_rules,
                failed_rules=current_summary.failed_rules,
                errors=current_summary.errors,
                warnings=current_summary.warnings,
                info=current_summary.info + 1,
            )

    def get_messages_by_severity(
        self, severity: ValidationSeverity
    ) -> list[ValidationMessage]:
        """Get all messages of a specific severity level."""
        return [msg for msg in self.messages if msg.severity == severity]

    def has_errors(self) -> bool:
        """Check if the result contains any error messages."""
        return self.summary.errors > 0

    def has_warnings(self) -> bool:
        """Check if the result contains any warning messages."""
        return self.summary.warnings > 0

    def rules_by_outcome(self, outcome: RuleOutcome) -> list[RuleCoverage]:
        """Get all rule coverage entries with a specific outcome.

        Args:
            outcome: The outcome to filter by.

        Returns:
            list[RuleCoverage]: Coverage entries matching ``outcome``.
        """
        return [
            coverage for coverage in self.rule_coverage if coverage.outcome == outcome
        ]

    def has_unevaluated_rules(self) -> bool:
        """Check whether any required rule was never actually evaluated.

        Returns:
            bool: True if any coverage entry has ``blocks_completeness``
            set, meaning a required rule could not be evaluated and the
            document must not be reported as complete.
        """
        return any(coverage.blocks_completeness for coverage in self.rule_coverage)

    def add_rule_coverage(self, coverage: RuleCoverage) -> None:
        """Add a rule coverage entry to the result.

        If the appended coverage blocks completeness (an unevaluated
        required rule), this fails closed: ``overall_valid`` is set to
        False, and if ``profile_status`` is currently ``PASSED`` it is
        downgraded to ``SKIPPED``. ``profile_valid`` is left untouched.

        Args:
            coverage: The rule coverage entry to record.
        """
        coverage_list = list(self.rule_coverage)
        coverage_list.append(coverage)
        self.rule_coverage = coverage_list

        if coverage.blocks_completeness:
            self.overall_valid = False
            if self.profile_status is ProfileStatus.PASSED:
                self.profile_status = ProfileStatus.SKIPPED
