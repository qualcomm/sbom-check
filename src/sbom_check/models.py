# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Core data models for SBOM-Check validation results and messages."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ValidationSeverity(str, Enum):
    """Severity levels for validation messages."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


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


class SbomCheckResult(BaseModel):
    """Complete validation result combining SPDX and custom validation."""

    overall_valid: bool
    spdx_valid: bool
    profile_valid: bool
    messages: list[ValidationMessage] = Field(default_factory=list)
    summary: ValidationSummary = Field(default_factory=ValidationSummary)
    profile_name: str | None = None
    file_path: str | None = None

    @classmethod
    def combine(
        cls,
        spdx_result: Any,  # spdx_validator.ValidationResult
        profile_result: SbomCheckResult | None = None,
        profile_name: str | None = None,
        file_path: str | None = None,
    ) -> SbomCheckResult:
        """Combine SPDX validation result with profile validation result."""
        # Convert and collect all messages
        messages = cls._convert_spdx_messages(spdx_result)
        if profile_result:
            messages.extend(profile_result.messages)

        # Calculate summary statistics
        summary = cls._calculate_summary(messages)

        # Determine validity
        spdx_valid = getattr(spdx_result, "is_valid", False)
        profile_valid = profile_result.overall_valid if profile_result else True
        overall_valid = spdx_valid and profile_valid and summary.errors == 0

        return cls(
            overall_valid=overall_valid,
            spdx_valid=spdx_valid,
            profile_valid=profile_valid,
            messages=messages,
            summary=summary,
            profile_name=profile_name,
            file_path=file_path,
        )

    @classmethod
    def _convert_spdx_messages(cls, spdx_result: Any) -> list[ValidationMessage]:
        """Convert spdx-validator messages to our format."""
        messages: list[ValidationMessage] = []

        if hasattr(spdx_result, "messages"):
            for spdx_msg in spdx_result.messages:
                # Determine severity level
                if hasattr(spdx_msg, "severity"):
                    severity_value = spdx_msg.severity.value.upper()
                    if severity_value == "WARNING":
                        severity_level = ValidationSeverity.WARNING
                    elif severity_value == "INFO":
                        severity_level = ValidationSeverity.INFO
                    else:
                        severity_level = ValidationSeverity.ERROR
                else:
                    severity_level = ValidationSeverity.ERROR

                validation_msg = ValidationMessage(
                    severity=severity_level,
                    message=spdx_msg.message,
                    rule_id=getattr(spdx_msg, "rule_id", None),
                    field_path=getattr(spdx_msg, "path", None),
                )
                messages.append(validation_msg)

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

    def add_message(  # pylint: disable=too-many-positional-arguments  # noqa: PLR0917
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
