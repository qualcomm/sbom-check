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
    CYCLONEDX = "CycloneDX"
    UNKNOWN = "unknown"


class ProfileStatus(str, Enum):
    """Applicability and outcome of profile validation."""

    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


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
    ) -> SbomCheckResult:
        """Combine core validation result with profile validation result.

        ``spdx_result`` is deprecated; use ``core_result`` instead.
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

        # Determine validity
        core_valid = getattr(core_result, "is_valid", False)
        is_spdx_document = document_format is DocumentFormat.SPDX
        spdx_valid = core_valid if is_spdx_document else None
        profile_valid: bool | None
        if is_spdx_document:
            profile_valid = profile_result.overall_valid if profile_result else True
            profile_status = (
                ProfileStatus.PASSED if profile_valid else ProfileStatus.FAILED
            )
        else:
            profile_valid = profile_result.overall_valid if profile_result else None
            profile_status = ProfileStatus.NOT_APPLICABLE
        overall_valid = (
            core_valid
            and (profile_result is None or profile_result.overall_valid)
            and summary.errors == 0
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
        )

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
                    field_path=getattr(raw_message, "field_path", getattr(raw_message, "path", None)),
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
