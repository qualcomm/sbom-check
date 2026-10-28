# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Models returned by CycloneDX validation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ValidationSeverity(str, Enum):
    """Severity assigned to a CycloneDX validation message."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass(slots=True)
class ValidationMessage:
    """A validation message with optional JSON-path context."""

    severity: ValidationSeverity
    message: str
    rule_id: str | None = None
    field_path: str | None = None
    section_reference: str | None = None
    found_value: Any | None = None
    expected_value: Any | None = None
    remediation: str | None = None


@dataclass(frozen=True, slots=True)
class CycloneDXValidationResult:
    """Result returned by CycloneDX validation."""

    is_valid: bool
    messages: list[ValidationMessage]


__all__ = [
    "CycloneDXValidationResult",
    "ValidationMessage",
    "ValidationSeverity",
]
