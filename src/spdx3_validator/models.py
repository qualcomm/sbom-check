# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Models used by the SPDX 3 validator."""

from dataclasses import dataclass
from enum import Enum
from typing import Any


class ValidationSeverity(str, Enum):
    """Severity levels for validation messages."""

    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


REMOTE_RESOURCE_UNAVAILABLE_RULE_ID = "remote_resource_unavailable"


@dataclass
class ValidationMessage:
    """A validation message with optional diagnostic context."""

    severity: ValidationSeverity
    message: str
    rule_id: str | None = None
    field_path: str | None = None
    json_path: str | None = None
    affected_element: str | None = None
    section_reference: str | None = None
    found_value: Any | None = None
    expected_value: Any | None = None
    remediation: str | None = None


@dataclass
class ValidationResult:
    """Result of SPDX 3.0.1 document validation."""

    is_valid: bool
    messages: list[ValidationMessage]
    # None means that validation could not be evaluated (for example, because a
    # required remote validation resource was unavailable).
    schema_valid: bool | None = True
    semantic_valid: bool | None = True
