# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Abstract interfaces shared by SBOM validation engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


class ValidationResultProtocol(Protocol):
    """Common result interface exposed by format-specific validators."""

    @property
    def is_valid(self) -> bool:
        """Whether the validated document is valid."""

    @property
    def messages(self) -> Sequence[Any]:
        """Validation messages produced for the document."""


class ValidatorEngine(ABC):
    """Interface required by every format-specific validation engine."""

    @abstractmethod
    def validate_json_string(self, json_string: str) -> ValidationResultProtocol:
        """Validate an SBOM document represented as a JSON string."""

    @abstractmethod
    def validate_dict(self, document: dict[str, Any]) -> ValidationResultProtocol:
        """Validate an SBOM document represented as a dictionary."""

    @abstractmethod
    def validate_file(self, file_path: str | Path) -> ValidationResultProtocol:
        """Validate an SBOM document loaded from a file."""


__all__ = ["ValidationResultProtocol", "ValidatorEngine"]
