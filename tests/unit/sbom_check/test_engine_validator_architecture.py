# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the shared ValidatorEngine contract."""

from pathlib import Path

import pytest

from cyclone_validator import CycloneDXValidationEngine
from sbom_validator.engine import ValidatorEngine
from spdx3_validator import ValidationEngine as Spdx3ValidationEngine
from spdx_validator.engine import ValidationEngine


def test_engine_validator_is_abstract() -> None:
    """The shared contract cannot be instantiated directly."""
    with pytest.raises(TypeError):
        ValidatorEngine()


def test_all_engines_implement_engine_validator() -> None:
    """All format engines satisfy the common engine contract."""
    assert issubclass(ValidationEngine, ValidatorEngine)
    assert issubclass(CycloneDXValidationEngine, ValidatorEngine)
    assert issubclass(Spdx3ValidationEngine, ValidatorEngine)


def test_cyclonedx_engine_has_shared_constructor_signature() -> None:
    """CycloneDX accepts the same configuration values as the SPDX engine."""
    engine = CycloneDXValidationEngine(
        schema_path=Path("unused-schema.json"),
        enable_schema_validation=False,
        enable_semantic_validation=True,
    )

    assert engine.enable_schema_validation is False
    assert engine.enable_semantic_validation is True
    assert engine.schema_validator is None
    assert engine.semantic_validator is not None


def test_spdx3_engine_has_shared_constructor_signature() -> None:
    """SPDX 3 accepts shared validation flags and rejects custom schema paths."""
    engine = Spdx3ValidationEngine(
        enable_schema_validation=False,
        enable_semantic_validation=True,
    )

    assert engine.enable_schema_validation is False
    assert engine.enable_semantic_validation is True

    with pytest.raises(ValueError, match="custom schema path is not supported"):
        Spdx3ValidationEngine(schema_path=Path("unused-schema.json"))


def test_engine_validator_subclass_must_implement_all_methods() -> None:
    """A subclass missing any contract method remains abstract."""

    class IncompleteValidator(ValidatorEngine):
        def __init__(
            self,
            schema_path: str | Path | None = None,
            enable_schema_validation: bool = True,
            enable_semantic_validation: bool = True,
        ) -> None:
            del schema_path, enable_schema_validation, enable_semantic_validation

    with pytest.raises(TypeError):
        IncompleteValidator()
