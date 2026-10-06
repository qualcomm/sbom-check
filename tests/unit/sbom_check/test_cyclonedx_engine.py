# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause
"""Tests for the CycloneDX engine and validation stages."""

import json
from unittest.mock import patch

from cyclone_validator import CycloneDXValidationEngine, SemanticValidator
from cyclone_validator.validators import CycloneDXValidationResult
from sbom_check.models import ValidationMessage, ValidationSeverity


def _valid_document() -> dict[str, str]:
    return {"bomFormat": "CycloneDX", "specVersion": "1.7"}


def test_default_engine_enables_both_validation_stages() -> None:
    engine = CycloneDXValidationEngine()

    assert engine.enable_schema_validation is True
    assert engine.enable_semantic_validation is True
    assert engine.schema_validator is not None
    assert engine.semantic_validator is not None


def test_schema_only_configuration_does_not_run_semantic_validation() -> None:
    engine = CycloneDXValidationEngine(
        enable_schema_validation=True,
        enable_semantic_validation=False,
    )

    with patch.object(engine.schema_validator, "validate", wraps=engine.schema_validator.validate) as schema_validate:
        result = engine.validate_dict(_valid_document())

    assert result.is_valid
    schema_validate.assert_called_once()
    assert engine.semantic_validator is None


def test_semantic_only_configuration_does_not_run_schema_validation() -> None:
    engine = CycloneDXValidationEngine(
        enable_schema_validation=False,
        enable_semantic_validation=True,
    )

    result = engine.validate_dict({"specVersion": "1.7"})

    assert result.is_valid
    assert engine.schema_validator is None
    assert engine.semantic_validator is not None


def test_schema_failure_skips_semantic_validation() -> None:
    engine = CycloneDXValidationEngine()
    schema_result = CycloneDXValidationResult(
        is_valid=False,
        messages=[
            ValidationMessage(
                severity=ValidationSeverity.ERROR,
                message="schema failure",
                rule_id="cyclonedx_schema_error",
            )
        ],
    )

    with (
        patch.object(engine.schema_validator, "validate", return_value=schema_result),
        patch.object(engine.semantic_validator, "validate") as semantic_validate,
    ):
        result = engine.validate_dict(_valid_document())

    assert not result.is_valid
    assert any(message.rule_id == "semantic_validation_skipped" for message in result.messages)
    semantic_validate.assert_not_called()


def test_json_string_and_file_validation_use_engine_pipeline(tmp_path) -> None:
    engine = CycloneDXValidationEngine()
    document_path = tmp_path / "bom.json"
    document_path.write_text(json.dumps(_valid_document()), encoding="utf-8")

    assert engine.validate_json_string(json.dumps(_valid_document())).is_valid
    assert engine.validate_file(document_path).is_valid


def test_invalid_json_returns_validation_message() -> None:
    result = CycloneDXValidationEngine().validate_json_string("{invalid")

    assert not result.is_valid
    assert result.messages[0].rule_id == "json_parse_error"


def test_unsupported_version_returns_validation_message() -> None:
    result = CycloneDXValidationEngine().validate_json_string(
        '{"bomFormat":"CycloneDX","specVersion":"1.2"}'
    )

    assert not result.is_valid
    assert result.messages[0].rule_id == "unsupported_version"
    assert "1.2" in result.messages[0].message


def test_cyclonedx_semantic_validator_is_explicit_todo() -> None:
    result = SemanticValidator().validate(_valid_document(), "1.7")

    assert result.is_valid
    assert result.messages == []
