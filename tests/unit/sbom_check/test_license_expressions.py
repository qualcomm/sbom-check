# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SPDX license-expression validation in SbomCheckEngine.

The license expressions live in ``tests/fixtures/spdx/license_expressions.json``
rather than in this module, so the copyright/license checker does not mistake
them for license declarations.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from sbom_check.engine import SbomCheckEngine
from sbom_check.models import SbomCheckResult, ValidationSeverity

FIXTURE = Path(__file__).parents[2] / "fixtures" / "spdx" / "license_expressions.json"
EXAMPLES = Path(__file__).parents[3] / "examples"
_DATA = json.loads(FIXTURE.read_text(encoding="utf-8"))
CASES = _DATA["cases"]
VALUES = _DATA["values"]
RULE_ID = "invalid_license_expression"


def _new_result() -> SbomCheckResult:
    return SbomCheckResult(overall_valid=True, spdx_valid=True, profile_valid=True)


def _license_errors(result: SbomCheckResult) -> list[Any]:
    return [msg for msg in result.messages if msg.rule_id == RULE_ID]


@pytest.mark.parametrize("case", CASES, ids=[case["id"] for case in CASES])
def test_license_expression_error(case):
    """Each fixture expression is accepted or rejected with the expected kind."""
    engine = SbomCheckEngine()

    detail = engine._license_expression_error(
        case["expression"],
        set(case.get("declared", [])),
        set(case.get("external", [])),
    )

    if (expected := case["expected"]) is None:
        assert detail is None
        return
    assert detail is not None
    if expected != "invalid":
        assert detail.startswith(f"{expected}:"), detail
    if contains := case.get("detail_contains"):
        assert contains in detail


def test_validate_package_licenses_reports_invalid_fields():
    """Invalid licenseConcluded/licenseDeclared values produce errors."""
    engine = SbomCheckEngine()
    result = _new_result()

    package = {
        "SPDXID": "SPDXRef-Package-0",
        "licenseConcluded": VALUES["valid"],
        "licenseDeclared": VALUES["free_text"],
    }
    engine._validate_package_licenses(package, 0, set(), set(), result)

    errors = _license_errors(result)
    assert len(errors) == 1
    assert "licenseDeclared" in errors[0].field_path


def test_validate_package_licenses_skips_missing_fields():
    """Packages without license fields produce no license errors."""
    engine = SbomCheckEngine()
    result = _new_result()

    engine._validate_package_licenses(
        {"SPDXID": "SPDXRef-Package-0"}, 0, set(), set(), result
    )

    assert not result.messages


def test_validate_package_licenses_reports_non_string_value():
    """A non-string license value is reported as a type error, not a bad symbol."""
    engine = SbomCheckEngine()
    result = _new_result()

    package = {"SPDXID": "SPDXRef-Package-0", "licenseConcluded": VALUES["non_string"]}
    engine._validate_package_licenses(package, 0, set(), set(), result)

    errors = _license_errors(result)
    assert len(errors) == 1
    assert "must be a string" in errors[0].message


@pytest.mark.parametrize(
    "value_key", ["lowercase_operator", "lowercase_operator_before_paren"]
)
def test_validate_package_licenses_warns_on_lowercase_operator(value_key):
    """A valid expression with lowercase operators yields a WARNING, not an ERROR."""
    engine = SbomCheckEngine()
    result = _new_result()

    package = {"SPDXID": "SPDXRef-Package-0", "licenseConcluded": VALUES[value_key]}
    engine._validate_package_licenses(package, 0, set(), set(), result)

    assert not _license_errors(result)
    warnings = [
        msg for msg in result.messages if msg.rule_id == "lowercase_license_operator"
    ]
    assert len(warnings) == 1
    assert warnings[0].severity == ValidationSeverity.WARNING


def test_validate_package_requirements_validates_licenses_in_default_profile():
    """The default profile flags invalid license expressions on packages."""
    engine = SbomCheckEngine()  # default profile
    result = _new_result()

    spdx_data = {
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-0",
                "name": "pkg",
                "licenseConcluded": VALUES["free_text_with_space"],
                "licenseDeclared": VALUES["declared_license_ref"],
            }
        ],
        "hasExtractedLicensingInfos": [{"licenseId": VALUES["declared_license_ref"]}],
    }
    engine._validate_package_requirements(spdx_data, result)

    license_errors = _license_errors(result)
    # Only the free-text licenseConcluded is invalid; the declared ref is fine.
    assert len(license_errors) == 1
    assert "licenseConcluded" in license_errors[0].field_path


def test_validate_package_requirements_accepts_external_document_ref():
    """A DocumentRef- declared in externalDocumentRefs is accepted end-to-end."""
    engine = SbomCheckEngine()  # default profile
    result = _new_result()

    document_ref = VALUES["document_ref"]
    spdx_data = {
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-0",
                "name": "pkg",
                "licenseConcluded": document_ref,
            }
        ],
        "externalDocumentRefs": [{"externalDocumentId": document_ref.split(":")[0]}],
    }
    engine._validate_package_requirements(spdx_data, result)

    assert not _license_errors(result)


@pytest.mark.parametrize(
    "bad", [None, {"not": "a list"}, [{"licenseId": ["a"]}], ["string"]]
)
def test_validate_package_requirements_tolerates_malformed_extracted_infos(bad):
    """Malformed hasExtractedLicensingInfos must not crash (default profile)."""
    engine = SbomCheckEngine()  # default profile, flag on
    result = _new_result()

    spdx_data = {
        "packages": [
            {"SPDXID": "SPDXRef-Package-0", "licenseDeclared": VALUES["valid"]}
        ],
        "hasExtractedLicensingInfos": bad,
    }
    # Must not raise.
    engine._validate_package_requirements(spdx_data, result)

    assert not _license_errors(result)


def test_validate_package_requirements_basic_profile_skips_and_tolerates():
    """basic_spdx (flag off) emits no license messages and never crashes on bad input."""
    engine = SbomCheckEngine(profile_name="basic_spdx")
    result = _new_result()

    spdx_data = {
        "packages": [
            {"SPDXID": "SPDXRef-Package-0", "licenseDeclared": VALUES["free_text"]}
        ],
        # Malformed values that would crash if the feature touched them.
        "hasExtractedLicensingInfos": None,
        "externalDocumentRefs": {"bad": "shape"},
    }
    engine._validate_package_requirements(spdx_data, result)

    assert not _license_errors(result)


def test_validate_file_reports_invalid_license_expression_in_example():
    """The public validate_file API reports the rule for the invalid example."""
    result = SbomCheckEngine().validate_file(EXAMPLES / "sample-invalid.spdx.json")

    assert not result.overall_valid
    fields = {msg.field_path for msg in _license_errors(result)}
    assert fields == {
        "packages[0].licenseConcluded",
        "packages[0].licenseDeclared",
    }


def test_validate_file_accepts_license_expressions_in_valid_example():
    """The valid example produces no invalid_license_expression messages."""
    result = SbomCheckEngine().validate_file(EXAMPLES / "sample-valid.spdx.json")

    assert not _license_errors(result)
