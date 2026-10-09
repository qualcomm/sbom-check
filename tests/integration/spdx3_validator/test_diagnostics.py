# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Integration tests for SPDX 3 SHACL diagnostic translation."""

import json
from pathlib import Path

import pytest
from spdx3_validate import validate

from spdx3_validator.diagnostics import ShaclDiagnosticParser


def _shacl_messages(document: dict, path: Path) -> list:
    """Validate a document and translate only its SHACL errors."""
    path.write_text(json.dumps(document), encoding="utf-8")
    result = validate(str(path), version="3.0.1")
    return [
        ShaclDiagnosticParser.parse_shacl_error(error.message)
        for error in result.errors
        if error.kind == "shacl"
    ]


@pytest.mark.integration
class TestShaclDiagnosticParser:
    """Integration tests for SHACL diagnostic translation."""

    def test_parser_translates_mincount_constraint(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Translate a missing required property."""
        document = minimal_spdx3_document
        document["@graph"][1].pop("createdBy")

        messages = _shacl_messages(document, tmp_path / "mincount-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_mincount_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "createdBy"
        assert message.found_value == "-"
        assert message.expected_value == "at least 1 value(s)"
        assert message.message == (
            "The 'createdBy' property must contain at least 1 value(s)."
        )
        assert message.remediation == "Provide at least 1 value(s)."

    def test_parser_translates_maxcount_constraint(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Translate a property with too many values."""
        document = minimal_spdx3_document
        document["@graph"][2]["name"] = ["a", "b"]

        messages = _shacl_messages(document, tmp_path / "maxcount-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_maxcount_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "name"
        assert message.found_value == "-"
        assert message.expected_value == "at most 1 value(s)"
        assert message.message == (
            "The 'name' property must contain at most 1 value(s)."
        )
        assert message.remediation == "Provide at most 1 value(s)."

    def test_parser_translates_pattern_constraint(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Translate a value that does not match a required pattern."""
        document = minimal_spdx3_document
        document["@graph"][1]["created"] = "not-a-date"

        messages = _shacl_messages(document, tmp_path / "pattern-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_pattern_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "created"
        assert message.found_value == (
            '"not-a-date"^^<http://www.w3.org/2001/XMLSchema#dateTimeStamp>'
        )
        assert message.expected_value == r"^\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ$"
        assert message.message == (
            "The 'created' value does not match the required pattern."
        )
        assert message.remediation == (
            "Provide a value that matches the required SPDX format."
        )

    def test_parser_translates_datatype_constraint(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Translate a value with an invalid datatype."""
        document = minimal_spdx3_document
        document["@graph"][2]["name"] = 123

        messages = _shacl_messages(document, tmp_path / "datatype-diagnostic.spdx.json")

        assert len(messages) == 1
        message = messages[0]
        assert message.rule_id == "spdx3_shacl_datatype_constraint"
        assert message.section_reference == "SPDX 3.0.1 SHACL validation"
        assert message.field_path == "name"
        assert message.found_value == (
            '"123"^^<http://www.w3.org/2001/XMLSchema#string>'
        )
        assert message.expected_value == "xsd:string"
        assert message.message == "The 'name' value must have datatype xsd:string."
        assert message.remediation == "Provide a value with datatype xsd:string."

    def test_parser_translates_node_kind_from_source_shape(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Use the source shape's node kind in the translated diagnostic."""
        document = minimal_spdx3_document
        package = next(
            node
            for node in document["@graph"]
            if node.get("type") == "software_Package"
        )
        package["software_packageVersion"] = {"@id": "https://example.com/version"}

        messages = _shacl_messages(
            document, tmp_path / "node-kind-diagnostic.spdx.json"
        )

        message = next(
            message
            for message in messages
            if message.rule_id == "spdx3_shacl_node_kind_constraint"
        )
        assert message.field_path == "packageVersion"
        assert message.expected_value == "Literal"
        assert message.message == "The 'packageVersion' value must be a literal value."
        assert message.remediation == "Provide a value that is a literal value."

    def test_parser_preserves_unstructured_shacl_error(self):
        """Retain check_graph errors that do not have a SHACL result header."""
        raw_message = (
            "ERROR: https://example.com/imported in an ExternalMap and also "
            "defined in the document"
        )

        message = ShaclDiagnosticParser.parse_shacl_error(raw_message)

        assert message.message == raw_message
        assert message.rule_id == "spdx3_shacl_generic_violation_constraint"
        assert message.field_path is None
        assert message.affected_element is None

    def test_parser_normalizes_unhandled_constraint_rule_id(self):
        """Convert an unhandled SHACL component name to the standard rule ID."""
        error_text = """\
            Violation of type sh:QualifiedValueShapeConstraintComponent:
            \tMessage: Value does not conform to the qualified value shape
            """

        message = ShaclDiagnosticParser.parse_shacl_error(error_text)

        assert message.rule_id == "spdx3_shacl_qualified_value_shape_constraint"

    def test_parser_translates_repeated_class_constraints(
        self, tmp_path: Path, minimal_spdx3_document: dict
    ):
        """Preserve the current specialized translation for repeated class errors."""
        document = minimal_spdx3_document
        document["@graph"][2]["type"] = "NotAnAgent"

        messages = _shacl_messages(document, tmp_path / "class-diagnostic.spdx.json")

        assert len(messages) == 2
        assert {message.affected_element for message in messages} == {
            "_:ci",
            "_:ci2",
        }
        for message in messages:
            assert message.rule_id == "spdx3_shacl_class_constraint"
            assert message.section_reference == "SPDX 3.0.1 SHACL validation"
            assert message.message == (
                "The 'createdBy' value must reference an SPDX Agent element."
            )
            assert message.field_path == "createdBy"
            assert message.found_value == "https://example.com/agent"
            assert message.expected_value == "SPDX Agent"
            assert message.remediation == (
                "Provide a reference to an SPDX Agent element and ensure the "
                "referenced element has the required type."
            )
