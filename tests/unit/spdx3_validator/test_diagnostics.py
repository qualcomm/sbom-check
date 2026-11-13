# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for SPDX 3 SHACL diagnostic translation."""

from spdx3_validator.diagnostics import ShaclDiagnosticParser


def test_parser_translates_node_level_datatype_constraint():
    """Keep the wording for datatype constraints without a result path."""
    error_text = """\
    Violation of type sh:DatatypeConstraintComponent:
        Focus Node: <https://example.com/package/example>
        Value Node: "123"
        Result path: -
        Source Shape:
            sh:datatype xsd:string ;
        Message: Value does not have datatype xsd:string
    """

    message = ShaclDiagnosticParser.parse_shacl_error(error_text)

    assert message.rule_id == "spdx3_shacl_datatype_constraint"
    assert message.field_path is None
    assert message.affected_element == "https://example.com/package/example"
    assert message.expected_value == "xsd:string"
    assert message.message == "The property value must have datatype xsd:string."
    assert message.remediation == "Provide a value with datatype xsd:string."
