# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3.0.1 typed element graph adapter."""

from __future__ import annotations

import json
from pathlib import Path

from sbom_check.profile.spdx3_model import Spdx3Document

FIXTURE_PATH = (
    Path(__file__).resolve().parents[3] / "fixtures" / "spdx3" / "complete.spdx.json"
)


def _load_fixture() -> dict:
    with FIXTURE_PATH.open(encoding="utf-8") as handle:
        return json.load(handle)


def test_fixture_finds_document_package_agent_and_relationships() -> None:
    doc = Spdx3Document.from_dict(_load_fixture())

    assert len(doc.elements_of_type("SpdxDocument")) == 1
    assert len(doc.packages()) == 1
    assert len(doc.elements_of_type("Organization")) == 1
    assert len(doc.relationships()) == 3


def test_fixture_spdx_document_and_package_accessors() -> None:
    doc = Spdx3Document.from_dict(_load_fixture())

    spdx_doc = doc.spdx_document()
    assert spdx_doc is not None
    assert spdx_doc.element_id == "https://qualcomm.example/spdx/doc-complete"

    [package] = doc.packages()
    assert package.get("name") == "libwidget"


def test_type_key_and_at_type_key_both_recognized() -> None:
    doc_type = Spdx3Document.from_dict(
        {"@graph": [{"type": "software_Package", "spdxId": "a"}]}
    )
    doc_at_type = Spdx3Document.from_dict(
        {"@graph": [{"@type": "software_Package", "spdxId": "a"}]}
    )

    assert doc_type.elements[0].element_type == "software_Package"
    assert doc_at_type.elements[0].element_type == "software_Package"


def test_spdxid_key_and_at_id_key_both_recognized() -> None:
    doc_spdxid = Spdx3Document.from_dict(
        {"@graph": [{"type": "Agent", "spdxId": "https://x/a"}]}
    )
    doc_at_id = Spdx3Document.from_dict(
        {"@graph": [{"type": "Agent", "@id": "https://x/a"}]}
    )

    assert doc_spdxid.elements[0].element_id == "https://x/a"
    assert doc_at_id.elements[0].element_id == "https://x/a"


def test_full_iri_type_normalizes_to_short_form() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "https://spdx.org/rdf/3.0.1/terms/Software/Package",
                    "spdxId": "a",
                }
            ]
        }
    )

    assert doc.elements[0].element_type == "software_Package"


def test_spdx_prefixed_type_normalizes_correctly() -> None:
    doc = Spdx3Document.from_dict(
        {"@graph": [{"type": "spdx:Software/Package", "spdxId": "a"}]}
    )

    assert doc.elements[0].element_type == "software_Package"


def test_core_iri_type_drops_core_namespace() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "https://spdx.org/rdf/3.0.1/terms/Core/Agent", "spdxId": "a"}
            ]
        }
    )

    assert doc.elements[0].element_type == "Agent"


def test_list_valued_type_yields_all_types() -> None:
    doc = Spdx3Document.from_dict(
        {"@graph": [{"type": ["software_Package", "Agent"], "spdxId": "a"}]}
    )

    element = doc.elements[0]
    assert element.element_types == ("software_Package", "Agent")
    assert element.is_type("Agent")
    assert element.is_type("software_Package", "Nope")


def test_creation_info_for_resolves_blank_node() -> None:
    doc = Spdx3Document.from_dict(_load_fixture())
    [package] = doc.packages()

    creation_info = doc.creation_info_for(package)
    assert creation_info is not None
    assert creation_info.is_type("CreationInfo")
    assert creation_info.get("specVersion") == "3.0.1"


def test_creation_info_for_returns_none_when_dangling() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "a",
                    "creationInfo": "_:missing",
                }
            ]
        }
    )
    element = doc.elements[0]

    assert doc.creation_info_for(element) is None


def test_creation_info_for_wraps_inline_dict() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "a",
                    "creationInfo": {"type": "CreationInfo", "specVersion": "3.0.1"},
                }
            ]
        }
    )
    element = doc.elements[0]

    creation_info = doc.creation_info_for(element)
    assert creation_info is not None
    assert creation_info.get("specVersion") == "3.0.1"


def test_relationships_from_filters_by_type_and_has_relationship() -> None:
    doc = Spdx3Document.from_dict(_load_fixture())
    pkg_id = "https://qualcomm.example/spdx/pkg/libwidget"

    concluded = doc.relationships_from(pkg_id, "hasConcludedLicense")
    assert len(concluded) == 1
    assert concluded[0].to_ids == ("https://qualcomm.example/spdx/license/apache",)

    all_from_pkg = doc.relationships_from(pkg_id)
    assert len(all_from_pkg) == 2

    assert doc.has_relationship(pkg_id, "hasDeclaredLicense") is True
    assert doc.has_relationship(pkg_id, "dependsOn") is False
    assert doc.has_relationship(None, "describes") is False


def test_relationship_to_as_bare_string_is_accepted() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "Relationship",
                    "spdxId": "r1",
                    "from": "a",
                    "relationshipType": "describes",
                    "to": "b",
                }
            ]
        }
    )

    [rel] = doc.relationships()
    assert rel.to_ids == ("b",)


def test_external_identifiers_inline_dict_form() -> None:
    doc = Spdx3Document.from_dict(_load_fixture())
    [package] = doc.packages()

    identifiers = doc.external_identifiers(package)
    assert len(identifiers) == 1
    assert identifiers[0].identifier_type == "packageUrl"
    assert identifiers[0].identifier == "pkg:generic/libwidget@2.4.1"


def test_external_identifiers_list_of_dicts_form() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "a",
                    "externalIdentifier": [
                        {
                            "type": "ExternalIdentifier",
                            "externalIdentifierType": "cpe23",
                            "identifier": "cpe:2.3:a:x:y:1.0",
                        },
                        {
                            "type": "ExternalIdentifier",
                            "externalIdentifierType": "cve",
                            "identifier": "CVE-2026-0001",
                        },
                    ],
                }
            ]
        }
    )
    element = doc.elements[0]

    identifiers = doc.external_identifiers(element)
    assert [i.identifier_type for i in identifiers] == ["cpe23", "cve"]


def test_external_identifiers_iri_reference_form() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "a",
                    "externalIdentifier": ["https://x/extid-1"],
                },
                {
                    "type": "ExternalIdentifier",
                    "spdxId": "https://x/extid-1",
                    "externalIdentifierType": "swid",
                    "identifier": "swid-123",
                },
            ]
        }
    )
    package = doc.elements[0]

    identifiers = doc.external_identifiers(package)
    assert len(identifiers) == 1
    assert identifiers[0].identifier_type == "swid"
    assert identifiers[0].identifier == "swid-123"


def test_resolve_agent_distinguishes_absent_vs_dangling() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "software_Package", "spdxId": "no-supplier"},
                {
                    "type": "software_Package",
                    "spdxId": "dangling-supplier",
                    "suppliedBy": "https://x/missing-agent",
                },
                {
                    "type": "software_Package",
                    "spdxId": "ok-supplier",
                    "suppliedBy": "https://x/agent-1",
                },
                {"type": "Agent", "spdxId": "https://x/agent-1"},
            ]
        }
    )

    no_supplier = doc.element_by_id("no-supplier")
    dangling_supplier = doc.element_by_id("dangling-supplier")
    ok_supplier = doc.element_by_id("ok-supplier")
    assert no_supplier is not None
    assert dangling_supplier is not None
    assert ok_supplier is not None

    # Absent: no value stated at all.
    assert doc.resolve_agent(no_supplier, "suppliedBy") is None
    assert doc.reference_is_dangling(no_supplier, "suppliedBy") is False

    # Dangling: a reference is stated but does not resolve.
    assert doc.resolve_agent(dangling_supplier, "suppliedBy") is None
    assert doc.reference_is_dangling(dangling_supplier, "suppliedBy") is True

    # Resolves successfully.
    resolved = doc.resolve_agent(ok_supplier, "suppliedBy")
    assert resolved is not None
    assert resolved.element_id == "https://x/agent-1"
    assert doc.reference_is_dangling(ok_supplier, "suppliedBy") is False


def test_element_path_returns_id_or_graph_index() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "Agent", "spdxId": "https://x/a"},
                {"type": "CreationInfo"},
            ]
        }
    )

    assert doc.elements[0].element_path() == "https://x/a"
    assert doc.elements[1].element_path() == "@graph[1]"


def test_robustness_empty_document() -> None:
    doc = Spdx3Document.from_dict({})
    assert doc.elements == ()
    assert doc.packages() == []
    assert doc.spdx_document() is None


def test_robustness_graph_none() -> None:
    doc = Spdx3Document.from_dict({"@graph": None})
    assert doc.elements == ()


def test_robustness_graph_nonsense_string() -> None:
    doc = Spdx3Document.from_dict({"@graph": "nonsense"})
    assert doc.elements == ()


def test_robustness_graph_with_non_dict_entries() -> None:
    doc = Spdx3Document.from_dict({"@graph": [None, 42, "x"]})
    assert doc.elements == ()


def test_robustness_graph_with_empty_dict_entry() -> None:
    doc = Spdx3Document.from_dict({"@graph": [{}]})
    assert len(doc.elements) == 1
    element = doc.elements[0]
    assert element.element_id is None
    assert element.element_type is None
    assert element.element_types == ()
    assert element.element_path() == "@graph[0]"


def test_robustness_none_document() -> None:
    doc = Spdx3Document.from_dict(None)  # type: ignore[arg-type]
    assert doc.elements == ()


def test_agents_includes_organization_person_and_tool() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "Agent", "spdxId": "a1"},
                {"type": "Organization", "spdxId": "a2"},
                {"type": "Person", "spdxId": "a3"},
                {"type": "Tool", "spdxId": "a4"},
                {"type": "software_Package", "spdxId": "p1"},
            ]
        }
    )

    agent_ids = {agent.element_id for agent in doc.agents()}
    assert agent_ids == {"a1", "a2", "a3", "a4"}
