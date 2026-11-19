# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3.0.1 typed element graph adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

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


@pytest.mark.parametrize(
    "raw_relationship_type",
    [
        "describes",
        "spdx:Core/RelationshipType/describes",
        "https://spdx.org/rdf/3.0.1/terms/Core/RelationshipType/describes",
    ],
)
def test_relationship_type_is_normalized_across_iri_spellings(
    raw_relationship_type: str,
) -> None:
    """relationshipType is IRI-valued, so every conforming spelling must match.

    A document that writes the expanded IRI (or the spdx:-prefixed form)
    is just as conformant as one using the short JSON-LD term. Comparing
    the raw string would make rules miss the relationship entirely.
    """
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "Relationship",
                    "spdxId": "r1",
                    "from": "a",
                    "relationshipType": raw_relationship_type,
                    "to": ["b"],
                }
            ]
        }
    )

    [rel] = doc.relationships()
    assert rel.relationship_type == "describes"
    assert doc.has_relationship("a", "describes") is True


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


def test_duplicate_ids_are_reported_and_do_not_resolve() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "software_Package", "spdxId": "urn:x:dup", "name": "a"},
                {"type": "software_Package", "spdxId": "urn:x:dup", "name": "b"},
                {"type": "software_Package", "spdxId": "urn:x:one", "name": "c"},
            ]
        }
    )

    duplicates = doc.duplicate_ids()
    assert set(duplicates) == {"urn:x:dup"}
    assert [e.get("name") for e in duplicates["urn:x:dup"]] == ["a", "b"]
    assert doc.element_by_id("urn:x:dup") is None
    assert doc.element_by_id("urn:x:one") is not None


def test_creation_info_for_rejects_non_creation_info_reference() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "SpdxDocument",
                    "spdxId": "urn:x:doc",
                    "creationInfo": "urn:x:pkg",
                },
                {
                    "type": "software_Package",
                    "spdxId": "urn:x:pkg",
                    "created": "2026-01-15T00:00:00Z",
                    "specVersion": "3.0.1",
                },
            ]
        }
    )
    spdx_doc = doc.spdx_document()
    assert spdx_doc is not None

    assert doc.creation_info_for(spdx_doc) is None
    assert doc.creation_info_is_wrong_type(spdx_doc) is True


def test_creation_info_is_wrong_type_false_when_dangling_or_absent() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {"type": "software_Package", "spdxId": "a", "creationInfo": "_:x"},
                {"type": "software_Package", "spdxId": "b"},
            ]
        }
    )
    first, second = doc.elements

    assert doc.creation_info_is_wrong_type(first) is False
    assert doc.creation_info_is_wrong_type(second) is False


SPDX_TERMS = "https://spdx.org/rdf/3.0.1/terms/"


@pytest.mark.parametrize(
    "raw_type",
    [
        "cpe23",
        "spdx:Core/ExternalIdentifierType/cpe23",
        f"{SPDX_TERMS}Core/ExternalIdentifierType/cpe23",
    ],
)
def test_external_identifier_type_is_normalized(raw_type: str) -> None:
    """externalIdentifierType is reduced to its short enum member."""
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "software_Package",
                    "spdxId": "a",
                    "externalIdentifier": {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": raw_type,
                        "identifier": "cpe:2.3:a:x:y:1.0",
                    },
                }
            ]
        }
    )

    [identifier] = doc.external_identifiers(doc.elements[0])
    assert identifier.identifier_type == "cpe23"


def test_compact_and_expanded_ids_index_to_one_key() -> None:
    """spdx: ids are indexed expanded and found by either spelling."""
    doc = Spdx3Document.from_dict(
        {"@graph": [{"type": "Organization", "spdxId": "spdx:CustomAgent"}]}
    )

    [element] = doc.elements
    assert element.element_id == f"{SPDX_TERMS}CustomAgent"
    assert doc.element_by_id("spdx:CustomAgent") is element
    assert doc.element_by_id(f"{SPDX_TERMS}CustomAgent") is element


def test_relationship_endpoints_are_expanded() -> None:
    doc = Spdx3Document.from_dict(
        {
            "@graph": [
                {
                    "type": "Relationship",
                    "spdxId": "r1",
                    "from": "spdx:a",
                    "relationshipType": "describes",
                    "to": ["spdx:b", "_:c", "urn:x:y"],
                }
            ]
        }
    )

    [rel] = doc.relationships()
    assert rel.from_id == f"{SPDX_TERMS}a"
    assert rel.to_ids == (f"{SPDX_TERMS}b", "_:c", "urn:x:y")
    assert doc.has_relationship(f"{SPDX_TERMS}a", "describes") is True
    assert doc.has_relationship("spdx:a", "describes") is True


@pytest.mark.parametrize(
    ("context", "expected"),
    [
        ({"ex": "https://example.test/"}, "https://example.test/a"),
        (
            {"ex": {"@id": "https://example.test/", "@prefix": True}},
            "https://example.test/a",
        ),
        # Not a prefix: the IRI does not end in a gen-delim and @prefix is unset.
        ({"ex": "https://example.test/x"}, "ex:a"),
        ({"ex": {"@id": "https://example.test/"}}, "ex:a"),
    ],
)
def test_document_context_prefixes(context: dict, expected: str) -> None:
    doc = Spdx3Document.from_dict(
        {
            "@context": ["https://spdx.org/rdf/3.0.1/spdx-context.jsonld", context],
            "@graph": [],
        }
    )

    assert doc.canonical_id("ex:a") == expected


def test_cleared_spdx_prefix_is_not_expanded() -> None:
    doc = Spdx3Document.from_dict({"@context": [{"spdx": None}], "@graph": []})

    assert doc.canonical_id("spdx:a") == "spdx:a"


@pytest.mark.parametrize(
    "value", ["https://example.test/a", "_:b0", "urn:uuid:1234", "plain"]
)
def test_non_compact_ids_are_unchanged(value: str) -> None:
    """Absolute IRIs, blank nodes and unprefixed strings pass through.

    A term named like a scheme does not rewrite ``scheme://`` IRIs, and
    ``_`` is reserved for blank nodes (JSON-LD 1.1 section 4.1.3).
    """
    doc = Spdx3Document.from_dict(
        {
            "@context": [{"https": "https://evil.test/", "_": "https://evil.test/"}],
            "@graph": [],
        }
    )

    assert doc.canonical_id(value) == value
