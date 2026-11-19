# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Relationship and reachability completeness rules for SPDX 3.0.1."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sbom_check.profile.rules_spdx3._common import (
    _DEPENDENCY_RELATIONSHIP_TYPES,
    _MULTI_PACKAGE_THRESHOLD,
    _SPDX_3_0_1,
    _as_str_list,
    _message,
)
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.models import ValidationMessage
    from sbom_check.profile.registry import RuleContext
    from sbom_check.profile.spdx3_model import Spdx3Relationship


class DocumentDescribesRule:
    """The document's ``rootElement`` or ``describes`` link must resolve."""

    rule_id = "spdx3_completeness.document_describes"
    description = (
        "The SpdxDocument must have a rootElement, or a Relationship of type "
        "describes originating from it, that resolves to an element in the "
        "document."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate document-describes completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: An empty list if at least one
            ``rootElement`` value or ``describes`` relationship target
            resolves to an element in the ``@graph``. Otherwise one
            finding, worded differently for "nothing is declared" and
            "something is declared but none of it resolves".
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        targets = [
            *_as_str_list(spdx_doc.get("rootElement")),
            *(
                to_id
                for rel in doc.relationships_from(spdx_doc.element_id, "describes")
                for to_id in rel.to_ids
            ),
        ]
        if any(doc.element_by_id(target) is not None for target in targets):
            return []
        path = spdx_doc.element_path()
        declared = bool(targets) or doc.has_relationship(
            spdx_doc.element_id, "describes"
        )
        if declared:
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {path} declares a rootElement or "
                        "describes relationship, but none of its targets is "
                        "present in the document."
                    ),
                    field_path=path,
                    remediation=(
                        "Point rootElement, or the describes relationship's "
                        "to, at an element defined in the document's @graph."
                    ),
                    section_reference="Relationships",
                    found_value=targets or None,
                )
            ]
        return [
            _message(
                rule_id=self.rule_id,
                message=(
                    f"SpdxDocument {path} declares neither a rootElement nor "
                    "a describes relationship."
                ),
                field_path=path,
                remediation=(
                    "Set rootElement on the SpdxDocument, or add a "
                    "Relationship element with relationshipType describes "
                    "originating from the document."
                ),
                section_reference="Relationships",
            )
        ]


class NoIsolatedElementsRule:
    """Every software artifact must be reachable from the ``SpdxDocument``.

    The checked types are ``software_Package``, ``software_File`` and
    ``software_Snippet`` -- the SPDX 3.0.1 counterparts of the 2.3
    packages, files and snippets the 2.3 isolated-element requirement is
    about. Other element types are exempt on purpose, because SPDX 3.0.1
    links them through properties rather than ``Relationship`` chains and
    a relationship walk would report valid documents: agents are reached
    via ``createdBy``/``suppliedBy``/``originatedBy``, licenses via
    ``dataLicense`` and license-set ``member``, ``CreationInfo`` via
    ``creationInfo``, and ``SpdxDocument`` and ``Relationship`` elements
    are the root and the edges of the walk themselves.
    """

    rule_id = "spdx3_completeness.no_isolated_elements"
    description = (
        "Every software_Package, software_File and software_Snippet element "
        "must be reachable from the SpdxDocument via rootElement or a "
        "Relationship chain."
    )
    _CHECKED_TYPES = ("software_Package", "software_File", "software_Snippet")
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate graph reachability from the SpdxDocument.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package, file or
            snippet element that is not reachable from the ``SpdxDocument``
            through ``rootElement`` plus a breadth-first walk of
            outgoing ``Relationship`` ``to`` edges; otherwise an empty
            list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []

        reachable: set[str] = set(_as_str_list(spdx_doc.get("rootElement")))
        queue: list[str] = list(reachable)
        for rel in doc.relationships_from(spdx_doc.element_id):
            for to_id in rel.to_ids:
                if to_id not in reachable:
                    reachable.add(to_id)
                    queue.append(to_id)

        while queue:
            current = queue.pop()
            for rel in doc.relationships_from(current):
                for to_id in rel.to_ids:
                    if to_id not in reachable:
                        reachable.add(to_id)
                        queue.append(to_id)

        messages: list[ValidationMessage] = []
        for element in doc.elements_of_type(*self._CHECKED_TYPES):
            if element.element_id is not None and element.element_id in reachable:
                continue
            path = element.element_path()
            messages.append(
                _message(
                    rule_id=self.rule_id,
                    message=f"Element {path} is not reachable from the SpdxDocument.",
                    field_path=path,
                    remediation=(
                        "List this element under rootElement, or link it "
                        "into the document via a chain of Relationship "
                        "elements starting from the SpdxDocument."
                    ),
                    section_reference="Relationships",
                )
            )
        return messages


class DependencyRelationshipsRule:
    """A multi-package document must relate its packages to each other.

    The matrix's structural mapping is clear -- a flat list of 2.3
    relationship entries becomes ``Relationship`` elements with
    ``relationshipType`` ``contains`` or ``dependsOn`` -- but enforcing
    it by default is new: 2.3 never enforced this, since
    ``RelationshipRequirementsConfig.required_relationships`` ships
    empty in ``create_default()``. A document with zero or one package
    has nothing to relate and passes; a document with two or more
    packages must have at least one ``contains`` or ``dependsOn``
    relationship whose ``from`` resolves to a package and whose ``to``
    includes a different package. Relationships with no target, dangling
    endpoints, or non-package endpoints do not count. This is reported
    once at the document level, not once per package.
    """

    rule_id = "spdx3_completeness.dependency_relationships"
    description = (
        "A document with two or more packages must have at least one "
        "contains or dependsOn Relationship from a package to a different "
        "package."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate dependency-relationship completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A single document-level finding if
            two or more packages exist and no ``contains``/``dependsOn``
            relationship links one package to a different package;
            otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        packages = doc.packages()
        if len(packages) < _MULTI_PACKAGE_THRESHOLD:
            return []
        if any(
            self._links_packages(doc, relationship)
            for relationship in doc.relationships()
        ):
            return []
        if (spdx_doc := doc.spdx_document()) is not None:
            path = spdx_doc.element_path()
        else:
            path = "@graph"
        return [
            _message(
                rule_id=self.rule_id,
                message=(
                    "Document declares multiple packages but has no contains "
                    "or dependsOn relationship from one package to another, "
                    "so it does not convey how the components relate to each "
                    "other."
                ),
                field_path=path,
                remediation=(
                    "Add a Relationship element with relationshipType "
                    "contains or dependsOn from one package to another."
                ),
                section_reference="Relationships",
            )
        ]

    @staticmethod
    def _links_packages(doc: Spdx3Document, relationship: Spdx3Relationship) -> bool:
        """Check whether a relationship links a package to a different package.

        Args:
            doc: The document adapter used to resolve endpoints.
            relationship: The relationship to inspect.

        Returns:
            bool: True if it is ``contains``/``dependsOn``, its ``from``
            resolves to a package, and some ``to`` resolves to a package
            with a different id.
        """
        if relationship.relationship_type not in _DEPENDENCY_RELATIONSHIP_TYPES:
            return False
        source = doc.element_by_id(relationship.from_id)
        if source is None or not source.is_type("software_Package"):
            return False
        for to_id in relationship.to_ids:
            if to_id == relationship.from_id:
                continue
            target = doc.element_by_id(to_id)
            if target is not None and target.is_type("software_Package"):
                return True
        return False
