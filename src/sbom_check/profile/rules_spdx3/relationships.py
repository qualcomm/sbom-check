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


class DocumentDescribesRule:
    """The document must declare a ``rootElement`` or a ``describes`` link."""

    rule_id = "spdx3_completeness.document_describes"
    description = (
        "The SpdxDocument must have a non-empty rootElement, or a "
        "Relationship of type describes originating from it."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate document-describes completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if neither a non-empty
            ``rootElement`` nor a ``describes`` relationship is
            present; otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        if _as_str_list(spdx_doc.get("rootElement")):
            return []
        if doc.has_relationship(spdx_doc.element_id, "describes"):
            return []
        path = spdx_doc.element_path()
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
    """Every package and file must be reachable from the ``SpdxDocument``."""

    rule_id = "spdx3_completeness.no_isolated_elements"
    description = (
        "Every software_Package and software_File element must be "
        "reachable from the SpdxDocument via rootElement or a Relationship "
        "chain."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate graph reachability from the SpdxDocument.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package/file
            element that is not reachable from the ``SpdxDocument``
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
        for element in (*doc.packages(), *doc.files()):
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
    relationship somewhere in the graph. This is reported once at the
    document level, not once per package.
    """

    rule_id = "spdx3_completeness.dependency_relationships"
    description = (
        "A document with two or more packages must have at least one "
        "contains or dependsOn Relationship connecting them."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate dependency-relationship completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A single document-level finding if
            two or more packages exist and none are linked by a
            ``contains``/``dependsOn`` relationship; otherwise an empty
            list.
        """
        doc = Spdx3Document.from_dict(document)
        packages = doc.packages()
        if len(packages) < _MULTI_PACKAGE_THRESHOLD:
            return []
        for relationship in doc.relationships():
            if relationship.relationship_type in _DEPENDENCY_RELATIONSHIP_TYPES:
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
                    "or dependsOn relationship, so it does not convey how "
                    "the components relate to each other."
                ),
                field_path=path,
                remediation=(
                    "Add a Relationship element with relationshipType "
                    "contains or dependsOn between related packages."
                ),
                section_reference="Relationships",
            )
        ]
