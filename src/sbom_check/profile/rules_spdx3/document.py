# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Document-level Qualcomm completeness rules for SPDX 3.0.1."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from sbom_check.profile.rules_spdx3._common import (
    _AGENT_TYPES,
    _SPDX_3_0_1,
    _as_str_list,
    _is_absolute_iri,
    _is_license_list_version,
    _is_nonempty_str,
    _is_valid_timestamp,
    _LicenseReference,
    _message,
    _raw_element_id,
    _ReferenceProblem,
    _resolve_license_reference,
)
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.models import ValidationMessage
    from sbom_check.profile.registry import RuleContext
    from sbom_check.profile.spdx3_model import Spdx3Element


class DocumentNameRule:
    """``SpdxDocument.name`` must be present and non-empty."""

    rule_id = "spdx3_completeness.document_name"
    description = "SpdxDocument.name must be present and non-empty."
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate document-name completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A single finding if there is no
            ``SpdxDocument`` element or its ``name`` is missing/empty;
            otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return [
                _message(
                    rule_id=self.rule_id,
                    message="Document has no SpdxDocument element.",
                    field_path="@graph",
                    remediation=(
                        "Add an SpdxDocument element to the @graph with a "
                        "non-empty name."
                    ),
                    section_reference="Document metadata",
                )
            ]
        if _is_nonempty_str(spdx_doc.get("name")):
            return []
        return [
            _message(
                rule_id=self.rule_id,
                message=(
                    f"SpdxDocument {spdx_doc.element_path()} is missing a "
                    "non-empty name."
                ),
                field_path=spdx_doc.element_path(),
                remediation="Set a non-empty name on the SpdxDocument element.",
                section_reference="Document metadata",
            )
        ]


class DocumentIdentifierRule:
    """The document's ``spdxId`` must be a valid IRI and graph ids unique.

    Besides checking the ``SpdxDocument`` identifier itself, this rule
    reports every id defined by more than one ``@graph`` entry, because
    duplicates make every reference in the document ambiguous. Duplicates
    that involve a package are left to
    :class:`~sbom_check.profile.rules_spdx3.package.PackageIdentifierRule`
    so that each is reported once.
    """

    rule_id = "spdx3_completeness.document_identifier"
    description = (
        "SpdxDocument.spdxId (or its @id alias) must be present, non-empty, an absolute IRI, "
        "and must not contain a '#' fragment; every element id in the "
        "document must be unique."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate document-identifier completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if ``spdxId`` is
            missing/empty, not an absolute IRI, or contains a ``#``
            fragment; plus one finding per non-package id defined more
            than once. The SpdxDocument checks are skipped (rather than
            duplicated) when there is no ``SpdxDocument`` element at
            all -- :class:`DocumentNameRule` reports that.
        """
        doc = Spdx3Document.from_dict(document)
        messages = self._duplicate_id_messages(doc)
        if (spdx_doc := doc.spdx_document()) is not None:
            messages.extend(self._document_id_messages(spdx_doc, doc))
        return messages

    def _duplicate_id_messages(self, doc: Spdx3Document) -> list[ValidationMessage]:
        """Report ids defined by more than one non-package ``@graph`` entry.

        Args:
            doc: The document adapter.

        Returns:
            list[ValidationMessage]: One finding per duplicated id none
            of whose definitions is a package.
        """
        messages: list[ValidationMessage] = []
        for element_id, definitions in doc.duplicate_ids().items():
            if any(element.is_type("software_Package") for element in definitions):
                continue
            indexes = ", ".join(f"@graph[{e.graph_index}]" for e in definitions)
            messages.append(
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"Element id {element_id!r} is defined by "
                        f"{len(definitions)} @graph entries ({indexes}), so "
                        "references to it are ambiguous."
                    ),
                    field_path=f"@graph[{definitions[0].graph_index}]",
                    remediation="Give every element in the document its own unique id.",
                    section_reference="Identifiers",
                    found_value=element_id,
                )
            )
        return messages

    def _document_id_messages(
        self, spdx_doc: Spdx3Element, doc: Spdx3Document
    ) -> list[ValidationMessage]:
        """Check the SpdxDocument's own ``spdxId``.

        Args:
            spdx_doc: The SpdxDocument element.
            doc: The document adapter, used to expand a compact IRI so the
                fragment and absolute-IRI checks see the id references
                resolve against.

        Returns:
            list[ValidationMessage]: At most one finding for a missing,
            fragment-bearing, or non-IRI ``spdxId``.
        """
        id_key, spdx_id = _raw_element_id(spdx_doc)
        path = spdx_doc.element_path()
        if not _is_nonempty_str(spdx_id):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=f"SpdxDocument {path} is missing a non-empty spdxId (or @id).",
                    field_path=path,
                    remediation="Assign a globally unique absolute IRI as spdxId (or @id).",
                    section_reference="Document metadata",
                )
            ]
        expanded = doc.canonical_id(spdx_id)
        if "#" in expanded:
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {path} {id_key} {spdx_id!r} contains a "
                        "prohibited '#' fragment."
                    ),
                    field_path=path,
                    remediation="Remove the '#' fragment from the document spdxId (or @id).",
                    section_reference="Document metadata",
                    found_value=spdx_id,
                )
            ]
        if not _is_absolute_iri(expanded):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {path} {id_key} {spdx_id!r} is not an "
                        "absolute IRI."
                    ),
                    field_path=path,
                    remediation=(
                        "Use an absolute IRI (with a scheme or 'urn:' prefix) "
                        "as the document spdxId (or @id)."
                    ),
                    section_reference="Document metadata",
                    found_value=spdx_id,
                )
            ]
        return []


class CreationTimestampRule:
    """CreationInfo's ``created`` must be a valid ISO-8601 UTC instant."""

    rule_id = "spdx3_completeness.creation_timestamp"
    description = (
        "The document's CreationInfo.created must be present and match "
        "ISO-8601 UTC instant format."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate creation-timestamp completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding naming a missing
            CreationInfo distinctly from a missing or malformed
            ``created`` value; otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        if (creation_info := doc.creation_info_for(spdx_doc)) is None:
            if doc.creation_info_is_wrong_type(spdx_doc):
                return [
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"SpdxDocument {spdx_doc.element_path()} "
                            "creationInfo does not identify a CreationInfo "
                            "element."
                        ),
                        field_path=spdx_doc.element_path(),
                        remediation=(
                            "Point creationInfo at an element of type CreationInfo."
                        ),
                        section_reference="Document metadata",
                        found_value=spdx_doc.get("creationInfo"),
                    )
                ]
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {spdx_doc.element_path()} has no "
                        "resolvable CreationInfo."
                    ),
                    field_path=spdx_doc.element_path(),
                    remediation=(
                        "Add a CreationInfo element and reference it from creationInfo."
                    ),
                    section_reference="Document metadata",
                )
            ]
        created = creation_info.get("created")
        path = creation_info.element_path()
        if not _is_nonempty_str(created):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=f"CreationInfo {path} is missing a 'created' timestamp.",
                    field_path=path,
                    remediation="Set CreationInfo.created to an ISO-8601 UTC instant.",
                    section_reference="Document metadata",
                )
            ]
        if not _is_valid_timestamp(created):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"CreationInfo {path} created value {created!r} is "
                        "not a valid ISO-8601 UTC instant (UTC 'Z' format, "
                        "real calendar date and time of day)."
                    ),
                    field_path=path,
                    remediation=(
                        "Format CreationInfo.created as "
                        "YYYY-MM-DDTHH:MM:SS[.ffffff]Z (UTC only)."
                    ),
                    section_reference="Document metadata",
                    found_value=created,
                )
            ]
        return []


class CreatorsRule:
    """CreationInfo's ``createdBy`` must list at least one resolvable agent."""

    rule_id = "spdx3_completeness.creators"
    description = (
        "The document's CreationInfo.createdBy must list at least one IRI "
        "that resolves to an Agent/Organization/Person/Tool element."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate creators completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding for an empty/absent
            ``createdBy``, and a distinct finding per IRI that is
            dangling or resolves to a non-agent element; otherwise an
            empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        if (creation_info := doc.creation_info_for(spdx_doc)) is None:
            return []
        path = creation_info.element_path()
        if not (creator_ids := _as_str_list(creation_info.get("createdBy"))):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(f"CreationInfo {path} states no createdBy creators."),
                    field_path=path,
                    remediation=(
                        "Reference at least one Agent/Organization/Person/"
                        "Tool element from CreationInfo.createdBy."
                    ),
                    section_reference="Document metadata",
                )
            ]
        messages: list[ValidationMessage] = []
        for creator_id in creator_ids:
            if (agent := doc.element_by_id(creator_id)) is None:
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"CreationInfo {path} createdBy references "
                            f"{creator_id!r}, which is not present in the "
                            "document."
                        ),
                        field_path=path,
                        remediation=(
                            "Add the referenced agent element to the @graph, "
                            "or remove the dangling createdBy reference."
                        ),
                        section_reference="Document metadata",
                        found_value=creator_id,
                    )
                )
            elif not agent.is_type(*_AGENT_TYPES):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"CreationInfo {path} createdBy reference "
                            f"{creator_id!r} does not identify an Agent/"
                            "Organization/Person/Tool element."
                        ),
                        field_path=path,
                        remediation=(
                            "Point createdBy at an Agent, Organization, "
                            "Person, or Tool element."
                        ),
                        section_reference="Document metadata",
                        found_value=creator_id,
                    )
                )
        return messages


class SpecVersionRule:
    """CreationInfo's ``specVersion`` must be exactly ``3.0.1``."""

    rule_id = "spdx3_completeness.spec_version"
    description = "The document's CreationInfo.specVersion must be '3.0.1'."
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate spec-version completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if ``specVersion`` is not
            exactly ``3.0.1``; otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        if (creation_info := doc.creation_info_for(spdx_doc)) is None:
            return []
        if (spec_version := creation_info.get("specVersion")) == "3.0.1":
            return []
        path = creation_info.element_path()
        return [
            _message(
                rule_id=self.rule_id,
                message=(
                    f"CreationInfo {path} specVersion {spec_version!r} is "
                    "not exactly '3.0.1'."
                ),
                field_path=path,
                remediation="Set CreationInfo.specVersion to exactly '3.0.1'.",
                section_reference="Document metadata",
                found_value=spec_version,
            )
        ]


class DataLicenseRule:
    """The document's ``dataLicense`` must resolve to an AnyLicenseInfo element.

    SPDX 3.0.1 makes ``dataLicense`` optional (``sh:maxCount 1``, no
    ``minCount``) and IRI-valued, with range
    ``SimpleLicensing/AnyLicenseInfo``, rather than the literal string
    ``CC0-1.0`` used in 2.3. The Qualcomm profile requires it anyway, and
    requires the reference to resolve: to an AnyLicenseInfo element in
    the ``@graph``, an inline AnyLicenseInfo object, an SPDX License List
    IRI (``https://spdx.org/licenses/<id>``), or one of the model's
    ``NoneLicense``/``NoAssertionLicense`` individuals. Missing,
    malformed (not a reference), dangling, and wrong-type values are
    reported with distinct messages.
    """

    rule_id = "spdx3_completeness.data_license"
    description = (
        "SpdxDocument.dataLicense must be present and resolve to an "
        "AnyLicenseInfo element."
    )
    spdx_versions = _SPDX_3_0_1

    _PROBLEMS: ClassVar[dict[_LicenseReference, _ReferenceProblem]] = {
        _LicenseReference.MALFORMED: _ReferenceProblem(
            "is not an IRI reference to a license element",
            "Set dataLicense to the IRI of a license element in the document, "
            "not a literal license name.",
        ),
        _LicenseReference.DANGLING: _ReferenceProblem(
            "references a license element that is not present in the document",
            "Add the referenced license element to the @graph, or correct the "
            "dataLicense reference.",
        ),
        _LicenseReference.WRONG_TYPE: _ReferenceProblem(
            "does not identify an AnyLicenseInfo element",
            "Point dataLicense at a license element such as a "
            "simplelicensing_LicenseExpression or expandedlicensing_ListedLicense.",
        ),
    }

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate data-license completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if ``dataLicense`` is
            missing/empty, malformed, dangling, or names a non-license
            element; otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        path = spdx_doc.element_path()
        value = spdx_doc.get("dataLicense")
        if value is None or (isinstance(value, str) and not value.strip()):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=f"SpdxDocument {path} is missing a dataLicense value.",
                    field_path=path,
                    remediation="Set dataLicense on the SpdxDocument to a license IRI.",
                    section_reference="Document metadata",
                )
            ]
        outcome = _resolve_license_reference(doc, value)
        if outcome is _LicenseReference.RESOLVED:
            return []
        problem, remediation = self._PROBLEMS[outcome]
        return [
            _message(
                rule_id=self.rule_id,
                message=f"SpdxDocument {path} dataLicense {value!r} {problem}.",
                field_path=path,
                remediation=remediation,
                section_reference="Document metadata",
                found_value=value,
            )
        ]


class LicenseListVersionRule:
    """A stated ``simplelicensing_licenseListVersion`` must look like a version.

    SPDX 2.3 tracked the SPDX license-list version once per document, on
    ``creationInfo.licenseListVersion``. SPDX 3.0.1 moves this property
    onto the ``simplelicensing_LicenseExpression`` shape instead --
    ``SimpleLicensing/licenseListVersion`` -- and makes it optional per
    expression, so there is no single document-wide value left to
    require. This rule therefore checks each ``LicenseExpression``
    element independently: an element that omits the property passes
    (it is optional), but a present-and-empty or non-semver-shaped value
    is a finding.
    """

    rule_id = "spdx3_completeness.license_list_version"
    description = (
        "Each simplelicensing_LicenseExpression that states a "
        "simplelicensing_licenseListVersion must use a non-empty, "
        "semver-shaped value."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate license-list-version completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per LicenseExpression
            element whose ``simplelicensing_licenseListVersion`` is
            present but empty or not semver-shaped; elements that omit
            the property produce no finding.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for expression in doc.elements_of_type("simplelicensing_LicenseExpression"):
            if (value := expression.get("simplelicensing_licenseListVersion")) is None:
                continue
            path = expression.element_path()
            if not _is_nonempty_str(value):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"LicenseExpression {path} states an empty "
                            "simplelicensing_licenseListVersion."
                        ),
                        field_path=path,
                        remediation=(
                            "Set simplelicensing_licenseListVersion to a "
                            "non-empty semver value, or remove the property."
                        ),
                        section_reference="Licensing & copyright",
                        found_value=value,
                    )
                )
                continue
            if not _is_license_list_version(value):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"LicenseExpression {path} "
                            f"simplelicensing_licenseListVersion {value!r} is "
                            "not a semver-shaped version."
                        ),
                        field_path=path,
                        remediation=(
                            "Format simplelicensing_licenseListVersion as a "
                            "semver version, e.g. '3.25.0'."
                        ),
                        section_reference="Licensing & copyright",
                        found_value=value,
                    )
                )
        return messages
