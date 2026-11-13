# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Document-level Qualcomm completeness rules for SPDX 3.0.1."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sbom_check.profile.rules_spdx3._common import (
    _AGENT_TYPES,
    _LICENSE_LIST_VERSION_PATTERN,
    _SPDX_3_0_1,
    _TIMESTAMP_PATTERN,
    _as_str_list,
    _is_absolute_iri,
    _is_nonempty_str,
    _message,
)
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.models import ValidationMessage
    from sbom_check.profile.registry import RuleContext


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
    """The document's ``spdxId`` must be present, non-empty, and an IRI."""

    rule_id = "spdx3_completeness.document_identifier"
    description = (
        "SpdxDocument.spdxId must be present, non-empty, an absolute IRI, "
        "and must not contain a '#' fragment."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate document-identifier completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if ``spdxId`` is
            missing/empty, not an absolute IRI, or contains a ``#``
            fragment; otherwise an empty list. Returns an empty list
            (rather than duplicating) when there is no ``SpdxDocument``
            element at all -- :class:`DocumentNameRule` reports that.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        spdx_id = spdx_doc.get("spdxId")
        path = spdx_doc.element_path()
        if not _is_nonempty_str(spdx_id):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=f"SpdxDocument {path} is missing a non-empty spdxId.",
                    field_path=path,
                    remediation="Assign a globally unique absolute IRI as spdxId.",
                    section_reference="Document metadata",
                )
            ]
        if "#" in spdx_id:
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {path} spdxId {spdx_id!r} contains a "
                        "prohibited '#' fragment."
                    ),
                    field_path=path,
                    remediation="Remove the '#' fragment from the document spdxId.",
                    section_reference="Document metadata",
                    found_value=spdx_id,
                )
            ]
        if not _is_absolute_iri(spdx_id):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"SpdxDocument {path} spdxId {spdx_id!r} is not an "
                        "absolute IRI."
                    ),
                    field_path=path,
                    remediation=(
                        "Use an absolute IRI (with a scheme or 'urn:' prefix) "
                        "as the document spdxId."
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
        if not _TIMESTAMP_PATTERN.match(created):
            return [
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"CreationInfo {path} created value {created!r} is "
                        "not a valid ISO-8601 UTC instant."
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
    """The document's ``dataLicense`` must be present.

    SPDX 3.0.1 makes ``dataLicense`` optional (``sh:maxCount 1``, no
    ``minCount``) and IRI-valued rather than the literal string
    ``CC0-1.0`` used in 2.3. The Qualcomm profile requires it anyway;
    any non-empty value is accepted and an IRI need not resolve.
    """

    rule_id = "spdx3_completeness.data_license"
    description = "SpdxDocument.dataLicense must be present and non-empty."
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate data-license completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: A finding if ``dataLicense`` is
            missing/empty; otherwise an empty list.
        """
        doc = Spdx3Document.from_dict(document)
        if (spdx_doc := doc.spdx_document()) is None:
            return []
        if _is_nonempty_str(spdx_doc.get("dataLicense")):
            return []
        path = spdx_doc.element_path()
        return [
            _message(
                rule_id=self.rule_id,
                message=f"SpdxDocument {path} is missing a dataLicense value.",
                field_path=path,
                remediation=("Set dataLicense on the SpdxDocument to a license IRI."),
                section_reference="Document metadata",
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
            if not _LICENSE_LIST_VERSION_PATTERN.match(value):
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
