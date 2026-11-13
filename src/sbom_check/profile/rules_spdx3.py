# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Qualcomm completeness profile rules for SPDX 3.0.1 documents.

Each rule implements the :class:`~sbom_check.profile.registry.ProfileRule`
protocol and maps one row of ``docs/spdx3-completeness-matrix.md`` that is
marked ``EQUIVALENT``, ``REPRESENTED_DIFFERENTLY``, or ``CONDITIONAL``.
Rules marked ``NEEDS_DECISION`` or ``NOT_APPLICABLE`` in that matrix are
deliberately absent from this module.

Severity is never decided here: every message is constructed with
:data:`~sbom_check.models.ValidationSeverity.ERROR` as a neutral
placeholder, and the :class:`~sbom_check.profile.registry.ProfileRuleRegistry`
overrides it from configuration when the rule runs.

``spdx3_completeness.package_purl`` is intentionally NOT implemented here.
The matrix marks that row ``NEEDS_DECISION`` because two shapes are both
valid 3.0.1 encodings of a package URL -- the ``software_packageUrl``
scalar property and an ``ExternalIdentifier`` element with
``externalIdentifierType: packageUrl`` -- and Qualcomm has not chosen
between them (or decided to require both). Its absence from
:data:`SPDX3_RULES` is deliberate, not an oversight.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sbom_check.models import ValidationMessage, ValidationSeverity
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.profile.registry import (
        ProfileRule,
        ProfileRuleRegistry,
        RuleContext,
    )

_SPDX_3_0_1: tuple[str, ...] = ("3.0.1",)
_AGENT_TYPES = ("Agent", "Organization", "Person", "Tool")
_CPE_IDENTIFIER_TYPES = ("cpe23", "cpe22")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")


def _is_nonempty_str(value: Any) -> bool:
    """Check whether a raw value is a non-empty, non-whitespace string.

    Args:
        value: The raw value to check.

    Returns:
        bool: True if ``value`` is a string with at least one
        non-whitespace character.
    """
    return isinstance(value, str) and bool(value.strip())


def _is_absolute_iri(value: Any) -> bool:
    """Check whether a raw value looks like an absolute IRI.

    Args:
        value: The raw value to check.

    Returns:
        bool: True if ``value`` is a non-empty string containing a
        scheme separator (``://``) or starting with ``urn:``.
    """
    if not _is_nonempty_str(value):
        return False
    return "://" in value or value.startswith("urn:")


def _as_str_list(value: Any) -> list[str]:
    """Coerce a raw property value into a list of strings.

    Args:
        value: A raw property value that may be a single string, a
            list of strings (with possible non-string noise), or
            absent/None.

    Returns:
        list[str]: The string values found, in order, empty if none.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _message(
    *,
    rule_id: str,
    message: str,
    field_path: str,
    remediation: str,
    section_reference: str | None = None,
    found_value: Any | None = None,
) -> ValidationMessage:
    """Build a neutral-severity completeness finding.

    Args:
        rule_id: The id of the rule reporting this finding.
        message: An actionable description naming the offending element.
        field_path: The stable element path the finding is about.
        remediation: A concrete instruction for how to fix the finding.
        section_reference: Optional citation into the completeness matrix.
        found_value: Optional raw value that was found to be invalid.

    Returns:
        ValidationMessage: The constructed message, with
        :data:`ValidationSeverity.ERROR` as a placeholder severity that
        the registry will override from configuration.
    """
    return ValidationMessage(
        severity=ValidationSeverity.ERROR,
        message=message,
        rule_id=rule_id,
        field_path=field_path,
        section_reference=section_reference,
        found_value=found_value,
        remediation=remediation,
    )


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


class _PackageScalarFieldRule:
    """Base for package rules that check one scalar property for presence."""

    rule_id: str
    description: str
    spdx_versions = _SPDX_3_0_1
    _property: str
    _label: str

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate presence of this rule's scalar package property.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package missing a
            non-empty value for the configured property.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            if _is_nonempty_str(pkg.get(self._property)):
                continue
            path = pkg.element_path()
            messages.append(
                _message(
                    rule_id=self.rule_id,
                    message=f"Package {path} is missing a non-empty {self._label}.",
                    field_path=path,
                    remediation=f"Set {self._property} on package {path}.",
                    section_reference="Package & component metadata",
                )
            )
        return messages


class PackageNameRule(_PackageScalarFieldRule):
    """``software_Package.name`` must be present and non-empty."""

    rule_id = "spdx3_completeness.package_name"
    description = "software_Package.name must be present and non-empty."
    _property = "name"
    _label = "name"


class PackageIdentifierRule:
    """``software_Package.spdxId`` must be present, non-empty, and an IRI."""

    rule_id = "spdx3_completeness.package_identifier"
    description = "software_Package.spdxId must be present, non-empty, and an IRI."
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate package-identifier completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package whose
            ``spdxId`` is missing, empty, or not an absolute IRI.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            path = pkg.element_path()
            spdx_id = pkg.get("spdxId")
            if not _is_nonempty_str(spdx_id):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=f"Package {path} is missing a non-empty spdxId.",
                        field_path=path,
                        remediation="Assign a globally unique absolute IRI as spdxId.",
                        section_reference="Identifiers",
                    )
                )
            elif not _is_absolute_iri(spdx_id):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} spdxId {spdx_id!r} is not an absolute IRI."
                        ),
                        field_path=path,
                        remediation=(
                            "Use an absolute IRI (with a scheme or 'urn:' "
                            "prefix) as the package spdxId."
                        ),
                        section_reference="Identifiers",
                        found_value=spdx_id,
                    )
                )
        return messages


class PackageVersionRule(_PackageScalarFieldRule):
    """``software_packageVersion`` must be present and non-empty."""

    rule_id = "spdx3_completeness.package_version"
    description = "software_packageVersion must be present and non-empty."
    _property = "software_packageVersion"
    _label = "software_packageVersion"


class PackageDownloadLocationRule(_PackageScalarFieldRule):
    """``software_downloadLocation`` must be present and non-empty."""

    rule_id = "spdx3_completeness.package_download_location"
    description = "software_downloadLocation must be present and non-empty."
    _property = "software_downloadLocation"
    _label = "software_downloadLocation"


class PackageHomepageRule(_PackageScalarFieldRule):
    """``software_homePage`` must be present and non-empty."""

    rule_id = "spdx3_completeness.package_homepage"
    description = "software_homePage must be present and non-empty."
    _property = "software_homePage"
    _label = "software_homePage"


class CopyrightTextRule(_PackageScalarFieldRule):
    """``software_copyrightText`` must be present and non-empty."""

    rule_id = "spdx3_completeness.copyright_text"
    description = "software_copyrightText must be present and non-empty."
    _property = "software_copyrightText"
    _label = "software_copyrightText"


class PackageSupplierRule:
    """``suppliedBy`` must be stated and resolve to an agent element.

    Three distinct outcomes are reported with different messages and
    remediation: the property is absent ("states no supplier"); the
    property names an IRI that is not present in the document
    (dangling reference); or the reference resolves to an element that
    is not an Agent/Organization/Person/Tool.
    """

    rule_id = "spdx3_completeness.package_supplier"
    description = "suppliedBy must be stated and resolve to an agent element."
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate package-supplier completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package whose
            ``suppliedBy`` is absent, dangling, or non-agent.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            path = pkg.element_path()
            if (value := pkg.get("suppliedBy")) is None:
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=f"Package {path} states no supplier.",
                        field_path=path,
                        remediation=("Set suppliedBy on the package to an Agent IRI."),
                        section_reference="Supplier & originator",
                    )
                )
                continue
            if doc.reference_is_dangling(pkg, "suppliedBy"):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} names a supplier that is not "
                            "present in the document."
                        ),
                        field_path=path,
                        remediation=(
                            "Add the referenced Agent element to the @graph, "
                            "or correct the dangling suppliedBy reference."
                        ),
                        section_reference="Supplier & originator",
                        found_value=value,
                    )
                )
                continue
            agent = doc.resolve_agent(pkg, "suppliedBy")
            if agent is None or not agent.is_type(*_AGENT_TYPES):
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} supplier reference does not "
                            "identify an Agent."
                        ),
                        field_path=path,
                        remediation=(
                            "Point suppliedBy at an Agent, Organization, "
                            "Person, or Tool element."
                        ),
                        section_reference="Supplier & originator",
                        found_value=value,
                    )
                )
        return messages


class _PackageLicenseRelationshipRule:
    """Base for license-relationship rules checking a relationship type."""

    rule_id: str
    description: str
    spdx_versions = _SPDX_3_0_1
    _relationship_type: str
    _label: str

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate presence of a license relationship from each package.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package lacking a
            ``Relationship`` of the configured type with a non-empty
            ``to``.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            relationships = doc.relationships_from(
                pkg.element_id, self._relationship_type
            )
            if any(rel.to_ids for rel in relationships):
                continue
            path = pkg.element_path()
            messages.append(
                _message(
                    rule_id=self.rule_id,
                    message=(
                        f"Package {path} has no {self._relationship_type} "
                        f"relationship identifying its {self._label}."
                    ),
                    field_path=path,
                    remediation=(
                        "Add a Relationship element with relationshipType "
                        f"{self._relationship_type} from this package to a "
                        "license element."
                    ),
                    section_reference="Licensing & copyright",
                )
            )
        return messages


class LicenseConcludedRule(_PackageLicenseRelationshipRule):
    """A ``hasConcludedLicense`` relationship must exist from each package."""

    rule_id = "spdx3_completeness.license_concluded"
    description = (
        "A hasConcludedLicense Relationship must exist from each package to "
        "a non-empty license target."
    )
    _relationship_type = "hasConcludedLicense"
    _label = "concluded license"


class LicenseDeclaredRule(_PackageLicenseRelationshipRule):
    """A ``hasDeclaredLicense`` relationship must exist from each package."""

    rule_id = "spdx3_completeness.license_declared"
    description = (
        "A hasDeclaredLicense Relationship must exist from each package to "
        "a non-empty license target."
    )
    _relationship_type = "hasDeclaredLicense"
    _label = "declared license"


class PackageCpeRule:
    """A CPE is required only when the package already declares one.

    CONDITIONAL: a package with no CPE external-identifier entry at all
    passes -- CPE remains conditional on an official CPE existing, as in
    the 2.3 profile. A package that *does* declare a ``cpe23``/``cpe22``
    external identifier but leaves its ``identifier`` empty or missing
    is a finding.
    """

    rule_id = "spdx3_completeness.package_cpe"
    description = (
        "A declared cpe23/cpe22 external identifier must carry a non-empty "
        "identifier value; packages without any CPE entry are unaffected."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate conditional CPE completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per malformed CPE
            external identifier entry; packages with no CPE entry at
            all produce no findings.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            path = pkg.element_path()
            for external_identifier in doc.external_identifiers(pkg):
                if external_identifier.identifier_type not in _CPE_IDENTIFIER_TYPES:
                    continue
                if _is_nonempty_str(external_identifier.identifier):
                    continue
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} declares a "
                            f"{external_identifier.identifier_type} external "
                            "identifier with an empty identifier value."
                        ),
                        field_path=path,
                        remediation=(
                            "Set a non-empty CPE identifier value, or remove "
                            "the malformed external identifier entry."
                        ),
                        section_reference="Identifiers",
                    )
                )
        return messages


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


SPDX3_RULES: tuple[ProfileRule, ...] = (
    DocumentNameRule(),
    DocumentIdentifierRule(),
    CreationTimestampRule(),
    CreatorsRule(),
    SpecVersionRule(),
    DataLicenseRule(),
    PackageNameRule(),
    PackageIdentifierRule(),
    PackageVersionRule(),
    PackageDownloadLocationRule(),
    PackageHomepageRule(),
    CopyrightTextRule(),
    PackageSupplierRule(),
    LicenseConcludedRule(),
    LicenseDeclaredRule(),
    PackageCpeRule(),
    DocumentDescribesRule(),
    NoIsolatedElementsRule(),
)


def register_spdx3_rules(registry: ProfileRuleRegistry) -> None:
    """Register every SPDX 3.0.1 completeness rule with a registry.

    Args:
        registry: The registry to register rules with, in document,
            package, then relationship order.
    """
    for rule in SPDX3_RULES:
        registry.register(rule)


__all__ = [
    "SPDX3_RULES",
    "CopyrightTextRule",
    "CreationTimestampRule",
    "CreatorsRule",
    "DataLicenseRule",
    "DocumentDescribesRule",
    "DocumentIdentifierRule",
    "DocumentNameRule",
    "LicenseConcludedRule",
    "LicenseDeclaredRule",
    "NoIsolatedElementsRule",
    "PackageCpeRule",
    "PackageDownloadLocationRule",
    "PackageHomepageRule",
    "PackageIdentifierRule",
    "PackageNameRule",
    "PackageSupplierRule",
    "PackageVersionRule",
    "SpecVersionRule",
    "register_spdx3_rules",
]
