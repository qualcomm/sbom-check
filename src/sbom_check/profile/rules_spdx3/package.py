# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Package-level Qualcomm completeness rules for SPDX 3.0.1."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sbom_check.profile.rules_spdx3._common import (
    _AGENT_TYPES,
    _CPE_IDENTIFIER_TYPES,
    _SPDX_3_0_1,
    _entry_has_type,
    _is_absolute_iri,
    _is_nonempty_str,
    _message,
    _PackageLicenseRelationshipRule,
    _PackageScalarFieldRule,
)
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.models import ValidationMessage
    from sbom_check.profile.registry import RuleContext


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


class PackageVerificationCodeRule:
    """A stated ``PackageVerificationCode`` must carry a non-empty ``hashValue``.

    ``Core/PackageVerificationCode`` is a subclass of
    ``Core/IntegrityMethod``, reached via the ``verifiedUsing`` property
    on ``Core/Element``, and the spec itself describes it as "An SPDX
    version 2.X compatible verification method for software packages."
    No 2.3 rule enforces this today, so requiring it is new. A package
    with no verification code at all passes; only a present-but-empty
    ``hashValue`` is a finding. Plain ``Hash`` entries under
    ``verifiedUsing`` are ignored -- only entries typed
    ``PackageVerificationCode`` are checked. ``verifiedUsing`` values
    may be inline dicts or IRI references to top-level elements; both
    forms are resolved here.
    """

    rule_id = "spdx3_completeness.package_verification_code"
    description = (
        "A PackageVerificationCode reached via verifiedUsing must carry a "
        "non-empty hashValue."
    )
    spdx_versions = _SPDX_3_0_1

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate package-verification-code completeness.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package whose
            ``verifiedUsing`` includes a ``PackageVerificationCode``
            entry with a missing or empty ``hashValue``; packages with
            no such entry produce no finding.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            path = pkg.element_path()
            for raw_entry in self._verification_codes(doc, pkg):
                if _is_nonempty_str(raw_entry.get("hashValue")):
                    continue
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} declares a "
                            "PackageVerificationCode with an empty hashValue."
                        ),
                        field_path=path,
                        remediation=(
                            "Set a non-empty hashValue on the "
                            "PackageVerificationCode, or remove the malformed "
                            "verifiedUsing entry."
                        ),
                        section_reference="Package & component metadata",
                    )
                )
        return messages

    @staticmethod
    def _verification_codes(doc: Spdx3Document, pkg: Any) -> list[dict[str, Any]]:
        """Resolve a package's ``verifiedUsing`` entries typed PackageVerificationCode.

        Args:
            doc: The document adapter, used to resolve IRI references.
            pkg: The package element whose ``verifiedUsing`` should be
                inspected.

        Returns:
            list[dict[str, Any]]: Raw dicts for each ``verifiedUsing``
            entry (inline or IRI-resolved) whose type is
            ``PackageVerificationCode``; plain ``Hash`` entries and
            dangling references are excluded.
        """
        if (raw_value := pkg.get("verifiedUsing")) is None:
            return []
        items: list[Any] = raw_value if isinstance(raw_value, list) else [raw_value]

        resolved: list[dict[str, Any]] = []
        for item in items:
            if isinstance(item, dict):
                candidate = item
            elif isinstance(item, str):
                if (element := doc.element_by_id(item)) is None:
                    continue
                candidate = element.raw
            else:
                continue
            if _entry_has_type(candidate, "PackageVerificationCode"):
                resolved.append(candidate)
        return resolved
