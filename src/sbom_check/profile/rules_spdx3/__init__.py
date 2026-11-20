# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Qualcomm completeness profile rules for SPDX 3.0.1 documents.

Each rule implements the :class:`~sbom_check.profile.registry.ProfileRule`
protocol and maps one row of ``docs/spdx3-completeness-matrix.md`` that is
marked ``EQUIVALENT``, ``REPRESENTED_DIFFERENTLY``, or ``CONDITIONAL``.
Rules marked ``NEEDS_DECISION`` or ``NOT_APPLICABLE`` in that matrix are
deliberately not implemented. ``NEEDS_DECISION`` rows are listed in
:data:`SPDX3_PENDING_DECISION_RULES` so they are reported in coverage.

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
:data:`SPDX3_RULES` is deliberate, not an oversight; it is reported as
pending instead.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sbom_check.profile.rules_spdx3.document import (
    CreationTimestampRule,
    CreatorsRule,
    DataLicenseRule,
    DocumentIdentifierRule,
    DocumentNameRule,
    LicenseListVersionRule,
    SpecVersionRule,
)
from sbom_check.profile.rules_spdx3.package import (
    CopyrightTextRule,
    LicenseConcludedRule,
    LicenseDeclaredRule,
    PackageCpeRule,
    PackageDownloadLocationRule,
    PackageHomepageRule,
    PackageIdentifierRule,
    PackageNameRule,
    PackageSupplierRule,
    PackageVerificationCodeRule,
    PackageVersionRule,
)
from sbom_check.profile.rules_spdx3.relationships import (
    DependencyRelationshipsRule,
    DocumentDescribesRule,
    NoIsolatedElementsRule,
)

if TYPE_CHECKING:
    from sbom_check.profile.registry import ProfileRule, ProfileRuleRegistry


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
    DependencyRelationshipsRule(),
    LicenseListVersionRule(),
    PackageVerificationCodeRule(),
)


# Matrix rows marked NEEDS_DECISION. They have no implementation, but are
# registered as pending so every run lists them in rule_coverage with a
# pending-decision reason instead of leaving them out.
SPDX3_PENDING_DECISION_RULES: dict[str, str] = {
    "spdx3_completeness.package_originator": (
        "Whether software_Package.originatedBy is required (matrix Open Question 2)."
    ),
    "spdx3_completeness.package_purl": (
        "Which package URL shape is required: software_packageUrl, an "
        "ExternalIdentifier of type packageUrl, or both (matrix Open "
        "Question 5)."
    ),
    "spdx3_completeness.build_tools_coverage": (
        "Whether and how build tooling must be represented in SPDX 3.0.1."
    ),
    "spdx3_completeness.vulnerability_info": (
        "Whether vulnerability/VEX information is in scope (matrix Open Question 7)."
    ),
    "spdx3_completeness.provenance_info": (
        "Whether build provenance is in scope (matrix Open Question 7)."
    ),
}


def register_spdx3_rules(registry: ProfileRuleRegistry) -> None:
    """Register every SPDX 3.0.1 completeness rule with a registry.

    Also records each requirement in :data:`SPDX3_PENDING_DECISION_RULES`
    as pending, so it appears in coverage.

    Args:
        registry: The registry to register rules with, in document,
            package, then relationship order.
    """
    for rule in SPDX3_RULES:
        registry.register(rule)
    for rule_id, description in SPDX3_PENDING_DECISION_RULES.items():
        registry.register_pending_decision(rule_id, description)


__all__ = [
    "SPDX3_PENDING_DECISION_RULES",
    "SPDX3_RULES",
    "CopyrightTextRule",
    "CreationTimestampRule",
    "CreatorsRule",
    "DataLicenseRule",
    "DependencyRelationshipsRule",
    "DocumentDescribesRule",
    "DocumentIdentifierRule",
    "DocumentNameRule",
    "LicenseConcludedRule",
    "LicenseDeclaredRule",
    "LicenseListVersionRule",
    "NoIsolatedElementsRule",
    "PackageCpeRule",
    "PackageDownloadLocationRule",
    "PackageHomepageRule",
    "PackageIdentifierRule",
    "PackageNameRule",
    "PackageSupplierRule",
    "PackageVerificationCodeRule",
    "PackageVersionRule",
    "SpecVersionRule",
    "register_spdx3_rules",
]
