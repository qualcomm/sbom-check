# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Shared constants, helpers, and base classes for SPDX 3.0.1 rules.

Imported by the document, package, and relationship rule modules. This
module must not import from them, keeping the dependency one-way.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sbom_check.models import ValidationMessage, ValidationSeverity
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.profile.registry import RuleContext

_SPDX_3_0_1: tuple[str, ...] = ("3.0.1",)
_AGENT_TYPES = ("Agent", "Organization", "Person", "Tool")
_CPE_IDENTIFIER_TYPES = ("cpe23", "cpe22")
_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_DEPENDENCY_RELATIONSHIP_TYPES = ("contains", "dependsOn")
_LICENSE_LIST_VERSION_PATTERN = re.compile(r"^\d+\.\d+\.\d+")
# A single-package document has nothing to relate, so containment and
# dependency relationships are only meaningful from two packages up.
_MULTI_PACKAGE_THRESHOLD = 2


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


def _entry_has_type(raw: dict[str, Any], type_name: str) -> bool:
    """Check whether a raw element dict's ``type``/``@type`` matches a name.

    Args:
        raw: The raw element dict (inline or resolved-by-reference).
        type_name: The short type name to match, e.g.
            ``"PackageVerificationCode"``.

    Returns:
        bool: True if any of the raw type values equals ``type_name`` or
        ends with it after a namespace separator (``/`` or ``:``),
        covering short-form, full-IRI, and ``spdx:``-prefixed spellings.
    """
    candidates = _as_str_list(raw.get("type")) or _as_str_list(raw.get("@type"))
    return any(
        candidate == type_name
        or candidate.endswith(f"/{type_name}")
        or candidate.endswith(f":{type_name}")
        for candidate in candidates
    )


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
