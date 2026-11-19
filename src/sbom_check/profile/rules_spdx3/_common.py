# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Shared constants, helpers, and base classes for SPDX 3.0.1 rules.

Imported by the document, package, and relationship rule modules. This
module must not import from them, keeping the dependency one-way.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any, NamedTuple

from sbom_check.models import ValidationMessage, ValidationSeverity
from sbom_check.profile.spdx3_model import Spdx3Document

if TYPE_CHECKING:
    from sbom_check.profile.registry import RuleContext

_SPDX_3_0_1: tuple[str, ...] = ("3.0.1",)
_AGENT_TYPES = ("Agent", "Organization", "Person", "Tool")
_CPE_IDENTIFIER_TYPES = ("cpe23", "cpe22")
# UTC only ("Z"), with optional fractional seconds of any precision. The
# pattern fixes the shape; _is_valid_timestamp then checks the values are a
# real calendar date and time of day. ASCII-only so that non-ASCII digits,
# which ``\d`` would otherwise accept, are rejected.
_TIMESTAMP_PATTERN = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]+)?Z",
    re.ASCII,
)
_DEPENDENCY_RELATIONSHIP_TYPES = ("contains", "dependsOn")
# Semantic Versioning 2.0.0, the grammar the SPDX 3.0.1 model's
# SimpleLicensing/licenseListVersion shape constrains the value to. Always
# used with fullmatch so trailing text is rejected.
_LICENSE_LIST_VERSION_PATTERN = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
    re.ASCII,
)
# RFC 3986 section 3.1: scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
_IRI_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*", re.ASCII)
# RFC 8141: "urn:" NID ":" NSS, NID 2-32 alphanumerics/hyphens.
_URN_PATTERN = re.compile(
    r"urn:[A-Za-z0-9][A-Za-z0-9-]{0,30}[A-Za-z0-9]:.+", re.ASCII | re.IGNORECASE
)
# RFC 3986 unreserved, sub-delims, and the gen-delims that may appear inside
# a component (":" and "@"). "/", "?" and "#" are handled structurally.
_IRI_ASCII_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@"
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
# RFC 3987 section 2.2 "ucschar" and "iprivate" code point ranges.
_UCSCHAR_RANGES: tuple[tuple[int, int], ...] = (
    (0xA0, 0xD7FF),
    (0xF900, 0xFDCF),
    (0xFDF0, 0xFFEF),
    *((plane, plane + 0xFFFD) for plane in range(0x10000, 0xE0000, 0x10000)),
    (0xE1000, 0xEFFFD),
)
_IPRIVATE_RANGES: tuple[tuple[int, int], ...] = (
    (0xE000, 0xF8FF),
    (0xF0000, 0xFFFFD),
    (0x100000, 0x10FFFD),
)
_BLANK_NODE_PREFIX = "_:"
_PORT_PATTERN = re.compile(r":[0-9]*", re.ASCII)
_IPVFUTURE_PATTERN = re.compile(
    r"[vV][0-9A-Fa-f]+\.[A-Za-z0-9\-._~!$&'()*+,;=:]+", re.ASCII
)
# The SPDX 3.0.1 subclasses of SimpleLicensing/AnyLicenseInfo, in the
# normalized short form the adapter produces.
_ANY_LICENSE_INFO_TYPES = (
    "simplelicensing_AnyLicenseInfo",
    "simplelicensing_LicenseExpression",
    "expandedlicensing_ConjunctiveLicenseSet",
    "expandedlicensing_CustomLicense",
    "expandedlicensing_DisjunctiveLicenseSet",
    "expandedlicensing_ExtendableLicense",
    "expandedlicensing_IndividualLicensingInfo",
    "expandedlicensing_License",
    "expandedlicensing_ListedLicense",
    "expandedlicensing_OrLaterOperator",
    "expandedlicensing_WithAdditionOperator",
)
# Named individuals the SPDX 3.0.1 model itself defines as AnyLicenseInfo
# values. They are part of the vocabulary rather than elements a document
# can define, so they resolve without a @graph entry.
_LICENSE_INDIVIDUALS = frozenset(
    {
        "https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoAssertionLicense",
        "https://spdx.org/rdf/3.0.1/terms/ExpandedLicensing/NoneLicense",
        "expandedlicensing_NoAssertionLicense",
        "expandedlicensing_NoneLicense",
    }
)
# SPDX License List entries are ListedLicense / ListedLicenseException
# elements the license list itself defines, identified by IRIs in this
# namespace with an SPDX idstring suffix. Documents reference them without
# redefining them, so they resolve without a @graph entry. Recognition is
# syntactic only; whether the id is on the current list is not checked.
_LICENSE_LIST_IRI_PATTERN = re.compile(
    r"https://spdx\.org/licenses/[A-Za-z0-9.+-]+", re.ASCII
)
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


def _is_iri_char(char: str, *, allow_private: bool = False) -> bool:
    """Check whether a character may appear literally in an IRI component.

    Args:
        char: A single character.
        allow_private: Also accept the RFC 3987 ``iprivate`` ranges,
            which are legal only in the query component.

    Returns:
        bool: True for RFC 3986 unreserved and sub-delimiter characters,
        ``:`` and ``@``, and the RFC 3987 ``ucschar`` ranges.
    """
    if char in _IRI_ASCII_CHARS:
        return True
    code = ord(char)
    if any(low <= code <= high for low, high in _UCSCHAR_RANGES):
        return True
    return allow_private and any(low <= code <= high for low, high in _IPRIVATE_RANGES)


def _is_valid_iri_component(
    text: str, extra: str = "", *, allow_private: bool = False
) -> bool:
    """Check one IRI component for legal characters and percent-encodings.

    Args:
        text: The component text.
        extra: Additional literal characters allowed in this component,
            e.g. ``/`` for paths or ``/?`` for queries and fragments.
        allow_private: Accept ``iprivate`` characters (query only).

    Returns:
        bool: True if every character is legal and every ``%`` starts a
        two-hex-digit escape.
    """
    index = 0
    while index < len(text):
        if (char := text[index]) == "%":
            escape = text[index + 1 : index + 3]
            if len(escape) != 2 or not set(escape) <= _HEX_DIGITS:  # noqa: PLR2004
                return False
            index += 3
            continue
        if char not in extra and not _is_iri_char(char, allow_private=allow_private):
            return False
        index += 1
    return True


def _is_valid_ip_literal(literal: str) -> bool:
    """Check the inside of an RFC 3986 ``IP-literal`` (between brackets).

    Args:
        literal: The text between ``[`` and ``]``.

    Returns:
        bool: True for a valid IPv6 address or an ``IPvFuture`` literal.
    """
    if _IPVFUTURE_PATTERN.fullmatch(literal):
        return True
    try:
        ipaddress.IPv6Address(literal)
    except ValueError:
        return False
    return True


def _is_valid_authority(authority: str) -> bool:
    """Check an RFC 3986 authority (``[userinfo@]host[:port]``).

    Args:
        authority: The text between ``//`` and the next ``/``. May be
            empty, as in ``file:///path``.

    Returns:
        bool: True if the userinfo, host and port are well formed.
    """
    userinfo, at_sign, host_port = authority.rpartition("@")
    if at_sign and ("@" in userinfo or not _is_valid_iri_component(userinfo)):
        return False
    if host_port.startswith("["):
        literal, closing, port_part = host_port[1:].partition("]")
        if not closing or not _is_valid_ip_literal(literal):
            return False
    else:
        host, _, _ = host_port.partition(":")
        port_part = host_port[len(host) :]
        if not _is_valid_iri_component(host) or "[" in host or "]" in host:
            return False
    return not port_part or _PORT_PATTERN.fullmatch(port_part) is not None


def _is_absolute_iri(value: Any) -> bool:
    """Check whether a raw value is a syntactically valid absolute IRI.

    Validates the RFC 3987 ``absolute-IRI`` / ``IRI`` grammar (built on
    RFC 3986): a scheme of a letter followed by letters, digits, ``+``,
    ``-`` or ``.``; a non-empty remainder; legal characters and
    well-formed percent-encodings in every component; a well-formed
    authority when the remainder starts with ``//``; and, for ``urn:``,
    the RFC 8141 ``urn:<NID>:<NSS>`` shape. Hierarchical
    (``https://...``) and non-hierarchical (``mailto:...``, ``urn:...``)
    schemes are both accepted. Purely syntactic: nothing is resolved
    and no network access is made.

    Args:
        value: The raw value to check.

    Returns:
        bool: True if ``value`` is a string that is a valid absolute IRI.
    """
    if not isinstance(value, str):
        return False
    scheme, separator, rest = value.partition(":")
    if not (separator and rest and _IRI_SCHEME_PATTERN.fullmatch(scheme)):
        return False
    if scheme.lower() == "urn" and not _URN_PATTERN.fullmatch(value):
        return False

    rest, _, fragment = rest.partition("#")
    rest, _, query = rest.partition("?")
    if rest.startswith("//"):
        authority, slash, tail = rest[2:].partition("/")
        authority_ok = _is_valid_authority(authority)
        path = slash + tail
    else:
        # "scheme:" alone, or "scheme:?q" / "scheme:#f", identifies
        # nothing; an element identifier needs a non-empty body.
        authority_ok = bool(rest)
        path = rest
    return (
        authority_ok
        and _is_valid_iri_component(path, "/")
        and _is_valid_iri_component(query, "/?", allow_private=True)
        and _is_valid_iri_component(fragment, "/?")
    )


def _is_valid_timestamp(value: Any) -> bool:
    """Check whether a raw value is a valid UTC ``created`` timestamp.

    The accepted shape is ``YYYY-MM-DDTHH:MM:SS[.fraction]Z``: UTC only,
    with optional fractional seconds of any precision. Beyond the shape,
    the date must exist on the calendar (leap days included) and the
    time of day must be in range. Leap seconds (``:60``) are rejected.

    Args:
        value: The raw value to check.

    Returns:
        bool: True if ``value`` matches the shape and names a real
        instant.
    """
    if not isinstance(value, str):
        return False
    if (match := _TIMESTAMP_PATTERN.fullmatch(value)) is None:
        return False
    year, month, day, hour, minute, second = (int(part) for part in match.groups())
    try:
        datetime(year, month, day, hour, minute, second)
    except ValueError:
        return False
    return True


def _is_license_list_version(value: str) -> bool:
    """Check whether a string is a Semantic Versioning 2.0.0 version.

    Args:
        value: The candidate version string.

    Returns:
        bool: True if the whole string is a semver version; trailing or
        leading text is rejected.
    """
    return _LICENSE_LIST_VERSION_PATTERN.fullmatch(value) is not None


class _LicenseReference(Enum):
    """Outcome of resolving one license-valued reference."""

    RESOLVED = "resolved"
    MALFORMED = "malformed"
    DANGLING = "dangling"
    WRONG_TYPE = "wrong_type"


def _is_reference_shape(value: str) -> bool:
    """Check whether a string has the shape of an element reference.

    Args:
        value: The candidate reference.

    Returns:
        bool: True for an absolute IRI or a JSON-LD blank-node id
        (``_:label``).
    """
    return _is_absolute_iri(value) or (
        value.startswith(_BLANK_NODE_PREFIX) and len(value) > len(_BLANK_NODE_PREFIX)
    )


def _resolve_license_reference(doc: Spdx3Document, value: Any) -> _LicenseReference:
    """Resolve a license-valued reference to an AnyLicenseInfo element.

    Args:
        doc: The document adapter used to resolve references.
        value: The raw reference: an IRI or blank-node id string, or an
            inline element dict.

    Returns:
        _LicenseReference: ``RESOLVED`` when the value is an
        AnyLicenseInfo element (inline, present in the graph, an SPDX
        License List IRI, or one of the model's
        ``NoneLicense``/``NoAssertionLicense`` individuals);
        ``MALFORMED`` when it is not a reference at all; ``DANGLING``
        when it names no single element in the graph; ``WRONG_TYPE``
        when it names an element that is not AnyLicenseInfo.
    """
    if isinstance(value, dict):
        return (
            _LicenseReference.RESOLVED
            if any(_entry_has_type(value, name) for name in _ANY_LICENSE_INFO_TYPES)
            else _LicenseReference.WRONG_TYPE
        )
    if not isinstance(value, str) or not _is_reference_shape(value):
        return _LicenseReference.MALFORMED
    if (element := doc.element_by_id(value)) is None:
        if value in _LICENSE_INDIVIDUALS or _LICENSE_LIST_IRI_PATTERN.fullmatch(value):
            return _LicenseReference.RESOLVED
        return _LicenseReference.DANGLING
    if element.is_type(*_ANY_LICENSE_INFO_TYPES):
        return _LicenseReference.RESOLVED
    return _LicenseReference.WRONG_TYPE


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


class _ReferenceProblem(NamedTuple):
    """Message fragment and remediation for one unresolved-reference outcome."""

    problem: str
    remediation: str


_LICENSE_REFERENCE_PROBLEMS: dict[_LicenseReference, _ReferenceProblem] = {
    _LicenseReference.MALFORMED: _ReferenceProblem(
        "is not an IRI or blank-node reference",
        "Point the relationship's to at the IRI of a license element.",
    ),
    _LicenseReference.DANGLING: _ReferenceProblem(
        "is not present in the document",
        "Add the referenced license element to the @graph, or correct the "
        "dangling reference.",
    ),
    _LicenseReference.WRONG_TYPE: _ReferenceProblem(
        "does not identify an AnyLicenseInfo element",
        "Point the relationship at a license element such as a "
        "simplelicensing_LicenseExpression or expandedlicensing_ListedLicense.",
    ),
}


class _PackageLicenseRelationshipRule:
    """Base for license-relationship rules checking a relationship type.

    A package passes only when it has a relationship of the configured
    type whose targets resolve to AnyLicenseInfo elements. Every target
    that is dangling, malformed, or of the wrong type is reported on its
    own, even when another target resolves, matching how ``createdBy``
    references are reported.
    """

    rule_id: str
    description: str
    spdx_versions = _SPDX_3_0_1
    _relationship_type: str
    _label: str

    def evaluate(self, document: Any, _context: RuleContext) -> list[ValidationMessage]:
        """Evaluate each package's license relationship and its targets.

        Args:
            document: The raw SPDX 3.0.1 JSON-LD document.

        Returns:
            list[ValidationMessage]: One finding per package lacking a
            ``Relationship`` of the configured type with any target, and
            one finding per target that does not resolve to an
            AnyLicenseInfo element.
        """
        doc = Spdx3Document.from_dict(document)
        messages: list[ValidationMessage] = []
        for pkg in doc.packages():
            path = pkg.element_path()
            targets = [
                to_id
                for rel in doc.relationships_from(
                    pkg.element_id, self._relationship_type
                )
                for to_id in rel.to_ids
            ]
            if not targets:
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
                continue
            for target in targets:
                outcome = _resolve_license_reference(doc, target)
                if outcome is _LicenseReference.RESOLVED:
                    continue
                problem, remediation = _LICENSE_REFERENCE_PROBLEMS[outcome]
                messages.append(
                    _message(
                        rule_id=self.rule_id,
                        message=(
                            f"Package {path} {self._relationship_type} target "
                            f"{target!r} {problem}."
                        ),
                        field_path=path,
                        remediation=remediation,
                        section_reference="Licensing & copyright",
                        found_value=target,
                    )
                )
        return messages
