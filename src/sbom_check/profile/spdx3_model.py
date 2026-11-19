# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Typed adapter over raw SPDX 3.0.1 JSON-LD documents.

This module converts a raw SPDX 3.0.1 ``@graph`` document into a typed,
queryable element graph so that profile rules can be written against a
stable API instead of performing raw JSON-LD traversal. No validation
rules or :class:`~sbom_check.models.ValidationMessage` construction live
here; this is pure data access and must never raise on malformed input.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_SPDX_IRI_PREFIX = "https://spdx.org/rdf/3.0.1/terms/"
_SPDX_PREFIX = "spdx:"

_AGENT_TYPES = ("Agent", "Organization", "Person", "Tool")
_MIN_NAMESPACED_PARTS = 2


def _normalize_type(raw_type: str) -> str:
    """Normalize a single SPDX type spelling to its short prefixed form.

    Args:
        raw_type: A type value as it appears in the raw document: a
            short prefixed form (``software_Package``), a full IRI
            (``https://spdx.org/rdf/3.0.1/terms/Software/Package``), or
            a ``spdx:``-prefixed form (``spdx:Software/Package``).

    Returns:
        str: The short prefixed form, e.g. ``software_Package`` or
        ``Agent``. Unrecognized spellings are returned unchanged.
    """
    value = raw_type
    if value.startswith(_SPDX_IRI_PREFIX):
        value = value[len(_SPDX_IRI_PREFIX) :]
    elif value.startswith(_SPDX_PREFIX):
        value = value[len(_SPDX_PREFIX) :]
    else:
        return value

    if not (parts := [part for part in value.split("/") if part]):
        return raw_type

    name = parts[-1]
    if len(parts) >= _MIN_NAMESPACED_PARTS:
        namespace = parts[-2]
        if namespace.lower() == "core":
            return name
        return f"{namespace.lower()}_{name}"
    return name


def _normalize_relationship_type(raw_value: Any) -> str | None:
    """Normalize a ``relationshipType`` value to its short enumeration name.

    ``relationshipType`` is IRI-valued in the SPDX 3.0.1 model, so a
    conforming document may spell ``describes`` as the short JSON-LD term,
    as a ``spdx:``-prefixed name, or as the fully expanded
    ``.../Core/RelationshipType/describes`` IRI. Rules compare against the
    short name, so every spelling is reduced to it here.

    Args:
        raw_value: The raw ``relationshipType`` value, expected to be a
            string; any other type yields None.

    Returns:
        str | None: The short enumeration name (e.g. ``describes``), or
        None when ``raw_value`` is not a string.
    """
    if not isinstance(raw_value, str):
        return None
    value = raw_value
    if value.startswith(_SPDX_IRI_PREFIX):
        value = value[len(_SPDX_IRI_PREFIX) :]
    elif value.startswith(_SPDX_PREFIX):
        value = value[len(_SPDX_PREFIX) :]
    else:
        return value

    if not (parts := [part for part in value.split("/") if part]):
        return raw_value
    return parts[-1]


def _coerce_type_list(raw_value: Any) -> list[str]:
    """Coerce a raw ``type``/``@type`` value into a list of raw type strings.

    Args:
        raw_value: The raw value of a ``type`` or ``@type`` property,
            which may be a string, a list of strings, or absent/None.

    Returns:
        list[str]: Raw (un-normalized) type strings, empty if none found.
    """
    if raw_value is None:
        return []
    if isinstance(raw_value, str):
        return [raw_value]
    if isinstance(raw_value, list):
        return [item for item in raw_value if isinstance(item, str)]
    return []


def _as_id_list(raw_value: Any) -> list[str]:
    """Coerce a raw IRI-valued property into a list of IRI strings.

    Args:
        raw_value: A raw property value that may be a single IRI
            string, a list of IRI strings (with possible non-string
            noise), or absent/None.

    Returns:
        list[str]: The IRI strings found, in order, empty if none.
    """
    if raw_value is None:
        return []
    if isinstance(raw_value, str):
        return [raw_value]
    if isinstance(raw_value, list):
        return [item for item in raw_value if isinstance(item, str)]
    return []


@dataclass(frozen=True)
class Spdx3Element:
    """A single element parsed from an SPDX 3.0.1 ``@graph`` entry."""

    element_id: str | None
    element_type: str | None
    element_types: tuple[str, ...]
    raw: dict[str, Any]
    graph_index: int

    def get(self, prop: str, default: Any = None) -> Any:
        """Read a raw property from this element.

        Args:
            prop: The property name as it appears in the raw JSON-LD.
            default: The value to return when the property is absent.

        Returns:
            Any: The raw property value, or ``default`` if absent.
        """
        return self.raw.get(prop, default)

    def element_path(self) -> str:
        """Return a stable path for this element for use in messages.

        Args:
            None.

        Returns:
            str: The element id if present, otherwise ``@graph[<index>]``.
        """
        if self.element_id:
            return self.element_id
        return f"@graph[{self.graph_index}]"

    def is_type(self, *types: str) -> bool:
        """Check whether this element has any of the given normalized types.

        Args:
            *types: One or more normalized short type names to test for.

        Returns:
            bool: True if any of ``types`` is among this element's
            normalized ``element_types``.
        """
        return any(candidate in self.element_types for candidate in types)


@dataclass(frozen=True)
class Spdx3Relationship:
    """A typed view of a ``Relationship`` element."""

    from_id: str | None
    relationship_type: str | None
    to_ids: tuple[str, ...]
    element: Spdx3Element


@dataclass(frozen=True)
class Spdx3ExternalIdentifier:
    """A typed view of an ``ExternalIdentifier`` element or inline value."""

    identifier_type: str | None
    identifier: str | None
    raw: dict[str, Any]


@dataclass(frozen=True)
class _AgentResolution:
    """Internal result of resolving an agent-valued property."""

    agent: Spdx3Element | None
    reference_is_dangling: bool


def _element_id_of(raw: Any) -> str | None:
    """Extract the id (``spdxId`` or ``@id``) from a raw element dict.

    Args:
        raw: The candidate raw element, expected to be a dict.

    Returns:
        str | None: The element id if present and a string, else None.
    """
    if not isinstance(raw, dict):
        return None
    for key in ("spdxId", "@id"):
        value = raw.get(key)
        if isinstance(value, str):
            return value
    return None


def _element_types_of(raw: Any) -> tuple[str, ...]:
    """Extract and normalize all types from a raw element dict.

    Args:
        raw: The candidate raw element, expected to be a dict.

    Returns:
        tuple[str, ...]: Normalized type names, in document order.
    """
    if not isinstance(raw, dict):
        return ()
    raw_types = _coerce_type_list(raw.get("type")) or _coerce_type_list(
        raw.get("@type")
    )
    return tuple(_normalize_type(t) for t in raw_types)


def _build_element(raw: Any, graph_index: int) -> Spdx3Element | None:
    """Build a :class:`Spdx3Element` from a raw ``@graph`` entry.

    Args:
        raw: The candidate raw entry from ``@graph``.
        graph_index: The entry's position in ``@graph``.

    Returns:
        Spdx3Element | None: The built element, or None if ``raw`` is
        not a dict.
    """
    if not isinstance(raw, dict):
        return None
    types = _element_types_of(raw)
    element_type = types[0] if types else None
    return Spdx3Element(
        element_id=_element_id_of(raw),
        element_type=element_type,
        element_types=types,
        raw=raw,
        graph_index=graph_index,
    )


@dataclass(frozen=True)
class Spdx3Document:
    """A typed, queryable view over a parsed SPDX 3.0.1 JSON-LD document.

    Lookups by id and by relationship source are served from indexes
    built once per document. Rules are run per element, so linear scans
    here would make a whole validation run quadratic in graph size.
    """

    elements: tuple[Spdx3Element, ...] = field(default_factory=tuple)
    _by_id: dict[str, Spdx3Element] = field(
        default_factory=dict, repr=False, compare=False
    )
    _relationships: tuple[Spdx3Relationship, ...] = field(
        default_factory=tuple, repr=False, compare=False
    )
    _relationships_by_from: dict[str, tuple[Spdx3Relationship, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )
    _duplicates: dict[str, tuple[Spdx3Element, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> Spdx3Document:
        """Build a document adapter from a raw SPDX 3.0.1 JSON-LD dict.

        Args:
            document: The raw parsed JSON document, expected to have an
                ``@graph`` list. Malformed shapes degrade gracefully to
                an empty document rather than raising.

        Returns:
            Spdx3Document: The adapted document. Never raises.
        """
        graph = document.get("@graph") if isinstance(document, dict) else None
        if not isinstance(graph, list):
            return cls(elements=())

        elements: list[Spdx3Element] = []
        for index, entry in enumerate(graph):
            if (built := _build_element(entry, index)) is not None:
                elements.append(built)

        # An id defined more than once is ambiguous: picking either
        # definition would let a reference be satisfied by an element the
        # producer may not have meant. Such ids are recorded as duplicates
        # for the identifier rules to report and are left out of the index,
        # so no reference can resolve through them.
        by_id_all: dict[str, list[Spdx3Element]] = {}
        for element in elements:
            if element.element_id is not None:
                by_id_all.setdefault(element.element_id, []).append(element)
        by_id = {
            element_id: defs[0]
            for element_id, defs in by_id_all.items()
            if len(defs) == 1
        }
        duplicates = {
            element_id: tuple(defs)
            for element_id, defs in by_id_all.items()
            if len(defs) > 1
        }

        relationships = tuple(
            Spdx3Relationship(
                from_id=(
                    from_value
                    if isinstance(from_value := element.get("from"), str)
                    else None
                ),
                relationship_type=_normalize_relationship_type(
                    element.get("relationshipType")
                ),
                to_ids=tuple(_as_id_list(element.get("to"))),
                element=element,
            )
            for element in elements
            if element.is_type("Relationship")
        )

        by_from: dict[str, list[Spdx3Relationship]] = {}
        for relationship in relationships:
            if relationship.from_id is not None:
                by_from.setdefault(relationship.from_id, []).append(relationship)

        return cls(
            elements=tuple(elements),
            _by_id=by_id,
            _relationships=relationships,
            _relationships_by_from={
                key: tuple(value) for key, value in by_from.items()
            },
            _duplicates=duplicates,
        )

    def duplicate_ids(self) -> dict[str, tuple[Spdx3Element, ...]]:
        """List ids defined by more than one ``@graph`` entry.

        Args:
            None.

        Returns:
            dict[str, tuple[Spdx3Element, ...]]: Each duplicated id mapped
            to every element defining it, in document order. Duplicated
            ids never resolve through :meth:`element_by_id`.
        """
        return dict(self._duplicates)

    def elements_of_type(self, *types: str) -> list[Spdx3Element]:
        """List all elements matching any of the given normalized types.

        Args:
            *types: One or more normalized short type names.

        Returns:
            list[Spdx3Element]: Matching elements, in document order.
        """
        return [element for element in self.elements if element.is_type(*types)]

    def element_by_id(self, element_id: str | None) -> Spdx3Element | None:
        """Look up an element by its id.

        Args:
            element_id: The element id to look up. None always misses.

        Returns:
            Spdx3Element | None: The matching element, or None if not
            found, if ``element_id`` is None, or if the id is defined
            more than once (see :meth:`duplicate_ids`).
        """
        if not element_id:
            return None
        return self._by_id.get(element_id)

    def packages(self) -> list[Spdx3Element]:
        """List all ``software_Package`` elements.

        Args:
            None.

        Returns:
            list[Spdx3Element]: All package elements, in document order.
        """
        return self.elements_of_type("software_Package")

    def files(self) -> list[Spdx3Element]:
        """List all ``software_File`` elements.

        Args:
            None.

        Returns:
            list[Spdx3Element]: All file elements, in document order.
        """
        return self.elements_of_type("software_File")

    def spdx_document(self) -> Spdx3Element | None:
        """Return the single ``SpdxDocument`` element, if present.

        Args:
            None.

        Returns:
            Spdx3Element | None: The first ``SpdxDocument`` element
            found, or None if there isn't one.
        """
        documents = self.elements_of_type("SpdxDocument")
        return documents[0] if documents else None

    def creation_info_for(self, element: Spdx3Element) -> Spdx3Element | None:
        """Resolve an element's ``creationInfo`` reference.

        Args:
            element: The element whose ``creationInfo`` property should
                be resolved.

        Returns:
            Spdx3Element | None: The referenced ``CreationInfo``
            element. If the raw value is a nested dict rather than a
            reference, it is wrapped and returned directly. None when
            absent, when the reference is dangling, or when the value
            does not have type ``CreationInfo``: another element that
            happens to carry ``created`` or ``specVersion`` fields must
            not stand in for creation metadata.
        """
        value = element.get("creationInfo")
        resolved: Spdx3Element | None = None
        if isinstance(value, dict):
            resolved = _build_element(value, element.graph_index)
        elif isinstance(value, str):
            resolved = self.element_by_id(value)
        if resolved is None or not resolved.is_type("CreationInfo"):
            return None
        return resolved

    def creation_info_is_wrong_type(self, element: Spdx3Element) -> bool:
        """Check whether ``creationInfo`` names an element that is not CreationInfo.

        Args:
            element: The element whose ``creationInfo`` should be checked.

        Returns:
            bool: True if ``creationInfo`` is an inline dict, or a
            reference resolving to a present element, whose type is not
            ``CreationInfo``. False when absent, dangling, or correct.
        """
        value = element.get("creationInfo")
        target: Spdx3Element | None = None
        if isinstance(value, dict):
            target = _build_element(value, element.graph_index)
        elif isinstance(value, str):
            target = self.element_by_id(value)
        return target is not None and not target.is_type("CreationInfo")

    def agents(self) -> list[Spdx3Element]:
        """List all agent-like elements.

        Args:
            None.

        Returns:
            list[Spdx3Element]: All ``Agent``, ``Organization``,
            ``Person``, and ``Tool`` elements, in document order.
        """
        return self.elements_of_type(*_AGENT_TYPES)

    def relationships(self) -> list[Spdx3Relationship]:
        """List all ``Relationship`` elements as typed views.

        Args:
            None.

        Returns:
            list[Spdx3Relationship]: All relationships, in document order.
        """
        return list(self._relationships)

    def relationships_from(
        self, from_id: str | None, relationship_type: str | None = None
    ) -> list[Spdx3Relationship]:
        """List relationships originating from a given element id.

        Args:
            from_id: The id of the element the relationship must
                originate from.
            relationship_type: If given, further filter to
                relationships with this exact ``relationshipType``.

        Returns:
            list[Spdx3Relationship]: Matching relationships, in
            document order. Empty when ``from_id`` is None.
        """
        if not from_id:
            return []
        matches = list(self._relationships_by_from.get(from_id, ()))
        if relationship_type is not None:
            matches = [
                rel for rel in matches if rel.relationship_type == relationship_type
            ]
        return matches

    def has_relationship(self, from_id: str | None, relationship_type: str) -> bool:
        """Check whether a relationship of the given type exists from an element.

        Args:
            from_id: The id of the element the relationship must
                originate from.
            relationship_type: The exact ``relationshipType`` to look for.

        Returns:
            bool: True if at least one such relationship exists.
        """
        return bool(self.relationships_from(from_id, relationship_type))

    def external_identifiers(
        self, element: Spdx3Element
    ) -> list[Spdx3ExternalIdentifier]:
        """Resolve an element's ``externalIdentifier`` property.

        Args:
            element: The element whose external identifiers should be
                resolved.

        Returns:
            list[Spdx3ExternalIdentifier]: The resolved external
            identifiers. Handles a single inline dict, a list of inline
            dicts, and a list of IRI strings referencing top-level
            ``ExternalIdentifier`` elements (any mix thereof).
        """
        if (raw_value := element.get("externalIdentifier")) is None:
            return []
        items: list[Any] = raw_value if isinstance(raw_value, list) else [raw_value]

        result: list[Spdx3ExternalIdentifier] = []
        for item in items:
            if isinstance(item, dict):
                result.append(self._external_identifier_from_dict(item))
            elif (
                isinstance(item, str)
                and (resolved := self.element_by_id(item)) is not None
            ):
                result.append(self._external_identifier_from_dict(resolved.raw))
        return result

    @staticmethod
    def _external_identifier_from_dict(raw: dict[str, Any]) -> Spdx3ExternalIdentifier:
        """Build an external identifier view from an inline dict.

        Args:
            raw: The raw ``ExternalIdentifier`` dict.

        Returns:
            Spdx3ExternalIdentifier: The typed view of ``raw``.
        """
        identifier_type_value = raw.get("externalIdentifierType")
        identifier_value = raw.get("identifier")
        return Spdx3ExternalIdentifier(
            identifier_type=(
                identifier_type_value
                if isinstance(identifier_type_value, str)
                else None
            ),
            identifier=(
                identifier_value if isinstance(identifier_value, str) else None
            ),
            raw=raw,
        )

    def _resolve_agent_reference(
        self, element: Spdx3Element, prop: str
    ) -> _AgentResolution:
        """Resolve an agent-valued property, distinguishing absent from dangling.

        Args:
            element: The element carrying the agent-valued property.
            prop: The property name (e.g. ``suppliedBy``, ``originatedBy``).

        Returns:
            _AgentResolution: The resolved agent (if any) and whether a
            stated reference failed to resolve to a present element.
        """
        value = element.get(prop)
        if isinstance(value, dict):
            built = _build_element(value, element.graph_index)
            return _AgentResolution(agent=built, reference_is_dangling=False)
        if isinstance(value, str):
            if (resolved := self.element_by_id(value)) is None:
                return _AgentResolution(agent=None, reference_is_dangling=True)
            return _AgentResolution(agent=resolved, reference_is_dangling=False)
        return _AgentResolution(agent=None, reference_is_dangling=False)

    def resolve_agent(self, element: Spdx3Element, prop: str) -> Spdx3Element | None:
        """Resolve an agent-valued property to its Agent element.

        Args:
            element: The element carrying the agent-valued property
                (e.g. ``suppliedBy``, ``originatedBy``).
            prop: The property name to resolve.

        Returns:
            Spdx3Element | None: The resolved agent element. None both
            when the property is absent and when it is stated but
            unresolvable; use :meth:`reference_is_dangling` to tell
            those two cases apart.
        """
        return self._resolve_agent_reference(element, prop).agent

    def reference_is_dangling(self, element: Spdx3Element, prop: str) -> bool:
        """Check whether an agent-valued property is stated but unresolvable.

        Args:
            element: The element carrying the agent-valued property.
            prop: The property name to check.

        Returns:
            bool: True if ``prop`` holds an IRI reference that does not
            resolve to any present element. False when the property is
            absent entirely or resolves successfully.
        """
        return self._resolve_agent_reference(element, prop).reference_is_dangling
