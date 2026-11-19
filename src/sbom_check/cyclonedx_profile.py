# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Qualcomm completeness profile for CycloneDX documents.

Structural schema errors and semantic integrity errors (duplicate or
dangling references) come from :mod:`cyclone_validator` and are always hard
errors. This module adds the completeness layer on top: checks that a
schema-valid document actually carries the content Qualcomm needs. Every
check's severity comes from the profile, so a vendor override can relax or
disable a check without a code change.

Rule ids are prefixed ``cyclonedx_completeness.`` so callers can tell these
findings apart from ``cyclonedx_schema_error`` and ``cyclonedx_semantic.*``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from packageurl import PackageURL

from cyclone_validator.validators import iter_bom_ref_holders
from sbom_check.models import ValidationMessage, ValidationSeverity

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sbom_check.config.models import CycloneDXRequirementsConfig

SECTION = "CycloneDX Completeness"
RULE_PREFIX = "cyclonedx_completeness."


def validate_cyclonedx_completeness(
    document: dict[str, Any], config: CycloneDXRequirementsConfig
) -> list[ValidationMessage]:
    """Return completeness findings for a CycloneDX document.

    Args:
        document: Parsed CycloneDX JSON document.
        config: The active profile's CycloneDX requirements.

    Returns:
        Findings with severities taken from ``config.severities``. Checks
        configured as ``"OFF"`` produce nothing.
    """
    findings: list[ValidationMessage] = []

    def emit(check: str, message: str, **details: Any) -> None:
        if (severity := config.severity(check)) == "OFF":
            return
        findings.append(
            ValidationMessage(
                severity=ValidationSeverity(severity),
                message=message,
                rule_id=RULE_PREFIX + check,
                section_reference=SECTION,
                **details,
            )
        )

    _check_spec_version(document, config, emit)
    _check_document_fields(document, config, emit)

    if not (components := list(_iter_components(document))):
        emit(
            "no_components",
            "The SBOM lists no components. Creator and tool metadata alone "
            "is not an SBOM: it must list the software it describes.",
            field_path="$.components",
            remediation=(
                "Regenerate the SBOM with every package, library and binary "
                "you ship listed as a component, each with its name, version, "
                "supplier and package URL (purl)."
            ),
        )
    else:
        _check_dependency_graph(document, emit)

    for path, component in components:
        _check_component(path, component, config, emit)

    return findings


def _check_spec_version(
    document: dict[str, Any], config: CycloneDXRequirementsConfig, emit: Any
) -> None:
    version = document.get("specVersion")
    if not isinstance(version, str):
        return
    if version_tuple(version) < version_tuple(config.minimum_spec_version):
        emit(
            "below_minimum_spec_version",
            f"The SBOM uses CycloneDX {version}, but this profile requires "
            f"CycloneDX {config.minimum_spec_version} or newer.",
            field_path="$.specVersion",
            found_value=version,
            expected_value=f">= {config.minimum_spec_version}",
            remediation=(
                "Configure your SBOM tool to produce CycloneDX "
                f"{config.minimum_spec_version} or newer."
            ),
        )


def _check_document_fields(
    document: dict[str, Any], config: CycloneDXRequirementsConfig, emit: Any
) -> None:
    for field in config.document_required_fields:
        if _is_missing(_get(document, field)):
            emit(
                "missing_document_field",
                f"The SBOM is missing the document field '{field}'.",
                field_path=f"$.{field}",
                remediation=_DOCUMENT_FIELD_HELP.get(
                    field, f"Add '{field}' to the top of the SBOM."
                ),
            )


def _check_dependency_graph(document: dict[str, Any], emit: Any) -> None:
    dependencies = document.get("dependencies")
    has_edge = isinstance(dependencies, list) and any(
        isinstance(entry, dict)
        and isinstance(entry.get("dependsOn"), list)
        and entry["dependsOn"]
        for entry in dependencies
    )
    if not has_edge:
        emit(
            "missing_dependency_graph",
            "The SBOM lists components but does not say how they depend on "
            "each other: no dependency entry has a non-empty 'dependsOn'.",
            field_path="$.dependencies",
            remediation=(
                "Add a 'dependencies' section that records, for your product "
                "and each component, which components it depends on. Most SBOM "
                "tools do this when run against the build or lock file rather "
                "than a source directory scan."
            ),
        )


def _check_component(
    path: str,
    component: dict[str, Any],
    config: CycloneDXRequirementsConfig,
    emit: Any,
) -> None:
    label = _component_label(component, path)
    for field in config.component_required_fields:
        if _is_missing(_get(component, field)):
            emit(
                "missing_component_field",
                f"Component {label} is missing '{field}'.",
                field_path=f"{path}.{field}",
                remediation=_COMPONENT_FIELD_HELP.get(
                    field, f"Add '{field}' to the component."
                ),
            )

    purl = component.get("purl")
    if isinstance(purl, str) and purl and (problem := purl_problem(purl)):
        emit(
            "invalid_purl",
            f"Component {label} has a package URL (purl) that is not valid: "
            f"{problem}. Vulnerability databases match components by purl, so "
            "this component may be silently missed when the SBOM is scanned.",
            field_path=f"{path}.purl",
            found_value=purl,
            remediation=(
                "Correct the purl so it follows the Package URL rules for its "
                "ecosystem (https://github.com/package-url/purl-spec), for "
                "example 'pkg:maven/org.apache.commons/commons-lang3@3.14.0'."
            ),
        )


def purl_problem(purl: str) -> str | None:
    """Return why a purl is invalid for its ecosystem, or None when it is valid."""
    errors = [
        message.message
        for message in PackageURL.validate_string(purl)
        if message.severity.value == "error"
    ]
    return "; ".join(errors) or None


def _iter_components(
    document: dict[str, Any],
) -> Iterable[tuple[str, dict[str, Any]]]:
    """Yield top-level and nested components, excluding metadata.component."""
    for path, element in iter_bom_ref_holders(document):
        if path.startswith("$.components") and ".services" not in path:
            yield path, element


def _component_label(component: dict[str, Any], path: str) -> str:
    name = component.get("name")
    if isinstance(name, str) and name:
        version = component.get("version")
        return f"'{name}@{version}'" if version else f"'{name}'"
    if isinstance(ref := component.get("bom-ref"), str) and ref:
        return f"'{ref}'"
    return f"at {path}"


def _get(data: Any, dotted: str) -> Any:
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _is_missing(value: Any) -> bool:
    if value is None or value in ("", [], {}):
        return True
    # metadata.tools is an array before CycloneDX 1.5 and an object of
    # {components, services} arrays from 1.5 on; an object with only empty
    # arrays names no tool.
    if isinstance(value, dict) and set(value) <= {"components", "services"}:
        return not any(value.get(key) for key in ("components", "services"))
    return False


def version_tuple(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return (0,)


_DOCUMENT_FIELD_HELP = {
    "serialNumber": (
        "Give the SBOM a unique serial number in the form "
        "'urn:uuid:<uuid>'; most tools generate one automatically."
    ),
    "version": "Set the SBOM's 'version' to 1, and increase it on each revision.",
    "metadata.timestamp": (
        "Record when the SBOM was generated in 'metadata.timestamp' "
        "(for example 2026-01-31T12:00:00Z)."
    ),
    "metadata.tools": (
        "Record the tool that generated the SBOM, with its name and version, "
        "in 'metadata.tools'."
    ),
}

_COMPONENT_FIELD_HELP = {
    "name": "Give every component its package or product name.",
    "version": "Record the exact version of the component you ship.",
    "supplier.name": (
        "Name the organization that supplies the component in "
        "'supplier.name': your company for your own code, or the upstream "
        "project or vendor for third-party code."
    ),
    "purl": (
        "Add a package URL (purl) identifying the component, for example "
        "'pkg:pypi/requests@2.32.0'. Vulnerability scanners rely on it."
    ),
    "bom-ref": (
        "Give the component a unique 'bom-ref' so the dependencies section "
        "can refer to it."
    ),
    "type": "Set the component 'type', for example 'library' or 'application'.",
}

__all__ = ["purl_problem", "validate_cyclonedx_completeness", "version_tuple"]
