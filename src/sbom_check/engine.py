# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Main SBOM-Check validation engine."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from license_expression import get_spdx_licensing

from sbom_check.config.loader import ConfigLoader
from sbom_check.models import SbomCheckResult, ValidationSeverity
from spdx_validator.engine import ValidationEngine

if TYPE_CHECKING:
    from license_expression import Licensing

    from sbom_check.config.models import SbomCheckConfig

# SPDX sentinel values that are legal in license fields but are not license keys.
_LICENSE_SENTINELS = {"NOASSERTION", "NONE"}

_LICENSING: Licensing | None = None


def _licensing() -> Licensing:
    """Return a cached SPDX licensing parser (building one is expensive)."""
    global _LICENSING  # noqa: PLW0603  # pylint: disable=global-statement
    if _LICENSING is None:
        _LICENSING = get_spdx_licensing()
    return _LICENSING


class SbomCheckEngine:
    """Main validation engine that combines SPDX validation with custom rules."""

    def __init__(
        self,
        config: SbomCheckConfig | None = None,
        profile_name: str = "default",
    ) -> None:
        """Initialize the SBOM-Check engine.

        Args:
            config: Custom configuration to use
            profile_name: Profile name to use if config is not provided
        """
        if config is None:
            loader = ConfigLoader()
            config = loader.load_profile(profile_name)

        self.config = config

        # Initialize SPDX validator engine
        self.spdx_engine = ValidationEngine()

    def validate_file(self, file_path: Path | str) -> SbomCheckResult:
        """Validate an SPDX document from file.

        Args:
            file_path: Path to the SPDX JSON file

        Returns:
            Complete validation result
        """
        file_path = Path(file_path)

        try:
            with file_path.open(encoding="utf-8") as f:
                spdx_json = f.read()
            return self.validate_json_string(spdx_json, str(file_path))
        except FileNotFoundError:
            result = SbomCheckResult(
                overall_valid=False,
                spdx_valid=False,
                profile_valid=False,
                file_path=str(file_path),
                profile_name=self.config.metadata.name,
            )
            result.add_message(
                ValidationSeverity.ERROR,
                f"File not found: {file_path}",
                rule_id="file_not_found",
            )
            return result
        except (OSError, UnicodeDecodeError) as e:
            result = SbomCheckResult(
                overall_valid=False,
                spdx_valid=False,
                profile_valid=False,
                file_path=str(file_path),
                profile_name=self.config.metadata.name,
            )
            result.add_message(
                ValidationSeverity.ERROR,
                f"Error reading file {file_path}: {e!s}",
                rule_id="file_read_error",
            )
            return result

    def validate_json_string(
        self, spdx_json: str, file_path: str | None = None
    ) -> SbomCheckResult:
        """Validate an SPDX document from JSON string.

        Args:
            spdx_json: SPDX document as JSON string
            file_path: Optional file path for context

        Returns:
            Complete validation result
        """
        try:
            spdx_data = json.loads(spdx_json)
        except json.JSONDecodeError as e:
            result = SbomCheckResult(
                overall_valid=False,
                spdx_valid=False,
                profile_valid=False,
                file_path=file_path,
                profile_name=self.config.metadata.name,
            )
            result.add_message(
                ValidationSeverity.ERROR,
                f"Invalid JSON: {e!s}",
                rule_id="json_parse_error",
            )
            return result

        return self.validate_dict(spdx_data, file_path)

    def validate_dict(
        self, spdx_data: dict[str, Any], file_path: str | None = None
    ) -> SbomCheckResult:
        """Validate an SPDX document from dictionary.

        Args:
            spdx_data: SPDX document as dictionary
            file_path: Optional file path for context

        Returns:
            Complete validation result
        """
        # Run SPDX validation first
        spdx_result = self.spdx_engine.validate_dict(spdx_data)

        # Run custom profile validation
        profile_result = self._validate_profile_requirements(spdx_data)

        # Combine results
        combined_result = SbomCheckResult.combine(
            spdx_result=spdx_result,
            profile_result=profile_result,
            profile_name=self.config.metadata.name,
            file_path=file_path,
        )

        return combined_result

    def _validate_profile_requirements(
        self, spdx_data: dict[str, Any]
    ) -> SbomCheckResult:
        """Validate document against profile-specific requirements.

        Args:
            spdx_data: SPDX document as dictionary

        Returns:
            Profile validation result
        """
        result = SbomCheckResult(
            overall_valid=True,
            spdx_valid=True,  # This will be overridden in combine()
            profile_valid=True,
            profile_name=self.config.metadata.name,
        )

        # Validate document requirements
        self._validate_document_requirements(spdx_data, result)

        # Validate package requirements
        self._validate_package_requirements(spdx_data, result)

        # Validate file requirements
        self._validate_file_requirements(spdx_data, result)

        # Validate relationship requirements
        self._validate_relationship_requirements(spdx_data, result)

        # Run custom rules
        self._validate_custom_rules(spdx_data, result)

        return result

    def _validate_document_requirements(
        self, spdx_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate document-level requirements."""
        doc_config = self.config.document_requirements

        # Check required fields
        for field in doc_config.required_fields:
            if not self._get_nested_field(spdx_data, field):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"Required field '{field}' is missing",
                    rule_id="missing_required_field",
                    field_path=field,
                    section_reference="Document Requirements",
                )

        # Validate field-specific rules
        for field_name, rule in doc_config.field_validation.items():
            field_value = self._get_nested_field(spdx_data, field_name)

            if (
                hasattr(rule, "exact_value")
                and rule.exact_value
                and field_value != rule.exact_value
            ):
                result.add_message(
                    ValidationSeverity.ERROR,
                    rule.error_message
                    or f"Field '{field_name}' must be '{rule.exact_value}'",
                    rule_id="invalid_field_value",
                    field_path=field_name,
                    found_value=field_value,
                    expected_value=rule.exact_value,
                )

            if (
                hasattr(rule, "require_https_scheme")
                and rule.require_https_scheme
                and field_value
                and not str(field_value).startswith("https://")
            ):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"Field '{field_name}' must use HTTPS scheme",
                    rule_id="invalid_uri_scheme",
                    field_path=field_name,
                    found_value=field_value,
                )

            if (
                hasattr(rule, "prohibit_fragment")
                and rule.prohibit_fragment
                and field_value
                and "#" in str(field_value)
            ):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"Field '{field_name}' must not contain fragment identifier '#'",
                    rule_id="prohibited_uri_fragment",
                    field_path=field_name,
                    found_value=field_value,
                )

    def _validate_package_requirements(
        self, spdx_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate package-level requirements."""
        if not (packages := spdx_data.get("packages", [])):
            return

        pkg_config = self.config.package_requirements

        # Check build tools requirement
        if pkg_config.build_tools.require_build_tools:
            self._validate_build_tools_coverage(packages, result)

        # Pre-compute declared LicenseRef- ids once for license validation.
        declared_license_refs = {
            info["licenseId"]
            for info in spdx_data.get("hasExtractedLicensingInfos", [])
            if isinstance(info, dict) and "licenseId" in info
        }

        # Validate each package
        for i, package in enumerate(packages):
            self._validate_single_package(package, i, result)
            if pkg_config.validate_license_expressions:
                self._validate_package_licenses(
                    package, i, declared_license_refs, result
                )

    def _validate_package_licenses(
        self,
        package: dict[str, Any],
        index: int,
        declared_license_refs: set[str],
        result: SbomCheckResult,
    ) -> None:
        """Validate that package license fields are valid SPDX expressions.

        Each of ``licenseConcluded`` and ``licenseDeclared`` must be a valid SPDX
        license expression, the sentinels ``NOASSERTION``/``NONE``, or reference a
        ``LicenseRef-`` id declared in ``hasExtractedLicensingInfos``.
        """
        package_id = self._get_package_identifier(package, index)

        for field in ("licenseConcluded", "licenseDeclared"):
            if (value := package.get(field)) is None:
                continue

            if unknown := self._unknown_license_symbols(value, declared_license_refs):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"{package_id}: Field '{field}' is not a valid SPDX license "
                    f"expression (unknown: {', '.join(unknown)})",
                    rule_id="invalid_license_expression",
                    field_path=f"packages[{index}].{field}",
                    found_value=value,
                    remediation=(
                        "Use a valid SPDX license expression, 'NOASSERTION'/'NONE', "
                        "or a 'LicenseRef-' declared in hasExtractedLicensingInfos"
                    ),
                )

    def _unknown_license_symbols(
        self, value: str, declared_license_refs: set[str]
    ) -> list[str]:
        """Return license symbols in ``value`` that are not valid SPDX ids.

        Declared ``LicenseRef-`` ids are treated as known. An empty list means the
        expression is acceptable.
        """
        text = str(value).strip()
        if not text or text in _LICENSE_SENTINELS:
            return []

        licensing = _licensing()

        # Parse first to catch syntax errors; validate() cannot report unknown-key
        # symbols for a syntactically invalid expression (and raises on some).
        try:
            licensing.parse(text, validate=False, strict=False)
        except Exception:  # pylint: disable=broad-exception-caught
            # Any parse failure means the expression is syntactically invalid.
            return [text]

        info = licensing.validate(text)
        return [
            symbol
            for symbol in info.invalid_symbols
            if not (
                symbol.startswith("LicenseRef-") and symbol in declared_license_refs
            )
        ]

    def _validate_build_tools_coverage(
        self, packages: list[dict[str, Any]], result: SbomCheckResult
    ) -> None:
        """Validate that build tools are properly documented."""
        build_tool_examples = self.config.package_requirements.build_tools.examples

        # This is a simplified check - in practice, you'd want more sophisticated detection
        package_names = [pkg.get("name", "").lower() for pkg in packages]

        missing_tools = []
        for tool in build_tool_examples:
            if not any(tool.lower() in name for name in package_names):
                missing_tools.append(tool)

        if missing_tools:
            result.add_message(
                ValidationSeverity.WARNING,
                f"Potential missing build tools: {', '.join(missing_tools)}",
                rule_id="missing_build_tools",
                section_reference="Package Requirements - Build Tools",
                remediation="Ensure all build tools, compilers, and code generators are documented as packages",
            )

    def _get_package_identifier(self, package: dict[str, Any], index: int) -> str:
        """Get a human-readable identifier for a package.

        Uses SPDX ID if available, falls back to index.
        """
        if spdx_id := package.get("SPDXID"):
            return str(spdx_id)
        return f"Package {index}"

    def _validate_single_package(
        self, package: dict[str, Any], index: int, result: SbomCheckResult
    ) -> None:
        """Validate a single package against requirements."""
        pkg_config = self.config.package_requirements
        package_id = self._get_package_identifier(package, index)

        # Check required fields
        for field in pkg_config.required_fields:
            if field not in package:
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"{package_id}: Required field '{field}' is missing",
                    rule_id="missing_package_field",
                    field_path=f"packages[{index}].{field}",
                )

        # Validate filesAnalyzed business logic
        files_analyzed = package.get("filesAnalyzed")
        if files_analyzed is True:
            # Check required fields when filesAnalyzed is true
            for required_field in pkg_config.files_analyzed_rules.when_true_requires:
                if required_field not in package:
                    result.add_message(
                        ValidationSeverity.ERROR,
                        f"{package_id}: Field '{required_field}' is required when filesAnalyzed is true",
                        rule_id="files_analyzed_missing_field",
                        field_path=f"packages[{index}].{required_field}",
                    )
        elif files_analyzed is False:
            # Check prohibited fields when filesAnalyzed is false
            for (
                prohibited_field
            ) in pkg_config.files_analyzed_rules.when_false_prohibits:
                if prohibited_field in package:
                    result.add_message(
                        ValidationSeverity.ERROR,
                        f"{package_id}: Field '{prohibited_field}' is not allowed when filesAnalyzed is false",
                        rule_id="files_analyzed_prohibited_field",
                        field_path=f"packages[{index}].{prohibited_field}",
                    )

        # Validate external references
        self._validate_package_external_refs(package, index, result)

    def _validate_package_external_refs(
        self, package: dict[str, Any], index: int, result: SbomCheckResult
    ) -> None:
        """Validate package external references."""
        external_refs = package.get("externalRefs", [])
        ext_config = self.config.package_requirements.external_refs
        package_id = self._get_package_identifier(package, index)

        # Check required reference types
        for required_ref in ext_config.required_types:
            found = any(
                ref.get("referenceType") == required_ref.reference_type
                for ref in external_refs
            )
            if not found:
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"{package_id}: Missing required external reference type '{required_ref.reference_type}'",
                    rule_id="missing_external_ref",
                    field_path=f"packages[{index}].externalRefs",
                    remediation=required_ref.description,
                )

    def _validate_file_requirements(
        self, spdx_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate file-level requirements."""
        # This is a placeholder for file validation logic
        # Implementation would depend on the specific file requirements
        # Currently no file-level validation rules are implemented
        _ = spdx_data, result  # Acknowledge unused parameters

    def _validate_relationship_requirements(
        self, spdx_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate relationship requirements."""
        relationships = spdx_data.get("relationships", [])
        rel_config = self.config.relationship_requirements

        if rel_config.no_isolated_elements:
            # Check that all elements are properly related
            # This is a simplified check - full implementation would be more complex
            document_id = spdx_data.get("SPDXID", "SPDXRef-DOCUMENT")

            # Check for DESCRIBES relationship from document
            has_describes = any(
                rel.get("spdxElementId") == document_id
                and rel.get("relationshipType") == "DESCRIBES"
                for rel in relationships
            )

            if not has_describes:
                result.add_message(
                    ValidationSeverity.ERROR,
                    "Document must have at least one DESCRIBES relationship",
                    rule_id="missing_describes_relationship",
                    section_reference="Relationship Requirements",
                )

    def _validate_custom_rules(
        self, _spdx_data: dict[str, Any], _result: SbomCheckResult
    ) -> None:
        """Validate custom rules."""
        for _rule in self.config.custom_rules:
            # This is a placeholder for custom rule validation
            # In practice, you'd implement specific validation functions
            # The _spdx_data and _result parameters would be used here
            pass

    def _get_nested_field(self, data: dict[str, Any], field_path: str) -> Any:
        """Get a nested field value using dot notation."""
        parts = field_path.split(".")
        current = data

        for part in parts:
            if isinstance(current, dict) and part in current:
                current = current[part]
            else:
                return None

        return current
