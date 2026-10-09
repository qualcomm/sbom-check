# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Main SBOM-Check validation engine."""

from __future__ import annotations

import json
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any
from warnings import warn

from sbom_check.config.loader import ConfigLoader
from sbom_check.detection import (
    UnsupportedDocumentError,
    detect_document,
    get_document_version,
)
from sbom_check.models import (
    DocumentFormat,
    ProfileStatus,
    SbomCheckResult,
    ValidationMessage,
    ValidationSeverity,
    ValidationSummary,
)
from spdx_validator.engine import ValidationEngine

if TYPE_CHECKING:
    from sbom_check.config.models import SbomCheckConfig
    from sbom_validator.engine import ValidatorEngine


class SbomCheckEngine:
    """Main engine that combines core validation with format-specific profile validation."""

    def __init__(
        self,
        config: SbomCheckConfig | None = None,
        profile_name: str = "default",
        validator_class: type[ValidatorEngine] | None = None,
    ) -> None:
        """Initialize the SBOM-Check engine.

        Args:
            config: Custom configuration to use
            profile_name: Profile name to use if config is not provided
            validator_class: Validator engine class to instantiate
        """
        if config is None:
            loader = ConfigLoader()
            config = loader.load_profile(profile_name)

        self.config = config
        self.engine = validator_class() if validator_class is not None else None

    @cached_property
    def spdx_engine(self) -> ValidatorEngine:
        """Legacy access to the SPDX 2.x validator.

        Deprecated: validation now selects an engine based on the document.
        """
        warn(
            "SbomCheckEngine.spdx_engine is deprecated; use validate_dict() or "
            "validate_file(). Validation engines are selected automatically per "
            "document, or explicitly with validator_class.",
            DeprecationWarning,
            stacklevel=2,
        )

        return ValidationEngine()

    def validate_file(self, file_path: Path | str) -> SbomCheckResult:
        """Validate an SBOM document from file.

        Args:
            file_path: Path to the SBOM JSON file

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
                spdx_valid=None,
                profile_valid=None,
                core_valid=False,
                profile_status=ProfileStatus.NOT_APPLICABLE,
                document_format=DocumentFormat.UNKNOWN,
                spec_version=None,
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
                spdx_valid=None,
                profile_valid=None,
                core_valid=False,
                profile_status=ProfileStatus.NOT_APPLICABLE,
                document_format=DocumentFormat.UNKNOWN,
                spec_version=None,
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
        """Validate an SBOM document from JSON string.

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
                spdx_valid=None,
                profile_valid=None,
                core_valid=False,
                profile_status=ProfileStatus.NOT_APPLICABLE,
                document_format=DocumentFormat.UNKNOWN,
                spec_version=None,
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
        selected_engine = None
        document_format: DocumentFormat = DocumentFormat.UNKNOWN
        spec_version = None

        try:
            if self.engine is None:
                detected = detect_document(spdx_data)

                selected_engine = detected.validator_class()
                document_format = detected.format
                spec_version = detected.spec_version
            else:
                selected_engine = self.engine
                document_format = selected_engine.format
                spec_version = get_document_version(document_format, spdx_data)
        except UnsupportedDocumentError as error:
            return self._unsupported_result(error, file_path=file_path)

        profile_applicable = document_format is DocumentFormat.SPDX

        # Run the selected format engine.
        core_result = selected_engine.validate_dict(spdx_data)

        # The completeness profile is SPDX-specific.
        profile_result = (
            self._validate_profile_requirements(spdx_data)
            if profile_applicable
            else None
        )

        # Combine results
        combined_result = SbomCheckResult.combine(
            core_result=core_result,
            profile_result=profile_result,
            profile_name=self.config.metadata.name,
            file_path=file_path,
            document_format=document_format,
            spec_version=spec_version,
        )

        return combined_result

    def _unsupported_result(
        self, error: UnsupportedDocumentError, file_path: str | None = None
    ) -> SbomCheckResult:
        """Create a structured result for unsupported input."""
        return SbomCheckResult(
            overall_valid=False,
            spdx_valid=None,
            profile_valid=None,
            core_valid=False,
            profile_status=ProfileStatus.NOT_APPLICABLE,
            messages=[
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=str(error),
                    rule_id=error.rule_id,
                )
            ],
            summary=ValidationSummary(errors=1, failed_rules=1),
            profile_name=None,
            file_path=file_path,
            document_format=DocumentFormat.UNKNOWN,
            spec_version=None,
        )

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
            core_valid=True,
            profile_status=ProfileStatus.PASSED,
            profile_name=self.config.metadata.name,
            document_format=DocumentFormat.SPDX,
            spec_version="2.3",
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

        # Validate each package
        for i, package in enumerate(packages):
            self._validate_single_package(package, i, result)

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
