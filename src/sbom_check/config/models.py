# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration data models for SBOM-Check."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ConfigMetadata(BaseModel):
    """Metadata about the configuration."""

    name: str
    version: str
    description: str | None = None
    reference_url: str | None = None
    effective_date: str | None = None


class SpdxValidationConfig(BaseModel):
    """Configuration for core SPDX validation."""

    enable_schema_validation: bool = True
    enable_semantic_validation: bool = True
    require_zero_validation_errors: bool = True
    require_zero_validation_warnings: bool = False


class FormatRequirementsConfig(BaseModel):
    """Configuration for supported file formats."""

    allowed_formats: list[str] = Field(default_factory=lambda: ["json"])
    file_extensions: list[str] = Field(default_factory=lambda: [".spdx.json"])


class FieldValidationRule(BaseModel):
    """Configuration for validating a specific field."""

    required: bool = False
    exact_value: str | None = None
    pattern: str | None = None
    pattern_description: str | None = None
    must_be_uri: bool = False
    require_https_scheme: bool = False
    prohibit_fragment: bool = False
    format: str | None = None
    min_count: int | None = None
    max_count: int | None = None
    allowed_values: list[str] | None = None
    error_message: str | None = None
    description: str | None = None


class CreatorTypeRule(BaseModel):
    """Configuration for required creator types."""

    type: str
    pattern: str | None = None
    description: str | None = None


class CreatorValidationRule(BaseModel):
    """Configuration for creator field validation."""

    required: bool = True
    min_count: int = 1
    required_creator_types: list[CreatorTypeRule] = Field(default_factory=list)
    error_message: str | None = None


class DocumentRequirementsConfig(BaseModel):
    """Configuration for document-level requirements."""

    required_fields: list[str] = Field(default_factory=list)
    field_validation: dict[str, FieldValidationRule | CreatorValidationRule] = Field(
        default_factory=dict
    )


class BuildToolsConfig(BaseModel):
    """Configuration for build tools requirements."""

    require_build_tools: bool = False
    description: str | None = None
    examples: list[str] = Field(default_factory=list)


class ExternalRefTypeRule(BaseModel):
    """Configuration for external reference type requirements."""

    reference_type: str
    reference_category: str
    description: str | None = None
    required_when: str | None = None
    validation: dict[str, Any] = Field(default_factory=dict)


class ExternalRefsConfig(BaseModel):
    """Configuration for external references requirements."""

    required_types: list[ExternalRefTypeRule] = Field(default_factory=list)
    conditional_types: list[ExternalRefTypeRule] = Field(default_factory=list)


class FilesAnalyzedRule(BaseModel):
    """Configuration for filesAnalyzed field validation."""

    when_true_requires: list[str] = Field(default_factory=list)
    when_false_prohibits: list[str] = Field(default_factory=list)
    when_true_description: str | None = None
    when_false_description: str | None = None


class PackageRequirementsConfig(BaseModel):
    """Configuration for package-level requirements."""

    required_fields: list[str] = Field(default_factory=list)
    field_validation: dict[str, FieldValidationRule] = Field(default_factory=dict)
    build_tools: BuildToolsConfig = Field(default_factory=BuildToolsConfig)
    external_refs: ExternalRefsConfig = Field(default_factory=ExternalRefsConfig)
    files_analyzed_rules: FilesAnalyzedRule = Field(default_factory=FilesAnalyzedRule)
    validate_license_expressions: bool = False


class FileRequirementsConfig(BaseModel):
    """Configuration for file-level requirements."""

    required_when: str | None = None
    prohibited_when: str | None = None
    required_fields: list[str] = Field(default_factory=list)
    field_validation: dict[str, FieldValidationRule] = Field(default_factory=dict)


class RelationshipPattern(BaseModel):
    """Configuration for required relationship patterns."""

    pattern: str
    description: str
    source_type: str
    relationship_type: str
    target_type: str
    required_when: str | None = None


class RelationshipRequirementsConfig(BaseModel):
    """Configuration for relationship requirements."""

    no_isolated_elements: bool = True
    error_message: str | None = None
    required_relationships: list[RelationshipPattern] = Field(default_factory=list)


class CustomRule(BaseModel):
    """Configuration for custom validation rules."""

    rule_id: str
    description: str
    severity: str = "error"
    field: str | None = None
    validation_function: str | None = None
    pattern: str | None = None
    max_age_days: int | None = None


class ComplianceRequirementsConfig(BaseModel):
    """Configuration for compliance and quality requirements."""

    spdx_validation: SpdxValidationConfig = Field(default_factory=SpdxValidationConfig)
    completeness_checks: dict[str, bool] = Field(default_factory=dict)
    quality_assurance: dict[str, bool] = Field(default_factory=dict)


class ReportingConfig(BaseModel):
    """Configuration for reporting and output."""

    include_section_references: bool = True
    group_by_severity: bool = True
    include_remediation_suggestions: bool = True
    output_formats: list[str] = Field(default_factory=lambda: ["text", "json", "html"])


class SbomCheckConfig(BaseModel):
    """Complete configuration for SBOM-Check validation."""

    metadata: ConfigMetadata
    spdx_validation: SpdxValidationConfig = Field(default_factory=SpdxValidationConfig)
    format_requirements: FormatRequirementsConfig = Field(
        default_factory=FormatRequirementsConfig
    )
    document_requirements: DocumentRequirementsConfig = Field(
        default_factory=DocumentRequirementsConfig
    )
    package_requirements: PackageRequirementsConfig = Field(
        default_factory=PackageRequirementsConfig
    )
    file_requirements: FileRequirementsConfig = Field(
        default_factory=FileRequirementsConfig
    )
    relationship_requirements: RelationshipRequirementsConfig = Field(
        default_factory=RelationshipRequirementsConfig
    )
    compliance_requirements: ComplianceRequirementsConfig = Field(
        default_factory=ComplianceRequirementsConfig
    )
    custom_rules: list[CustomRule] = Field(default_factory=list)
    error_messages: dict[str, str] = Field(default_factory=dict)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    @classmethod
    def create_basic_spdx(cls) -> SbomCheckConfig:
        """Create a basic SPDX 2.3 compliance configuration."""
        return cls(
            metadata=ConfigMetadata(
                name="Basic SPDX 2.3 Compliance",
                version="1.0",
                description="Minimal SPDX 2.3 compliance validation only",
                reference_url="https://spdx.github.io/spdx-spec/v2.3/",
            )
        )

    @classmethod
    def create_default(cls) -> SbomCheckConfig:
        """Create the default comprehensive configuration."""
        return cls(
            metadata=ConfigMetadata(
                name="Default SBOM Requirements",
                version="1.0",
                description="Comprehensive SBOM validation with enterprise requirements",
                reference_url="https://spdx.github.io/spdx-spec/v2.3/",
            ),
            spdx_validation=SpdxValidationConfig(
                enable_schema_validation=True,
                enable_semantic_validation=True,
                require_zero_validation_errors=True,
                require_zero_validation_warnings=True,
            ),
            document_requirements=DocumentRequirementsConfig(
                required_fields=[
                    "spdxVersion",
                    "dataLicense",
                    "SPDXID",
                    "name",
                    "documentNamespace",
                    "creationInfo.creators",
                    "creationInfo.created",
                    "creationInfo.licenseListVersion",
                ],
                field_validation={
                    "spdxVersion": FieldValidationRule(
                        exact_value="SPDX-2.3",
                        error_message="SPDX version SHALL be exactly 'SPDX-2.3'",
                    ),
                    "dataLicense": FieldValidationRule(
                        exact_value="CC0-1.0",
                        error_message="Data license SHALL be exactly 'CC0-1.0'",
                    ),
                    "SPDXID": FieldValidationRule(
                        exact_value="SPDXRef-DOCUMENT",
                        error_message="Document SPDX ID SHALL be 'SPDXRef-DOCUMENT'",
                    ),
                    "documentNamespace": FieldValidationRule(
                        required=True,
                        must_be_uri=True,
                        require_https_scheme=False,
                        prohibit_fragment=True,
                        pattern=r"^https?://[^/#]+/.*",
                        error_message="Document namespace SHALL be unique URI without '#' delimiter",
                    ),
                    "creationInfo.created": FieldValidationRule(
                        required=True,
                        format="iso8601_utc",
                        pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                        error_message="Creation timestamp SHALL be in ISO 8601 UTC format",
                    ),
                },
            ),
            package_requirements=PackageRequirementsConfig(
                required_fields=[
                    "name",
                    "SPDXID",
                    "downloadLocation",
                    "versionInfo",
                    "supplier",
                    "homepage",
                    "filesAnalyzed",
                    "licenseConcluded",
                    "licenseDeclared",
                    "copyrightText",
                    "externalRefs",
                ],
                validate_license_expressions=True,
                build_tools=BuildToolsConfig(
                    require_build_tools=True,
                    description="All build tools, compilers, interpreters must be included",
                    examples=["GCC", "Clang", "Maven", "CMake"],
                ),
                external_refs=ExternalRefsConfig(
                    required_types=[
                        ExternalRefTypeRule(
                            reference_type="purl",
                            reference_category="PACKAGE-MANAGER",
                            description="Required for ALL packages",
                            validation={"must_be_valid_purl": True},
                        )
                    ],
                    conditional_types=[
                        ExternalRefTypeRule(
                            reference_type="cpe23Type",
                            reference_category="SECURITY",
                            required_when="official_cpe_exists",
                            description="Required when official CPE identifier exists",
                            validation={"must_be_valid_cpe": True, "cpe_format": "2.3"},
                        )
                    ],
                ),
            ),
        )

    def merge_with(self, other: SbomCheckConfig) -> SbomCheckConfig:
        """Merge this configuration with another, with other taking precedence."""
        # This is a simplified merge - in practice, you'd want more sophisticated merging
        merged_dict = self.model_dump()
        other_dict = other.model_dump()

        # Simple recursive merge
        def merge_dicts(
            base: dict[str, Any], override: dict[str, Any]
        ) -> dict[str, Any]:
            result = base.copy()
            for key, value in override.items():
                if (
                    key in result
                    and isinstance(result[key], dict)
                    and isinstance(value, dict)
                ):
                    result[key] = merge_dicts(result[key], value)
                else:
                    result[key] = value
            return result

        merged = merge_dicts(merged_dict, other_dict)
        return SbomCheckConfig.model_validate(merged)
