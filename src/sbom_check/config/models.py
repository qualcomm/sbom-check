# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration data models for SBOM-Check."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from sbom_check.models import ValidationSeverity


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


class CompletenessCheckRule(BaseModel):
    """Per-rule configuration for a Qualcomm completeness check.

    Controls whether a given completeness rule (identified elsewhere by
    ``rule_id``) is enabled, how loud its findings are reported, which
    SPDX document versions it applies to, and whether it has an
    approved implementation/mapping at all.
    """

    enabled: bool = True
    severity: ValidationSeverity = ValidationSeverity.ERROR
    spdx_versions: list[str] = Field(default_factory=lambda: ["2.3", "3.0.1"])
    description: str | None = None
    remediation: str | None = None
    # Set False for a rule that is defined (has a rule_id and config entry)
    # but has no implementation/approved mapping for the applicable
    # document version. A rule with supported=False that is otherwise
    # enabled and applicable to the document's spec version must produce
    # RuleOutcome.UNSUPPORTED rather than being silently skipped: an
    # unsupported-but-applicable rule fails closed so a document is never
    # reported as complete when a required check never actually ran.
    supported: bool = True

    def applies_to_version(self, spec_version: str | None) -> bool:
        """Check whether this rule applies to a given SPDX document version.

        Args:
            spec_version: The bare SPDX specification version of the
                document being validated (e.g. ``"2.3"`` or ``"3.0.1"``),
                or None if unknown.

        Returns:
            bool: True when ``spec_version`` is not None and is present
            in ``spdx_versions``.
        """
        return spec_version is not None and spec_version in self.spdx_versions


class ComplianceRequirementsConfig(BaseModel):
    """Configuration for compliance and quality requirements."""

    spdx_validation: SpdxValidationConfig = Field(default_factory=SpdxValidationConfig)
    completeness_checks: dict[str, CompletenessCheckRule] = Field(default_factory=dict)
    quality_assurance: dict[str, bool] = Field(default_factory=dict)

    @field_validator("completeness_checks", mode="before")
    @classmethod
    def _coerce_legacy_completeness_checks(cls, value: Any) -> Any:
        """Coerce legacy boolean completeness-check entries to rule objects.

        Existing configuration files in the wild use the legacy shape
        ``{"require_x": true}``, where the value is a plain bool meaning
        "enabled". This normalizes any bool value in the mapping to
        ``CompletenessCheckRule(enabled=<bool>)`` before standard
        validation runs, so legacy config files keep loading unchanged.
        Non-bool values (e.g. already-structured dicts) pass through
        untouched.

        Args:
            value: The raw ``completeness_checks`` mapping as parsed from
                configuration input.

        Returns:
            Any: The mapping with any bool values replaced by
            ``CompletenessCheckRule`` instances; non-dict input is
            returned unchanged.
        """
        if not isinstance(value, dict):
            return value
        coerced: dict[str, Any] = {}
        for key, entry in value.items():
            if isinstance(entry, bool):
                coerced[key] = CompletenessCheckRule(enabled=entry)
            else:
                coerced[key] = entry
        return coerced


def _default_spdx3_completeness_checks() -> dict[str, CompletenessCheckRule]:
    """Build the default Qualcomm SPDX 3.0.1 completeness check entries.

    Each entry enables one SPDX 3.0.1 completeness rule from
    ``docs/spdx3-completeness-matrix.md`` for the ``default`` profile,
    with the severity that matrix's "Severity rationale" section (6)
    proposes. Every entry is scoped to ``spdx_versions=["3.0.1"]`` only,
    so these checks never apply to SPDX 2.3 documents and the existing
    SPDX 2.3 default-profile behavior is unaffected.

    Returns:
        dict[str, CompletenessCheckRule]: Mapping of the 21 approved
        ``spdx3_completeness.*`` rule ids to their enabled, supported
        configuration.
    """

    def _rule(
        *, severity: ValidationSeverity, description: str, remediation: str
    ) -> CompletenessCheckRule:
        return CompletenessCheckRule(
            enabled=True,
            severity=severity,
            spdx_versions=["3.0.1"],
            supported=True,
            description=description,
            remediation=remediation,
        )

    error = ValidationSeverity.ERROR
    warning = ValidationSeverity.WARNING

    return {
        "spdx3_completeness.document_name": _rule(
            severity=error,
            description=(
                "The SBOM document must have a non-empty name identifying it."
            ),
            remediation=(
                "Set a clear, non-empty name on the SPDX document when you "
                "generate the SBOM."
            ),
        ),
        "spdx3_completeness.document_identifier": _rule(
            severity=error,
            description=(
                "The SBOM document must have a globally unique identifier "
                "(spdxId) with no '#' fragment."
            ),
            remediation=(
                "Make sure your SBOM tooling assigns the document a unique, "
                "fragment-free identifier before you deliver it."
            ),
        ),
        "spdx3_completeness.creation_timestamp": _rule(
            severity=error,
            description=(
                "The SBOM document must record when it was created, in "
                "ISO-8601 UTC format."
            ),
            remediation=(
                "Confirm your SBOM tooling stamps a valid creation date/time "
                "(UTC) on every document you deliver."
            ),
        ),
        "spdx3_completeness.creators": _rule(
            severity=error,
            description=(
                "The SBOM document must identify at least one creator "
                "(organization, person, or tool) that produced it."
            ),
            remediation=(
                "Make sure the tool or team that generated the SBOM is "
                "recorded as a creator before you deliver it."
            ),
        ),
        "spdx3_completeness.spec_version": _rule(
            severity=error,
            description=(
                "The SBOM document must declare that it conforms to SPDX "
                "specification version 3.0.1."
            ),
            remediation=(
                "Confirm your SBOM generation tooling is configured to emit "
                "SPDX 3.0.1 and declares that version explicitly."
            ),
        ),
        "spdx3_completeness.data_license": _rule(
            severity=error,
            description=(
                "The SBOM document must declare the license that applies to "
                "the SBOM data itself."
            ),
            remediation=(
                "Make sure your SBOM tooling sets a data license on the "
                "document before delivery."
            ),
        ),
        "spdx3_completeness.package_name": _rule(
            severity=error,
            description="Every package in the SBOM must have a non-empty name.",
            remediation=(
                "Provide a clear name for every package you include in the SBOM."
            ),
        ),
        "spdx3_completeness.package_identifier": _rule(
            severity=error,
            description=(
                "Every package in the SBOM must have a unique identifier (spdxId)."
            ),
            remediation=(
                "Make sure every package you list has a unique identifier "
                "assigned by your SBOM tooling."
            ),
        ),
        "spdx3_completeness.package_version": _rule(
            severity=error,
            description="Every package in the SBOM must state its version.",
            remediation=(
                "Record the exact version of every package you deliver in the SBOM."
            ),
        ),
        "spdx3_completeness.package_download_location": _rule(
            severity=error,
            description=(
                "Every package in the SBOM must state where it can be downloaded from."
            ),
            remediation=(
                "Provide a working download location (or explicitly state "
                "none exists) for every package you deliver."
            ),
        ),
        "spdx3_completeness.package_supplier": _rule(
            severity=error,
            description=(
                "Every package in the SBOM must identify the organization "
                "or person that supplied it."
            ),
            remediation=(
                "Identify your organization (or the upstream supplier) as "
                "the supplier of every package you deliver."
            ),
        ),
        "spdx3_completeness.license_concluded": _rule(
            severity=error,
            description=(
                "Every package in the SBOM must state the license your "
                "organization concluded applies to it."
            ),
            remediation=(
                "Record the license your organization has determined "
                "applies to every package you deliver."
            ),
        ),
        "spdx3_completeness.license_declared": _rule(
            severity=error,
            description=(
                "Every package in the SBOM must state the license declared "
                "by the package's authors or upstream source."
            ),
            remediation=(
                "Record the license declared by the package's own authors "
                "or upstream source for every package you deliver."
            ),
        ),
        "spdx3_completeness.document_describes": _rule(
            severity=error,
            description=(
                "The SBOM document must clearly state which package(s) it describes."
            ),
            remediation=(
                "Make sure the SBOM explicitly links the document to the "
                "package(s) it covers before you deliver it."
            ),
        ),
        "spdx3_completeness.package_homepage": _rule(
            severity=warning,
            description=(
                "Each package in the SBOM should state its homepage, when one exists."
            ),
            remediation=(
                "Where a package has a public homepage, include it in the "
                "SBOM for easier reference."
            ),
        ),
        "spdx3_completeness.copyright_text": _rule(
            severity=warning,
            description=("Each package in the SBOM should state its copyright notice."),
            remediation=(
                "Include the copyright notice for each package you deliver, "
                "where it is known."
            ),
        ),
        "spdx3_completeness.package_cpe": _rule(
            severity=warning,
            description=(
                "Where a package has an official CPE identifier, the SBOM "
                "should include it."
            ),
            remediation=(
                "Include the official CPE identifier for a package whenever "
                "one has been assigned to it."
            ),
        ),
        "spdx3_completeness.no_isolated_elements": _rule(
            severity=warning,
            description=(
                "Every package and file in the SBOM should be linked back "
                "to the document so nothing is orphaned."
            ),
            remediation=(
                "Make sure every package and file you include is connected "
                "to the document, not left disconnected from the rest of the "
                "SBOM."
            ),
        ),
        "spdx3_completeness.dependency_relationships": _rule(
            severity=warning,
            description=(
                "When the SBOM lists more than one package, it should state "
                "how those packages relate (e.g. one contains or depends on "
                "another)."
            ),
            remediation=(
                "Add containment or dependency relationships between the "
                "packages you deliver so readers can see how they relate."
            ),
        ),
        "spdx3_completeness.license_list_version": _rule(
            severity=warning,
            description=(
                "Where a license expression states the SPDX license-list "
                "version it was checked against, that version should be a "
                "non-empty, properly formatted value."
            ),
            remediation=(
                "If you record a license-list version on a license "
                "expression, format it as a semantic version, e.g. '3.25.0'."
            ),
        ),
        "spdx3_completeness.package_verification_code": _rule(
            severity=warning,
            description=(
                "Where a package states a 2.X-style verification code, that "
                "code should carry a non-empty hash value."
            ),
            remediation=(
                "If you include a package verification code, make sure it "
                "carries a non-empty hash value, or remove the malformed entry."
            ),
        ),
    }


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
            compliance_requirements=ComplianceRequirementsConfig(
                completeness_checks=_default_spdx3_completeness_checks()
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
