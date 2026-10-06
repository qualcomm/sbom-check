# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Pydantic models for SPDX 2.3 document structure."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator


class ValidationSeverity(str, Enum):
    """Validation message severity levels."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class ValidationMessage(BaseModel):
    """A single validation message."""

    severity: ValidationSeverity
    message: str
    path: str | None = None
    element_id: str | None = None
    rule_id: str | None = None


class ValidationResult(BaseModel):
    """Result of SPDX document validation."""

    is_valid: bool
    messages: list[ValidationMessage] = Field(default_factory=list)
    schema_valid: bool = True
    semantic_valid: bool = True

    @property
    def has_errors(self) -> bool:
        """Check if validation result contains any errors."""
        return any(msg.severity == ValidationSeverity.ERROR for msg in self.messages)

    @property
    def has_warnings(self) -> bool:
        """Check if validation result contains any warnings."""
        return any(msg.severity == ValidationSeverity.WARNING for msg in self.messages)


class ChecksumAlgorithm(str, Enum):
    """Supported checksum algorithms."""

    SHA1 = "SHA1"
    SHA224 = "SHA224"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    SHA512 = "SHA512"
    SHA3_256 = "SHA3-256"
    SHA3_384 = "SHA3-384"
    SHA3_512 = "SHA3-512"
    MD2 = "MD2"
    MD4 = "MD4"
    MD5 = "MD5"
    MD6 = "MD6"
    BLAKE2B_256 = "BLAKE2b-256"
    BLAKE2B_384 = "BLAKE2b-384"
    BLAKE2B_512 = "BLAKE2b-512"
    BLAKE3 = "BLAKE3"
    ADLER32 = "ADLER32"


class Checksum(BaseModel):
    """Checksum information."""

    algorithm: ChecksumAlgorithm
    checksumValue: str = Field(alias="checksumValue")


class AnnotationType(str, Enum):
    """Annotation types."""

    REVIEW = "REVIEW"
    OTHER = "OTHER"


class Annotation(BaseModel):
    """Annotation on an SPDX element."""

    annotationType: AnnotationType
    annotator: str
    annotationDate: str
    comment: str


class CreationInfo(BaseModel):
    """SPDX document creation information."""

    created: str
    creators: list[str] = Field(min_length=1)
    licenseListVersion: str | None = None
    comment: str | None = None


class RelationshipType(str, Enum):
    """SPDX relationship types."""

    DESCRIBES = "DESCRIBES"
    DESCRIBED_BY = "DESCRIBED_BY"
    CONTAINS = "CONTAINS"
    CONTAINED_BY = "CONTAINED_BY"
    DEPENDS_ON = "DEPENDS_ON"
    DEPENDENCY_OF = "DEPENDENCY_OF"
    DEPENDENCY_MANIFEST_OF = "DEPENDENCY_MANIFEST_OF"
    BUILD_DEPENDENCY_OF = "BUILD_DEPENDENCY_OF"
    DEV_DEPENDENCY_OF = "DEV_DEPENDENCY_OF"
    OPTIONAL_DEPENDENCY_OF = "OPTIONAL_DEPENDENCY_OF"
    PROVIDED_DEPENDENCY_OF = "PROVIDED_DEPENDENCY_OF"
    TEST_DEPENDENCY_OF = "TEST_DEPENDENCY_OF"
    RUNTIME_DEPENDENCY_OF = "RUNTIME_DEPENDENCY_OF"
    EXAMPLE_OF = "EXAMPLE_OF"
    GENERATES = "GENERATES"
    GENERATED_FROM = "GENERATED_FROM"
    ANCESTOR_OF = "ANCESTOR_OF"
    DESCENDANT_OF = "DESCENDANT_OF"
    VARIANT_OF = "VARIANT_OF"
    DISTRIBUTION_ARTIFACT = "DISTRIBUTION_ARTIFACT"
    PATCH_FOR = "PATCH_FOR"
    PATCH_APPLIED = "PATCH_APPLIED"
    COPY_OF = "COPY_OF"
    FILE_ADDED = "FILE_ADDED"
    FILE_DELETED = "FILE_DELETED"
    FILE_MODIFIED = "FILE_MODIFIED"
    EXPANDED_FROM_ARCHIVE = "EXPANDED_FROM_ARCHIVE"
    DYNAMIC_LINK = "DYNAMIC_LINK"
    STATIC_LINK = "STATIC_LINK"
    DATA_FILE_OF = "DATA_FILE_OF"
    TEST_CASE_OF = "TEST_CASE_OF"
    BUILD_TOOL_OF = "BUILD_TOOL_OF"
    DEV_TOOL_OF = "DEV_TOOL_OF"
    TEST_OF = "TEST_OF"
    TEST_TOOL_OF = "TEST_TOOL_OF"
    DOCUMENTATION_OF = "DOCUMENTATION_OF"
    OPTIONAL_COMPONENT_OF = "OPTIONAL_COMPONENT_OF"
    METAFILE_OF = "METAFILE_OF"
    PACKAGE_OF = "PACKAGE_OF"
    AMENDS = "AMENDS"
    PREREQUISITE_FOR = "PREREQUISITE_FOR"
    HAS_PREREQUISITE = "HAS_PREREQUISITE"
    REQUIREMENT_DESCRIPTION_FOR = "REQUIREMENT_DESCRIPTION_FOR"
    SPECIFICATION_FOR = "SPECIFICATION_FOR"
    OTHER = "OTHER"


class Relationship(BaseModel):
    """SPDX relationship between elements."""

    spdxElementId: str
    relationshipType: RelationshipType
    relatedSpdxElement: str
    comment: str | None = None


class ExternalDocumentRef(BaseModel):
    """Reference to external SPDX document."""

    externalDocumentId: str
    spdxDocument: str
    checksum: Checksum


class ExtractedLicensingInfo(BaseModel):
    """Extracted licensing information."""

    licenseId: str
    extractedText: str
    name: str | None = None
    seeAlsos: list[str] | None = None
    comment: str | None = None


class FileType(str, Enum):
    """File types."""

    SOURCE = "SOURCE"
    BINARY = "BINARY"
    ARCHIVE = "ARCHIVE"
    APPLICATION = "APPLICATION"
    AUDIO = "AUDIO"
    IMAGE = "IMAGE"
    TEXT = "TEXT"
    VIDEO = "VIDEO"
    DOCUMENTATION = "DOCUMENTATION"
    SPDX = "SPDX"
    OTHER = "OTHER"


class File(BaseModel):
    """SPDX file information."""

    SPDXID: str
    fileName: str
    checksums: list[Checksum] = Field(min_length=1)
    licenseConcluded: str | None = None
    licenseInfoInFiles: list[str] | None = None
    licenseComments: str | None = None
    copyrightText: str | None = None
    comment: str | None = None
    noticeText: str | None = None
    fileContributors: list[str] | None = None
    fileTypes: list[FileType] | None = None
    annotations: list[Annotation] | None = None


class PackagePurpose(str, Enum):
    """Package purpose types."""

    APPLICATION = "APPLICATION"
    FRAMEWORK = "FRAMEWORK"
    LIBRARY = "LIBRARY"
    CONTAINER = "CONTAINER"
    OPERATING_SYSTEM = "OPERATING_SYSTEM"
    DEVICE = "DEVICE"
    FIRMWARE = "FIRMWARE"
    SOURCE = "SOURCE"
    ARCHIVE = "ARCHIVE"
    FILE = "FILE"
    INSTALL = "INSTALL"
    OTHER = "OTHER"


class ExternalRefCategory(str, Enum):
    """External reference categories."""

    SECURITY = "SECURITY"
    PACKAGE_MANAGER = "PACKAGE-MANAGER"
    PACKAGE_MANAGER_UNDERSCORE = "PACKAGE_MANAGER"
    PERSISTENT_ID = "PERSISTENT-ID"
    PERSISTENT_ID_UNDERSCORE = "PERSISTENT_ID"
    OTHER = "OTHER"


class ExternalRef(BaseModel):
    """External reference for a package."""

    referenceCategory: ExternalRefCategory
    referenceType: str
    referenceLocator: str
    comment: str | None = None


class PackageVerificationCode(BaseModel):
    """Package verification code."""

    packageVerificationCodeValue: str = Field(min_length=40, max_length=40)
    packageVerificationCodeExcludedFiles: list[str] | None = None


class Package(BaseModel):
    """SPDX package information."""

    SPDXID: str
    name: str
    downloadLocation: str
    filesAnalyzed: bool = True
    packageVerificationCode: PackageVerificationCode | None = None
    checksums: list[Checksum] | None = None
    homepage: str | None = None
    sourceInfo: str | None = None
    licenseConcluded: str | None = None
    licenseDeclared: str | None = None
    licenseComments: str | None = None
    licenseInfoFromFiles: list[str] | None = None
    copyrightText: str | None = None
    summary: str | None = None
    description: str | None = None
    comment: str | None = None
    externalRefs: list[ExternalRef] | None = None
    attributionTexts: list[str] | None = None
    primaryPackagePurpose: PackagePurpose | None = None
    releaseDate: str | None = None
    builtDate: str | None = None
    validUntilDate: str | None = None
    annotations: list[Annotation] | None = None
    supplier: str | None = None
    originator: str | None = None
    versionInfo: str | None = None
    packageFileName: str | None = None
    hasFiles: list[str] | None = None


class SpdxDocument(BaseModel):
    """Complete SPDX document model."""

    SPDXID: str
    spdxVersion: str
    creationInfo: CreationInfo
    name: str
    dataLicense: str
    documentNamespace: str
    documentDescribes: list[str] | None = None
    packages: list[Package] | None = None
    files: list[File] | None = None
    snippets: list[dict[str, object]] | None = None  # Simplified for now
    relationships: list[Relationship] | None = None
    annotations: list[Annotation] | None = None
    revieweds: list[dict[str, object]] | None = None  # Deprecated field
    hasExtractedLicensingInfos: list[ExtractedLicensingInfo] | None = None
    externalDocumentRefs: list[ExternalDocumentRef] | None = None
    comment: str | None = None

    @field_validator("spdxVersion")
    @classmethod
    def validate_spdx_version(cls, v: str) -> str:
        """Validate SPDX version is 2.3."""
        if v != "SPDX-2.3":
            raise ValueError(f"Only SPDX-2.3 is supported, got: {v}")
        return v

    @field_validator("dataLicense")
    @classmethod
    def validate_data_license(cls, v: str) -> str:
        """Validate data license is CC0-1.0."""
        if v != "CC0-1.0":
            raise ValueError(f"Data license must be CC0-1.0, got: {v}")
        return v
