# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Main SBOM-Check validation engine."""

from __future__ import annotations

import json
import re
from functools import cache
from pathlib import Path
from typing import TYPE_CHECKING, Any
from warnings import warn

from license_expression import ExpressionError, get_spdx_licensing

from sbom_check.config.loader import ConfigLoader
from sbom_check.detection import UnsupportedDocumentError, detect_document
from sbom_check.models import (
    DocumentFormat,
    ProfileStatus,
    SbomCheckResult,
    ValidationMessage,
    ValidationSeverity,
    ValidationSummary,
)
from spdx_validator.engine import ValidationEngine
from spdx_validator.models import DEFAULT_FILES_ANALYZED

if TYPE_CHECKING:
    from license_expression import Licensing

    from sbom_check.config.models import SbomCheckConfig
    from sbom_validator.engine import ValidatorEngine

# SPDX sentinel values that are legal in license fields but are not license keys.
_LICENSE_SENTINELS = {"NOASSERTION", "NONE"}

# SPDX license-expression operators (AND/OR/WITH), matched case-insensitively so
# lowercase use can be warned about; Annex D.2 says they should be uppercase.
_OPERATOR_WORD = re.compile(r"\b(?:and|or|with)\b", re.IGNORECASE)

# A cross-document license reference: DocumentRef-<id>:LicenseRef-<id> (Annex D).
_DOCUMENT_REF = re.compile(r"(DocumentRef-[A-Za-z0-9.\-]+):LicenseRef-[A-Za-z0-9.\-]+")

# Fixed prefixes the parser uses for WITH-operator misuse (as opposed to an
# "Unknown license key(s): ..." error, which is a plain unknown symbol).
_MISUSE_PREFIXES = (
    "A plain license symbol cannot be used as an exception",
    "A license exception symbol can only be used as an exception",
)


@cache
def _licensing() -> Licensing:
    """Return a cached SPDX licensing parser (building one is expensive)."""
    return get_spdx_licensing()


def _strip_or_later(key: str) -> str:
    """Remove a single trailing ``+`` ("or later") suffix from a license key.

    SPDX Annex D allows ``license-id "+"``; the parser does not split the ``+``
    off, so ``<id>+`` must be reduced to ``<id>`` before looking the id up.
    """
    return key[:-1] if key.endswith("+") else key


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
        self._validator_class = validator_class

        # Engines are instantiated only when their document format is used and
        # then retained for subsequent documents of that format.
        self._engines: dict[type[ValidatorEngine], ValidatorEngine] = {}
        self._engine_override: ValidatorEngine | None = None

    def _get_engine(self, validator_class: type[ValidatorEngine]) -> ValidatorEngine:
        """Return the cached instance for a validator class."""
        if validator_class not in self._engines:
            self._engines[validator_class] = validator_class()
        return self._engines[validator_class]

    @property
    def engine(self) -> ValidatorEngine:
        """Configured core validator, instantiated lazily."""
        if self._engine_override is not None:
            return self._engine_override
        return self._get_engine(self._validator_class or ValidationEngine)

    @engine.setter
    def engine(self, value: ValidatorEngine) -> None:
        """Override the core validator instance used for every document format."""
        self._engine_override = value

    @property
    def spdx_engine(self) -> Any:
        """Deprecated alias for the configured SPDX validator engine."""
        warn(
            "spdx_engine is deprecated; use engine instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._engine_override or self._get_engine(ValidationEngine)

    @spdx_engine.setter
    def spdx_engine(self, value: Any) -> None:
        """Set the SPDX validator through this deprecated alias."""
        warn(
            "spdx_engine is deprecated; use engine instead",
            DeprecationWarning,
            stacklevel=2,
        )
        self._engines[ValidationEngine] = value

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
                sbom_json = f.read()
            return self.validate_json_string(sbom_json, str(file_path))
        except FileNotFoundError:
            return self._early_failure_result(
                f"File not found: {file_path}",
                rule_id="file_not_found",
                file_path=str(file_path),
            )
        except (OSError, UnicodeDecodeError) as e:
            return self._early_failure_result(
                f"Error reading file {file_path}: {e!s}",
                rule_id="file_read_error",
                file_path=str(file_path),
            )

    def validate_json_string(
        self, sbom_json: str, file_path: str | None = None
    ) -> SbomCheckResult:
        """Validate an SBOM document from JSON string.

        Args:
            sbom_json: SBOM document as JSON string
            file_path: Optional file path for context

        Returns:
            Complete validation result
        """
        try:
            sbom_data = json.loads(sbom_json)
        except json.JSONDecodeError as e:
            return self._early_failure_result(
                f"Invalid JSON: {e!s}",
                rule_id="json_parse_error",
                file_path=file_path,
            )

        return self.validate_dict(sbom_data, file_path)

    def validate_dict(
        self, sbom_data: object, file_path: str | None = None
    ) -> SbomCheckResult:
        """Validate an SBOM document from dictionary.

        Args:
            sbom_data: SBOM document as dictionary
            file_path: Optional file path for context

        Returns:
            Complete validation result
        """
        if not isinstance(sbom_data, dict):
            return self._unsupported_result(
                UnsupportedDocumentError(
                    "Unsupported input: the JSON document must be a top-level object"
                ),
                file_path=file_path,
            )

        # Detection owns document metadata and profile applicability, even when
        # a caller overrides the validator. The override changes only which
        # core validator executes; it must not relabel the input document.
        try:
            detected = detect_document(sbom_data)
        except UnsupportedDocumentError as error:
            return self._unsupported_result(error, file_path=file_path)

        selected_engine = (
            self.engine
            if self._engine_override is not None or self._validator_class is not None
            else self._get_engine(detected.validator_class)
        )
        profile_applicable = detected.format is DocumentFormat.SPDX

        # Run the selected format engine.
        core_result = selected_engine.validate_dict(sbom_data)

        # The completeness profile is SPDX-specific.
        profile_result = (
            self._validate_profile_requirements(sbom_data)
            if profile_applicable
            else None
        )

        # Combine results
        combined_result = SbomCheckResult.combine(
            core_result=core_result,
            profile_result=profile_result,
            profile_name=self.config.metadata.name,
            file_path=file_path,
            document_format=detected.format,
            spec_version=detected.spec_version,
        )

        return combined_result

    def _unsupported_result(
        self, error: UnsupportedDocumentError, file_path: str | None = None
    ) -> SbomCheckResult:
        """Create a structured result for unsupported input."""
        return self._early_failure_result(
            str(error), rule_id=error.rule_id, file_path=file_path
        )

    @staticmethod
    def _early_failure_result(
        message: str, *, rule_id: str, file_path: str | None = None
    ) -> SbomCheckResult:
        """Create a format-neutral result for failures before validation."""
        return SbomCheckResult(
            overall_valid=False,
            spdx_valid=None,
            profile_valid=None,
            core_valid=False,
            profile_status=ProfileStatus.NOT_APPLICABLE,
            messages=[
                ValidationMessage(
                    severity=ValidationSeverity.ERROR,
                    message=message,
                    rule_id=rule_id,
                )
            ],
            summary=ValidationSummary(errors=1, failed_rules=1),
            profile_name=None,
            file_path=file_path,
            document_format=DocumentFormat.UNKNOWN,
            spec_version=None,
        )

    def _validate_profile_requirements(
        self, sbom_data: dict[str, Any]
    ) -> SbomCheckResult:
        """Validate document against profile-specific requirements.

        Args:
            sbom_data: SPDX document as dictionary

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
        self._validate_document_requirements(sbom_data, result)

        # Validate package requirements
        self._validate_package_requirements(sbom_data, result)

        # Validate file requirements
        self._validate_file_requirements(sbom_data, result)

        # Validate relationship requirements
        self._validate_relationship_requirements(sbom_data, result)

        # Run custom rules
        self._validate_custom_rules(sbom_data, result)

        return result

    def _validate_document_requirements(
        self, sbom_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate document-level requirements."""
        doc_config = self.config.document_requirements

        # Check required fields
        for field in doc_config.required_fields:
            if not self._get_nested_field(sbom_data, field):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"Required field '{field}' is missing",
                    rule_id="missing_required_field",
                    field_path=field,
                    section_reference="Document Requirements",
                )

        # Validate field-specific rules
        for field_name, rule in doc_config.field_validation.items():
            field_value = self._get_nested_field(sbom_data, field_name)

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
        self, sbom_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate package-level requirements."""
        if not (packages := sbom_data.get("packages", [])):
            return

        pkg_config = self.config.package_requirements

        # Check build tools requirement
        if pkg_config.build_tools.require_build_tools:
            self._validate_build_tools_coverage(packages, result)

        # License-expression validation is opt-in. Only compute the document-level
        # context it needs (declared LicenseRef- ids, external document ids) when
        # the flag is on, so a malformed hasExtractedLicensingInfos/externalDocumentRefs
        # cannot crash profiles that don't use the feature.
        if pkg_config.validate_license_expressions:
            declared_license_refs = self._collect_declared_license_refs(sbom_data)
            external_document_ids = self._collect_external_document_ids(sbom_data)

        # Validate each package
        for i, package in enumerate(packages):
            self._validate_single_package(package, i, result)
            if pkg_config.validate_license_expressions:
                self._validate_package_licenses(
                    package, i, declared_license_refs, external_document_ids, result
                )

    @staticmethod
    def _collect_declared_license_refs(spdx_data: dict[str, Any]) -> set[str]:
        """Return the ``LicenseRef-`` ids declared in ``hasExtractedLicensingInfos``.

        Tolerates malformed input: a missing/``null`` value, a non-list value, or
        entries whose ``licenseId`` is absent or not a string are simply skipped
        (the SPDX schema validator reports those separately).
        """
        infos = spdx_data.get("hasExtractedLicensingInfos")
        if not isinstance(infos, list):
            return set()
        return {
            info["licenseId"]
            for info in infos
            if isinstance(info, dict) and isinstance(info.get("licenseId"), str)
        }

    @staticmethod
    def _collect_external_document_ids(spdx_data: dict[str, Any]) -> set[str]:
        """Return the ``externalDocumentId`` values from ``externalDocumentRefs``.

        These are the ``DocumentRef-`` ids a license expression may legally
        reference. Malformed input is tolerated the same way as above.
        """
        refs = spdx_data.get("externalDocumentRefs")
        if not isinstance(refs, list):
            return set()
        return {
            ref["externalDocumentId"]
            for ref in refs
            if isinstance(ref, dict) and isinstance(ref.get("externalDocumentId"), str)
        }

    def _validate_package_licenses(
        self,
        package: dict[str, Any],
        index: int,
        declared_license_refs: set[str],
        external_document_ids: set[str],
        result: SbomCheckResult,
    ) -> None:
        """Validate that package license fields are valid SPDX expressions.

        Each of ``licenseConcluded`` and ``licenseDeclared`` must be a valid SPDX
        license expression, the sentinels ``NOASSERTION``/``NONE``, or reference a
        ``LicenseRef-`` id declared in ``hasExtractedLicensingInfos`` (or a
        ``DocumentRef-`` matching an ``externalDocumentRefs`` entry).
        """
        package_id = self._get_package_identifier(package, index)

        for field in ("licenseConcluded", "licenseDeclared"):
            if (value := package.get(field)) is None:
                continue

            field_path = f"packages[{index}].{field}"

            # A non-string value gets a clear type error here rather than being
            # stringified and reported as a bogus license symbol.
            if not isinstance(value, str):
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"{package_id}: Field '{field}' must be a string license "
                    f"expression, got {type(value).__name__}",
                    rule_id="invalid_license_expression",
                    field_path=field_path,
                    found_value=value,
                    remediation="Provide the license as a string SPDX expression",
                )
                continue

            detail = self._license_expression_error(
                value, declared_license_refs, external_document_ids
            )
            if detail is not None:
                result.add_message(
                    ValidationSeverity.ERROR,
                    f"{package_id}: Field '{field}' is not a valid SPDX license "
                    f"expression ({detail})",
                    rule_id="invalid_license_expression",
                    field_path=field_path,
                    found_value=value,
                    remediation=(
                        "Use a valid SPDX license expression, 'NOASSERTION'/'NONE', "
                        "or a 'LicenseRef-' declared in hasExtractedLicensingInfos"
                    ),
                )
            elif lowercase := self._lowercase_operators(value):
                result.add_message(
                    ValidationSeverity.WARNING,
                    f"{package_id}: Field '{field}' uses lowercase operator(s) "
                    f"({', '.join(lowercase)}); SPDX operators should be uppercase",
                    rule_id="lowercase_license_operator",
                    field_path=field_path,
                    found_value=value,
                    remediation="Write AND/OR/WITH in uppercase",
                )

    def _license_expression_error(
        self,
        value: str,
        declared_license_refs: set[str],
        external_document_ids: set[str],
    ) -> str | None:
        """Classify why ``value`` is not an acceptable SPDX license expression.

        Returns ``None`` when the expression is acceptable, otherwise a short
        human-readable detail describing the failure kind (syntax error, unknown
        license id, misused exception, or undeclared license reference).
        """
        # An empty value is not a license expression; SPDX uses NONE/NOASSERTION
        # to say "no license" or "not known".
        if not (text := value.strip()):
            return "syntax error: empty expression"
        if text in _LICENSE_SENTINELS:
            return None

        licensing = _licensing()

        # Parse first to catch syntax errors; validate() cannot report unknown-key
        # symbols for a syntactically invalid expression (and raises on some).
        try:
            parsed = licensing.parse(text, validate=False, strict=False)
            # strict=True additionally flags misuse such as a plain license used
            # as a "WITH" exception, which a non-strict validate() silently accepts.
            info = licensing.validate(text, strict=True)
        except ExpressionError as exc:
            return f"syntax error: {exc}"
        except (IndexError, ValueError, AttributeError):
            # The library has internal crash paths on some malformed inputs, e.g.
            # validate("()") raises IndexError and a "/"-separated pair of ids
            # raises AttributeError; treat them as syntax errors. Recheck these
            # when upgrading license-expression.
            return "syntax error: invalid expression"

        # Symbols the parser flagged as misused: a plain license on the right of
        # WITH, or an exception used without WITH. These are keyed off the parser's
        # fixed message prefixes, not a substring of the symbol name (a declared
        # LicenseRef- whose id contains "exception" must not be mistaken for one).
        if misuse := [err for err in info.errors if err.startswith(_MISUSE_PREFIXES)]:
            return f"misused license/exception: {misuse[0]}"

        invalid = [
            symbol
            for symbol in info.invalid_symbols
            if not self._symbol_is_known(
                symbol, declared_license_refs, external_document_ids
            )
        ]
        # Every LicenseRef- must be declared in hasExtractedLicensingInfos, even
        # ids the parser recognises natively (its built-in ScanCode refs). A
        # trailing "+" ("or later") is part of the operator, not the id.
        undeclared = [
            key
            for key in licensing.license_keys(parsed)
            if _strip_or_later(key).startswith("LicenseRef-")
            and _strip_or_later(key) not in declared_license_refs
        ]
        unknown = list(dict.fromkeys([*invalid, *undeclared]))
        return (
            f"unknown or undeclared license id(s): {', '.join(unknown)}"
            if unknown
            else None
        )

    @staticmethod
    def _symbol_is_known(
        symbol: str,
        declared_license_refs: set[str],
        external_document_ids: set[str],
    ) -> bool:
        """Return whether an ``invalid_symbols`` entry should be excused.

        Only called when the parser reported no misuse, so a declared
        ``LicenseRef-`` here is genuinely an ordinary license symbol.
        """
        # A cross-document DocumentRef-<id>:LicenseRef-<id> is accepted when its
        # DocumentRef- part matches a declared externalDocumentRefs entry; we
        # can't resolve the referenced document, so we don't ERROR on it. The
        # full form is required (a bare DocumentRef-<id>, or one followed by
        # anything but a LicenseRef-, is not).
        if ref := _DOCUMENT_REF.fullmatch(symbol):
            return ref.group(1) in external_document_ids
        # Strip a trailing "+" ("or later") before looking the base id up.
        base = _strip_or_later(symbol)
        if base.startswith("LicenseRef-"):
            return base in declared_license_refs
        return base in _licensing().known_symbols

    @staticmethod
    def _lowercase_operators(value: str) -> list[str]:
        """Return distinct lowercase SPDX operators used in ``value``.

        SPDX Annex D.2 says operators should be matched case-sensitively; the
        parser accepts lowercase, so we surface it as a WARNING rather than fail.
        """
        # Word-boundary match so operators adjacent to parentheses are found too,
        # e.g. "<id> and(<id>)".
        found = [
            token for token in _OPERATOR_WORD.findall(value) if token != token.upper()
        ]
        return list(dict.fromkeys(found))

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
        # SPDX 2.3 specifies that filesAnalyzed defaults to true when omitted.
        files_analyzed = package.get("filesAnalyzed", DEFAULT_FILES_ANALYZED)
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
        self, sbom_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate file-level requirements."""
        # This is a placeholder for file validation logic
        # Implementation would depend on the specific file requirements
        # Currently no file-level validation rules are implemented
        _ = sbom_data, result  # Acknowledge unused parameters

    def _validate_relationship_requirements(
        self, sbom_data: dict[str, Any], result: SbomCheckResult
    ) -> None:
        """Validate relationship requirements."""
        relationships = sbom_data.get("relationships", [])
        rel_config = self.config.relationship_requirements

        if rel_config.no_isolated_elements:
            # Check that all elements are properly related
            # This is a simplified check - full implementation would be more complex
            document_id = sbom_data.get("SPDXID", "SPDXRef-DOCUMENT")

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
        self, _sbom_data: dict[str, Any], _result: SbomCheckResult
    ) -> None:
        """Validate custom rules."""
        for _rule in self.config.custom_rules:
            # This is a placeholder for custom rule validation
            # In practice, you'd implement specific validation functions
            # The _sbom_data and _result parameters would be used here
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
