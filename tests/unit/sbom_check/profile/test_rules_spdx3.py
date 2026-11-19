# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3.0.1 Qualcomm completeness profile rules."""

from __future__ import annotations

import itertools
import json
from pathlib import Path
from typing import Any

import pytest

from sbom_check.config.models import SbomCheckConfig
from sbom_check.models import DocumentFormat, ValidationMessage
from sbom_check.profile.registry import ProfileRuleRegistry, RuleContext
from sbom_check.profile.rules_spdx3 import (
    SPDX3_RULES,
    CreationTimestampRule,
    CreatorsRule,
    DataLicenseRule,
    DependencyRelationshipsRule,
    DocumentDescribesRule,
    DocumentIdentifierRule,
    LicenseConcludedRule,
    LicenseDeclaredRule,
    LicenseListVersionRule,
    NoIsolatedElementsRule,
    PackageCpeRule,
    PackageIdentifierRule,
    PackageNameRule,
    PackageSupplierRule,
    PackageVerificationCodeRule,
    SpecVersionRule,
    register_spdx3_rules,
)
from sbom_check.profile.rules_spdx3._common import (
    _is_absolute_iri,
    _is_valid_timestamp,
)
from sbom_check.profile.spdx3_model import Spdx3Document

FIXTURE_DIR = Path(__file__).resolve().parents[3] / "fixtures" / "spdx3"


def _load_fixture(name: str) -> dict[str, Any]:
    """Load a named fixture document from ``tests/fixtures/spdx3``.

    Args:
        name: The fixture file name, e.g. ``"complete.spdx.json"``.

    Returns:
        dict[str, Any]: The parsed JSON document.
    """
    with (FIXTURE_DIR / name).open(encoding="utf-8") as handle:
        return json.load(handle)


def _context() -> RuleContext:
    """Build a RuleContext for SPDX 3.0.1 evaluation against the default config.

    Returns:
        RuleContext: A context with spec_version "3.0.1", format SPDX3,
        and the default SbomCheckConfig.
    """
    return RuleContext(
        spec_version="3.0.1",
        document_format=DocumentFormat.SPDX3,
        config=SbomCheckConfig.create_default(),
    )


def _rule_ids(messages: list[ValidationMessage]) -> set[str | None]:
    """Extract the set of rule_ids from a list of messages.

    Args:
        messages: The messages to extract rule ids from.

    Returns:
        set[str | None]: The distinct rule_id values present.
    """
    return {message.rule_id for message in messages}


COMPLETE_DOC = _load_fixture("complete.spdx.json")
INCOMPLETE_PACKAGE_DOC = _load_fixture("incomplete-package.spdx.json")
MISSING_SUPPLIER_DOC = _load_fixture("missing-supplier.spdx.json")
DANGLING_SUPPLIER_DOC = _load_fixture("dangling-supplier.spdx.json")
NO_DESCRIBES_DOC = _load_fixture("no-describes.spdx.json")

ALL_FIXTURE_DOCS = (
    COMPLETE_DOC,
    INCOMPLETE_PACKAGE_DOC,
    MISSING_SUPPLIER_DOC,
    DANGLING_SUPPLIER_DOC,
    NO_DESCRIBES_DOC,
)


class TestRegistration:
    """Tests for register_spdx3_rules and the SPDX3_RULES tuple."""

    def test_register_spdx3_rules_registers_every_rule(self) -> None:
        """register_spdx3_rules registers each rule in SPDX3_RULES exactly once."""
        registry = ProfileRuleRegistry()
        register_spdx3_rules(registry)

        assert {rule.rule_id for rule in registry.rules()} == {
            rule.rule_id for rule in SPDX3_RULES
        }
        assert len(registry.rules()) == len(SPDX3_RULES)

    def test_all_rules_declare_spdx_3_0_1_only(self) -> None:
        """Every rule's spdx_versions is exactly ("3.0.1",)."""
        for rule in SPDX3_RULES:
            assert rule.spdx_versions == ("3.0.1",)

    def test_package_purl_rule_id_not_registered(self) -> None:
        """package_purl is deliberately absent (NEEDS_DECISION in the matrix)."""
        rule_ids = {rule.rule_id for rule in SPDX3_RULES}
        assert "spdx3_completeness.package_purl" not in rule_ids


class TestCompleteFixtureIsZeroFindings:
    """complete.spdx.json must produce zero findings from every rule."""

    @pytest.mark.parametrize(
        "rule", SPDX3_RULES, ids=[rule.rule_id for rule in SPDX3_RULES]
    )
    def test_rule_produces_no_findings_on_complete_fixture(self, rule: Any) -> None:
        """Each implemented rule returns [] against the conforming fixture.

        complete.spdx.json was verified (by direct evaluation of every
        rule in SPDX3_RULES) to satisfy all of them, so no rule needs to
        be excluded from this sweep.
        """
        messages = rule.evaluate(COMPLETE_DOC, _context())
        assert messages == []


class TestIncompletePackageFixture:
    """incomplete-package.spdx.json: the bare package triggers several rules."""

    def test_bare_package_triggers_expected_rule_ids(self) -> None:
        """version, download location, supplier, concluded+declared license all fire."""
        registry = ProfileRuleRegistry()
        register_spdx3_rules(registry)
        messages, _coverage = registry.run(INCOMPLETE_PACKAGE_DOC, _context())

        fired = _rule_ids(messages)
        expected = {
            "spdx3_completeness.package_version",
            "spdx3_completeness.package_download_location",
            "spdx3_completeness.package_supplier",
            "spdx3_completeness.license_concluded",
            "spdx3_completeness.license_declared",
        }
        assert expected.issubset(fired)

    def test_bare_package_name_and_identifier_pass(self) -> None:
        """The bare package still has name and spdxId, so those rules pass."""

        assert PackageNameRule().evaluate(INCOMPLETE_PACKAGE_DOC, _context()) == []
        assert (
            PackageIdentifierRule().evaluate(INCOMPLETE_PACKAGE_DOC, _context()) == []
        )


class TestSupplierDistinguishesMissingFromDangling:
    """Supplier rule must distinguish absent from dangling with different wording."""

    def test_missing_supplier_uses_states_no_supplier_wording(self) -> None:
        """missing-supplier.spdx.json produces the 'states no supplier' message."""

        messages = PackageSupplierRule().evaluate(MISSING_SUPPLIER_DOC, _context())
        assert len(messages) == 1
        assert "states no supplier" in messages[0].message
        assert "not present in the document" not in messages[0].message

    def test_dangling_supplier_uses_dangling_wording(self) -> None:
        """dangling-supplier.spdx.json produces the dangling-reference message."""

        messages = PackageSupplierRule().evaluate(DANGLING_SUPPLIER_DOC, _context())
        assert len(messages) == 1
        assert "not present in the document" in messages[0].message
        assert "states no supplier" not in messages[0].message

    def test_missing_and_dangling_produce_different_messages(self) -> None:
        """The two fixtures produce genuinely different message text."""

        rule = PackageSupplierRule()
        missing_messages = rule.evaluate(MISSING_SUPPLIER_DOC, _context())
        dangling_messages = rule.evaluate(DANGLING_SUPPLIER_DOC, _context())

        assert missing_messages[0].message != dangling_messages[0].message


class TestNoDescribesFixture:
    """no-describes.spdx.json: document_describes fires and the package is isolated."""

    def test_document_describes_fires(self) -> None:
        """document_describes fires when there is no rootElement or describes link."""

        messages = DocumentDescribesRule().evaluate(NO_DESCRIBES_DOC, _context())
        assert len(messages) == 1
        assert (
            "rootElement" in messages[0].message or "describes" in messages[0].message
        )

    def test_no_isolated_elements_reports_the_unreachable_package(self) -> None:
        """no_isolated_elements names the isolated package element."""

        messages = NoIsolatedElementsRule().evaluate(NO_DESCRIBES_DOC, _context())
        assert len(messages) == 1
        assert "https://qualcomm.example/spdx/pkg/isolated" in messages[0].field_path


class TestMessageShapeAcrossRulesAndFixtures:
    """Every message from every rule must carry field_path/rule_id/remediation."""

    @pytest.mark.parametrize(
        "rule", SPDX3_RULES, ids=[rule.rule_id for rule in SPDX3_RULES]
    )
    @pytest.mark.parametrize(
        "document",
        ALL_FIXTURE_DOCS,
        ids=[
            "complete",
            "incomplete-package",
            "missing-supplier",
            "dangling-supplier",
            "no-describes",
        ],
    )
    def test_messages_carry_required_fields(
        self, rule: Any, document: dict[str, Any]
    ) -> None:
        """Every message has non-empty field_path/remediation and rule_id == rule.rule_id."""
        messages = rule.evaluate(document, _context())
        for message in messages:
            assert message.rule_id == rule.rule_id
            assert message.field_path
            assert message.remediation


class TestSpecVersionRule:
    """spec_version fires on anything other than exactly '3.0.1'."""

    def test_spec_version_3_0_0_fires(self) -> None:
        """A document whose CreationInfo.specVersion is '3.0.0' fires."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "CreationInfo":
                element["specVersion"] = "3.0.0"

        messages = SpecVersionRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert messages[0].found_value == "3.0.0"

    def test_spec_version_3_0_1_does_not_fire(self) -> None:
        """A document whose CreationInfo.specVersion is '3.0.1' does not fire."""

        assert SpecVersionRule().evaluate(COMPLETE_DOC, _context()) == []


class TestCreationTimestampRule:
    """creation_timestamp distinguishes missing CreationInfo/created from malformed."""

    def _doc_without_creation_info(self) -> dict[str, Any]:
        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"] = [
            element
            for element in doc["@graph"]
            if element.get("type") != "CreationInfo"
        ]
        return doc

    def _doc_with_created(self, created: Any) -> dict[str, Any]:
        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "CreationInfo":
                if created is None:
                    element.pop("created", None)
                else:
                    element["created"] = created
        return doc

    def test_missing_creation_info_fires(self) -> None:
        """A document with no resolvable CreationInfo fires."""

        messages = CreationTimestampRule().evaluate(
            self._doc_without_creation_info(), _context()
        )
        assert len(messages) == 1
        assert "no resolvable CreationInfo" in messages[0].message

    def test_missing_created_fires(self) -> None:
        """A CreationInfo with no created value fires with distinct wording."""

        messages = CreationTimestampRule().evaluate(
            self._doc_with_created(None), _context()
        )
        assert len(messages) == 1
        assert "missing a 'created'" in messages[0].message

    def test_malformed_created_date_only_fires(self) -> None:
        """A date-only created value (no time) fires."""

        messages = CreationTimestampRule().evaluate(
            self._doc_with_created("2026-01-15"), _context()
        )
        assert len(messages) == 1
        assert "not a valid ISO-8601 UTC instant" in messages[0].message

    def test_malformed_created_non_utc_offset_fires(self) -> None:
        """A non-UTC offset created value fires."""

        messages = CreationTimestampRule().evaluate(
            self._doc_with_created("2026-01-15T00:00:00+05:00"), _context()
        )
        assert len(messages) == 1

    def test_valid_created_does_not_fire(self) -> None:
        """A valid ISO-8601 UTC created value does not fire."""

        assert CreationTimestampRule().evaluate(COMPLETE_DOC, _context()) == []


class TestCreatorsRule:
    """creators distinguishes empty createdBy from a dangling createdBy IRI."""

    def test_empty_created_by_fires(self) -> None:
        """An empty createdBy list produces the absent-creators message."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "CreationInfo":
                element["createdBy"] = []

        messages = CreatorsRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "states no createdBy creators" in messages[0].message

    def test_dangling_created_by_fires_with_different_message(self) -> None:
        """A dangling createdBy IRI produces a different message than the empty case."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "CreationInfo":
                element["createdBy"] = ["https://qualcomm.example/spdx/agent/ghost"]

        empty_messages = CreatorsRule().evaluate(
            {
                **doc,
                "@graph": [
                    {**e, "createdBy": []} if e.get("type") == "CreationInfo" else e
                    for e in doc["@graph"]
                ],
            },
            _context(),
        )
        dangling_messages = CreatorsRule().evaluate(doc, _context())

        assert len(dangling_messages) == 1
        assert "not present in the document" in dangling_messages[0].message
        assert empty_messages[0].message != dangling_messages[0].message


class TestDocumentIdentifierRule:
    """document_identifier fires on fragments; passes on clean absolute IRIs."""

    def test_fragment_identifier_fires(self) -> None:
        """A document spdxId containing '#' fires."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "SpdxDocument":
                element["spdxId"] = "https://qualcomm.example/spdx/doc-complete#frag"

        messages = DocumentIdentifierRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "fragment" in messages[0].message

    def test_clean_absolute_iri_does_not_fire(self) -> None:
        """A clean absolute IRI document identifier does not fire."""

        assert DocumentIdentifierRule().evaluate(COMPLETE_DOC, _context()) == []


class TestPackageCpeRule:
    """package_cpe is conditional on a CPE external identifier existing."""

    def test_empty_cpe23_identifier_fires(self) -> None:
        """A cpe23 external identifier entry with an empty identifier fires."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "software_Package":
                element["externalIdentifier"] = [
                    {
                        "type": "ExternalIdentifier",
                        "externalIdentifierType": "cpe23",
                        "identifier": "",
                    }
                ]

        messages = PackageCpeRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "cpe23" in messages[0].message

    def test_no_cpe_entry_does_not_fire(self) -> None:
        """A package with no CPE entry at all passes (conditional rule)."""

        assert PackageCpeRule().evaluate(INCOMPLETE_PACKAGE_DOC, _context()) == []


def _second_package(doc: dict[str, Any], spdx_id: str, name: str) -> dict[str, Any]:
    """Build a second bare package element for multi-package test fixtures.

    Args:
        doc: The source document to copy a CreationInfo reference style from.
        spdx_id: The spdxId to assign the new package.
        name: The name to assign the new package.

    Returns:
        dict[str, Any]: A minimal software_Package element.
    """
    _ = doc
    return {
        "type": "software_Package",
        "spdxId": spdx_id,
        "name": name,
        "creationInfo": "_:creationInfo",
    }


class TestDependencyRelationshipsRule:
    """dependency_relationships requires a contains/dependsOn link between packages."""

    def test_two_packages_with_no_relationship_fires(self) -> None:
        """Two packages with no contains/dependsOn relationship fires."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"].append(
            _second_package(doc, "https://qualcomm.example/spdx/pkg/second", "second")
        )

        messages = DependencyRelationshipsRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert messages[0].rule_id == "spdx3_completeness.dependency_relationships"

    def test_two_packages_with_contains_passes(self) -> None:
        """Two packages linked by a contains relationship pass."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"].append(
            _second_package(doc, "https://qualcomm.example/spdx/pkg/second", "second")
        )
        doc["@graph"].append(
            {
                "type": "Relationship",
                "spdxId": "https://qualcomm.example/spdx/rel/contains",
                "creationInfo": "_:creationInfo",
                "from": "https://qualcomm.example/spdx/pkg/libwidget",
                "relationshipType": "contains",
                "to": ["https://qualcomm.example/spdx/pkg/second"],
            }
        )

        assert DependencyRelationshipsRule().evaluate(doc, _context()) == []

    def test_two_packages_with_depends_on_passes(self) -> None:
        """Two packages linked by a dependsOn relationship pass."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"].append(
            _second_package(doc, "https://qualcomm.example/spdx/pkg/second", "second")
        )
        doc["@graph"].append(
            {
                "type": "Relationship",
                "spdxId": "https://qualcomm.example/spdx/rel/depends",
                "creationInfo": "_:creationInfo",
                "from": "https://qualcomm.example/spdx/pkg/libwidget",
                "relationshipType": "dependsOn",
                "to": ["https://qualcomm.example/spdx/pkg/second"],
            }
        )

        assert DependencyRelationshipsRule().evaluate(doc, _context()) == []

    def test_single_package_passes(self) -> None:
        """A single-package document passes (nothing to relate)."""

        assert DependencyRelationshipsRule().evaluate(COMPLETE_DOC, _context()) == []

    def test_zero_packages_passes(self) -> None:
        """A document with no packages at all passes."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"] = [
            element
            for element in doc["@graph"]
            if element.get("type") != "software_Package"
        ]

        assert DependencyRelationshipsRule().evaluate(doc, _context()) == []


class TestLicenseListVersionRule:
    """license_list_version checks each LicenseExpression's optional version."""

    def _doc_with_license_list_version(self, value: Any) -> dict[str, Any]:
        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "simplelicensing_LicenseExpression":
                if value is None:
                    element.pop("simplelicensing_licenseListVersion", None)
                else:
                    element["simplelicensing_licenseListVersion"] = value
        return doc

    def test_valid_semver_version_passes(self) -> None:
        """A LicenseExpression with a valid semver version passes."""

        doc = self._doc_with_license_list_version("3.25.0")
        assert LicenseListVersionRule().evaluate(doc, _context()) == []

    def test_empty_version_fires(self) -> None:
        """An empty simplelicensing_licenseListVersion fires."""

        doc = self._doc_with_license_list_version("")
        messages = LicenseListVersionRule().evaluate(doc, _context())
        assert len(messages) == 1

    def test_non_semver_version_fires(self) -> None:
        """A non-semver-shaped value fires."""

        doc = self._doc_with_license_list_version("not-a-version")
        messages = LicenseListVersionRule().evaluate(doc, _context())
        assert len(messages) == 1

    def test_omitted_version_passes(self) -> None:
        """A LicenseExpression that omits the property entirely passes."""

        doc = self._doc_with_license_list_version(None)
        assert LicenseListVersionRule().evaluate(doc, _context()) == []

    def test_no_license_expression_elements_passes(self) -> None:
        """A document with no LicenseExpression elements at all passes."""

        doc = json.loads(json.dumps(COMPLETE_DOC))
        doc["@graph"] = [
            element
            for element in doc["@graph"]
            if element.get("type") != "simplelicensing_LicenseExpression"
        ]

        assert LicenseListVersionRule().evaluate(doc, _context()) == []


class TestPackageVerificationCodeRule:
    """package_verification_code checks verifiedUsing PackageVerificationCode entries."""

    def _doc_with_verified_using(self, value: Any) -> dict[str, Any]:
        doc = json.loads(json.dumps(COMPLETE_DOC))
        for element in doc["@graph"]:
            if element.get("type") == "software_Package":
                if value is None:
                    element.pop("verifiedUsing", None)
                else:
                    element["verifiedUsing"] = value
        return doc

    def test_real_hash_value_passes(self) -> None:
        """A PackageVerificationCode with a real hashValue passes."""

        doc = self._doc_with_verified_using(
            {
                "type": "PackageVerificationCode",
                "hashValue": "abc123",
            }
        )
        assert PackageVerificationCodeRule().evaluate(doc, _context()) == []

    def test_empty_hash_value_fires(self) -> None:
        """A PackageVerificationCode with an empty hashValue fires."""

        doc = self._doc_with_verified_using(
            {
                "type": "PackageVerificationCode",
                "hashValue": "",
            }
        )
        messages = PackageVerificationCodeRule().evaluate(doc, _context())
        assert len(messages) == 1

    def test_no_verified_using_passes(self) -> None:
        """A package with no verifiedUsing at all passes."""

        doc = self._doc_with_verified_using(None)
        assert PackageVerificationCodeRule().evaluate(doc, _context()) == []

    def test_plain_hash_entry_is_ignored(self) -> None:
        """A verifiedUsing entry typed Hash (not PackageVerificationCode) passes."""

        doc = self._doc_with_verified_using(
            {
                "type": "Hash",
                "algorithm": "sha256",
                "hashValue": "abc123",
            }
        )
        assert PackageVerificationCodeRule().evaluate(doc, _context()) == []

    def test_iri_reference_form_resolves(self) -> None:
        """A verifiedUsing IRI reference to a top-level element resolves correctly."""

        doc = self._doc_with_verified_using(
            "https://qualcomm.example/spdx/verification/libwidget"
        )
        doc["@graph"].append(
            {
                "@id": "https://qualcomm.example/spdx/verification/libwidget",
                "type": "PackageVerificationCode",
                "hashValue": "",
            }
        )
        messages = PackageVerificationCodeRule().evaluate(doc, _context())
        assert len(messages) == 1


class TestRobustness:
    """Every rule must return a list (never raise) on degenerate input."""

    @pytest.mark.parametrize(
        "rule", SPDX3_RULES, ids=[rule.rule_id for rule in SPDX3_RULES]
    )
    @pytest.mark.parametrize(
        "document", [{}, {"@graph": []}], ids=["empty-dict", "empty-graph"]
    )
    def test_rule_never_raises_on_degenerate_documents(
        self, rule: Any, document: dict[str, Any]
    ) -> None:
        """Every rule returns a list, never raises, on {} and {"@graph": []}."""
        result = rule.evaluate(document, _context())
        assert isinstance(result, list)


PKG_ID = "https://qualcomm.example/spdx/pkg/libwidget"
DOC_ID = "https://qualcomm.example/spdx/doc-complete"
LICENSE_ID = "https://qualcomm.example/spdx/license/apache"
AGENT_ID = "https://qualcomm.example/spdx/agent/acme-corp"


def _copy(doc: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a fixture document so a test can mutate it freely.

    Args:
        doc: The document to copy.

    Returns:
        dict[str, Any]: An independent copy.
    """
    return json.loads(json.dumps(doc))


def _element(doc: dict[str, Any], type_name: str) -> dict[str, Any]:
    """Return the first ``@graph`` entry of a given type.

    Args:
        doc: The document to search.
        type_name: The raw ``type`` value to match.

    Returns:
        dict[str, Any]: The matching entry.
    """
    return next(e for e in doc["@graph"] if e.get("type") == type_name)


_REL_IDS = itertools.count()


def _relationship(rel_type: str, from_id: str | None, to: Any) -> dict[str, Any]:
    """Build a Relationship element.

    Args:
        rel_type: The relationshipType.
        from_id: The from IRI, or None to omit it.
        to: The raw to value.

    Returns:
        dict[str, Any]: The Relationship element.
    """
    rel: dict[str, Any] = {
        "type": "Relationship",
        "spdxId": f"https://qualcomm.example/spdx/rel/{rel_type}-{next(_REL_IDS)}",
        "creationInfo": "_:creationInfo",
        "relationshipType": rel_type,
        "to": to,
    }
    if from_id is not None:
        rel["from"] = from_id
    return rel


class TestLicenseRelationshipTargets:
    """License relationships must resolve to an AnyLicenseInfo element."""

    def _with_targets(self, rel_type: str, to: Any) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        for element in doc["@graph"]:
            if element.get("relationshipType") == rel_type:
                element["to"] = to
        return doc

    @pytest.mark.parametrize(
        ("rule", "rel_type"),
        [
            (LicenseConcludedRule(), "hasConcludedLicense"),
            (LicenseDeclaredRule(), "hasDeclaredLicense"),
        ],
        ids=["concluded", "declared"],
    )
    def test_dangling_target_fails(self, rule: Any, rel_type: str) -> None:
        """A target id absent from the graph is a dangling-reference finding."""
        doc = self._with_targets(rel_type, ["https://example.test/missing"])

        messages = rule.evaluate(doc, _context())
        assert len(messages) == 1
        assert "not present in the document" in messages[0].message
        assert messages[0].found_value == "https://example.test/missing"

    @pytest.mark.parametrize(
        ("rule", "rel_type"),
        [
            (LicenseConcludedRule(), "hasConcludedLicense"),
            (LicenseDeclaredRule(), "hasDeclaredLicense"),
        ],
        ids=["concluded", "declared"],
    )
    @pytest.mark.parametrize("target", [PKG_ID, AGENT_ID], ids=["package", "agent"])
    def test_wrong_type_target_fails(
        self, rule: Any, rel_type: str, target: str
    ) -> None:
        """A target that resolves to a non-license element fails."""
        doc = self._with_targets(rel_type, [target])

        messages = rule.evaluate(doc, _context())
        assert len(messages) == 1
        assert "does not identify an AnyLicenseInfo" in messages[0].message

    def test_malformed_target_fails(self) -> None:
        """A literal license name is not a reference and fails."""
        doc = self._with_targets("hasConcludedLicense", ["Apache-2.0"])

        messages = LicenseConcludedRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "is not an IRI" in messages[0].message

    def test_empty_target_list_fails_as_missing(self) -> None:
        """A relationship with no targets counts as no license relationship."""
        doc = self._with_targets("hasConcludedLicense", [])

        messages = LicenseConcludedRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "has no hasConcludedLicense relationship" in messages[0].message

    def test_one_bad_target_is_reported_alongside_a_good_one(self) -> None:
        """Each unresolvable target is reported, even when another resolves."""
        doc = self._with_targets(
            "hasDeclaredLicense", [LICENSE_ID, "https://example.test/missing"]
        )

        messages = LicenseDeclaredRule().evaluate(doc, _context())
        assert [m.found_value for m in messages] == ["https://example.test/missing"]

    @pytest.mark.parametrize(
        "license_type",
        [
            "expandedlicensing_ListedLicense",
            "expandedlicensing_CustomLicense",
            "expandedlicensing_ConjunctiveLicenseSet",
            "https://spdx.org/rdf/3.0.1/terms/SimpleLicensing/LicenseExpression",
        ],
    )
    def test_other_any_license_info_types_resolve(self, license_type: str) -> None:
        """Any AnyLicenseInfo subclass is an acceptable target."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "simplelicensing_LicenseExpression")["type"] = license_type

        assert LicenseConcludedRule().evaluate(doc, _context()) == []

    def test_spdx_license_list_iri_resolves(self) -> None:
        """An SPDX License List IRI resolves without a @graph entry."""
        doc = self._with_targets(
            "hasConcludedLicense", ["https://spdx.org/licenses/MIT"]
        )

        assert LicenseConcludedRule().evaluate(doc, _context()) == []


class TestDataLicenseRule:
    """dataLicense must resolve to an AnyLicenseInfo element."""

    def _with_data_license(self, value: Any) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        spdx_doc = _element(doc, "SpdxDocument")
        if value is None:
            spdx_doc.pop("dataLicense", None)
        else:
            spdx_doc["dataLicense"] = value
        return doc

    def _message(self, value: Any) -> str:
        messages = DataLicenseRule().evaluate(
            self._with_data_license(value), _context()
        )
        assert len(messages) == 1
        return messages[0].message

    @pytest.mark.parametrize(
        "value", [None, "", "   "], ids=["absent", "empty", "blank"]
    )
    def test_missing_value_fires(self, value: Any) -> None:
        """An absent or empty dataLicense is reported as missing."""
        assert "missing a dataLicense" in self._message(value)

    @pytest.mark.parametrize("value", ["not-a-license", "CC0-1.0", 42, ["x"]])
    def test_malformed_value_fires(self, value: Any) -> None:
        """A literal string or non-string value is reported as malformed."""
        assert "is not an IRI reference" in self._message(value)

    def test_dangling_value_fires(self) -> None:
        """An IRI naming no element is reported as dangling."""
        message = self._message("https://example.test/missing-license")
        assert "not present in the document" in message

    def test_wrong_type_value_fires(self) -> None:
        """An IRI naming a non-license element is reported as wrong type."""
        assert "does not identify an AnyLicenseInfo" in self._message(PKG_ID)

    def test_four_failure_kinds_have_distinct_messages(self) -> None:
        """Missing, malformed, dangling and wrong-type are told apart."""
        wordings = {
            self._message(None),
            self._message("not-a-license"),
            self._message("https://example.test/missing-license"),
            self._message(PKG_ID),
        }
        assert len(wordings) == 4

    def test_resolving_graph_element_passes(self) -> None:
        """An IRI naming a license element in the graph passes."""
        doc = self._with_data_license(LICENSE_ID)
        assert DataLicenseRule().evaluate(doc, _context()) == []

    def test_spdx_license_list_iri_passes(self) -> None:
        """The complete fixture's https://spdx.org/licenses/CC0-1.0 passes."""
        assert DataLicenseRule().evaluate(COMPLETE_DOC, _context()) == []


class TestDocumentDescribesResolution:
    """At least one rootElement or describes target must resolve."""

    def _doc(self, root: Any, describes_to: Any) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        spdx_doc = _element(doc, "SpdxDocument")
        if root is None:
            spdx_doc.pop("rootElement", None)
        else:
            spdx_doc["rootElement"] = root
        doc["@graph"] = [
            e for e in doc["@graph"] if e.get("relationshipType") != "describes"
        ]
        if describes_to is not None:
            doc["@graph"].append(_relationship("describes", DOC_ID, describes_to))
        return doc

    def test_dangling_root_element_fires(self) -> None:
        """A rootElement naming no element fails."""
        doc = self._doc(["https://example.test/absent"], None)

        messages = DocumentDescribesRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "none of its targets is present" in messages[0].message

    def test_describes_with_empty_to_fires(self) -> None:
        """A describes relationship with an empty to fails."""
        messages = DocumentDescribesRule().evaluate(self._doc(None, []), _context())
        assert len(messages) == 1
        assert "none of its targets is present" in messages[0].message

    def test_describes_with_dangling_to_fires(self) -> None:
        """A describes relationship whose to does not resolve fails."""
        doc = self._doc(None, ["https://example.test/absent"])

        messages = DocumentDescribesRule().evaluate(doc, _context())
        assert len(messages) == 1

    def test_absent_root_and_describes_fires_with_distinct_wording(self) -> None:
        """Declaring nothing is worded differently from declaring dangling targets."""
        messages = DocumentDescribesRule().evaluate(self._doc(None, None), _context())
        assert len(messages) == 1
        assert "declares neither" in messages[0].message

    def test_resolving_describes_alone_passes(self) -> None:
        """A resolving describes target passes without rootElement."""
        doc = self._doc(None, [PKG_ID])
        assert DocumentDescribesRule().evaluate(doc, _context()) == []

    def test_resolving_root_alongside_dangling_describes_passes(self) -> None:
        """One resolving target is enough."""
        doc = self._doc([PKG_ID], ["https://example.test/absent"])
        assert DocumentDescribesRule().evaluate(doc, _context()) == []


class TestDuplicateIdentifiers:
    """Duplicate spdxIds are identifier errors and never resolve."""

    def _duplicate_package_doc(self) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        twin = _copy(_element(doc, "software_Package"))
        twin["name"] = "impostor"
        doc["@graph"].append(twin)
        return doc

    def test_duplicate_package_ids_fail_for_each_definition(self) -> None:
        """Both packages sharing an absolute spdxId are reported."""
        messages = PackageIdentifierRule().evaluate(
            self._duplicate_package_doc(), _context()
        )

        assert len(messages) == 2
        assert {m.found_value for m in messages} == {PKG_ID}
        assert len({m.field_path for m in messages}) == 2
        assert all("ambiguous" in m.message for m in messages)

    def test_duplicate_package_ids_cannot_satisfy_references(self) -> None:
        """References to a duplicated id do not resolve to either definition."""
        doc = self._duplicate_package_doc()

        messages = DocumentDescribesRule().evaluate(doc, _context())
        assert len(messages) == 1

    def test_duplicate_non_package_id_is_reported_by_document_identifier(
        self,
    ) -> None:
        """A duplicated license id is reported once, by document_identifier."""
        doc = _copy(COMPLETE_DOC)
        doc["@graph"].append(_copy(_element(doc, "simplelicensing_LicenseExpression")))

        messages = DocumentIdentifierRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert messages[0].found_value == LICENSE_ID
        # And the license reference no longer resolves.
        assert LicenseConcludedRule().evaluate(doc, _context()) != []

    def test_duplicate_package_id_not_double_reported(self) -> None:
        """document_identifier leaves package duplicates to package_identifier."""
        doc = self._duplicate_package_doc()
        assert DocumentIdentifierRule().evaluate(doc, _context()) == []


class TestAbsoluteIri:
    """_is_absolute_iri validates RFC 3987/3986 syntax without resolving."""

    @pytest.mark.parametrize(
        "value",
        [
            "https://qualcomm.example/spdx/pkg/libwidget",
            "http://example.org:8080/a/b?q=1#frag",
            "mailto:sbom@example.org",
            "urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66",
            "tag:example.org,2026:sbom",
            "file:///tmp/sbom.json",
            "http://[2001:db8::1]/x",
            "https://example.org/caf%C3%A9",
            "https://例え.jp/パス",
            "z39.50r://example.org/db",
        ],
    )
    def test_valid_iris_are_accepted(self, value: str) -> None:
        """Hierarchical and non-hierarchical absolute IRIs are accepted."""
        assert _is_absolute_iri(value) is True

    @pytest.mark.parametrize(
        "value",
        [
            "not a URI://x",
            "",
            "   ",
            "relative/path",
            "//example.org/x",
            "1http://example.org",
            "-x:y",
            "ht tp://example.org",
            "https://exa mple.org",
            " https://example.org",
            "https://example.org/ ",
            "https://example.org/a\tb",
            "https://example.org/%zz",
            "https://example.org/%4",
            "https://example.org:80x/",
            "http://[::g]/",
            "https://example.org/a<b>",
            "https:",
            "urn:",
            "urn:uuid:",
            "urn:x:y",
            None,
            42,
        ],
    )
    def test_invalid_iris_are_rejected(self, value: Any) -> None:
        """Malformed schemes, whitespace, bad escapes and empty URNs fail."""
        assert _is_absolute_iri(value) is False

    def test_package_rule_rejects_contains_scheme_separator(self) -> None:
        """A package spdxId like 'not a URI://x' fails package_identifier."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "software_Package")["spdxId"] = "not a URI://x"

        messages = PackageIdentifierRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "not an absolute IRI" in messages[0].message

    def test_document_rule_accepts_non_hierarchical_scheme(self) -> None:
        """A urn:/non-hierarchical document spdxId passes document_identifier."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "SpdxDocument")["spdxId"] = "urn:uuid:1b4e28ba-2fa1-11d2"

        assert DocumentIdentifierRule().evaluate(doc, _context()) == []


class TestTimestampValues:
    """created must be a real UTC instant, not just the right digit counts."""

    @pytest.mark.parametrize(
        "value",
        [
            "2025-99-99T29:70:70Z",
            "2026-13-01T00:00:00Z",
            "2026-00-10T00:00:00Z",
            "2026-01-00T00:00:00Z",
            "2026-01-32T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2025-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2026-01-15T24:00:00Z",
            "2026-01-15T23:60:00Z",
            "2026-01-15T23:59:60Z",
            "2026-01-15T00:00:00",
            "2026-01-15T00:00:00+00:00",
            "2026-01-15T00:00:00.Z",
            "2026-01-15 00:00:00Z",
            "2026-01-15T00:00:00Z\n",
        ],
    )
    def test_invalid_timestamps_fail(self, value: str) -> None:
        """Out-of-range fields, impossible dates and non-Z forms fail."""
        assert _is_valid_timestamp(value) is False

    @pytest.mark.parametrize(
        "value",
        [
            "2026-01-15T00:00:00Z",
            "2024-02-29T12:00:00Z",
            "2000-02-29T23:59:59Z",
            "2026-12-31T23:59:59.999999Z",
            "2026-06-01T08:30:00.1Z",
            "2026-06-01T08:30:00.123456789Z",
        ],
    )
    def test_valid_timestamps_pass(self, value: str) -> None:
        """Valid instants, leap days and any fractional precision pass."""
        assert _is_valid_timestamp(value) is True

    def test_rule_reports_impossible_timestamp(self) -> None:
        """The creation_timestamp rule fires on an impossible date."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "CreationInfo")["created"] = "2025-99-99T29:70:70Z"

        messages = CreationTimestampRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert messages[0].found_value == "2025-99-99T29:70:70Z"


class TestCreationInfoMustBeCreationInfo:
    """creationInfo must resolve to an element of type CreationInfo."""

    def _doc_pointing_creation_info_at_package(self) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        _element(doc, "SpdxDocument")["creationInfo"] = PKG_ID
        package = _element(doc, "software_Package")
        package["created"] = "2026-01-15T00:00:00Z"
        package["createdBy"] = [AGENT_ID]
        package["specVersion"] = "3.0.1"
        return doc

    def test_wrong_type_reference_fails_timestamp_rule(self) -> None:
        """A creationInfo pointing at a package is reported, not trusted."""
        doc = self._doc_pointing_creation_info_at_package()

        messages = CreationTimestampRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "does not identify a CreationInfo" in messages[0].message

    def test_wrong_type_reference_does_not_satisfy_other_metadata_rules(
        self,
    ) -> None:
        """Creators and spec version do not read fields off the wrong element."""
        doc = self._doc_pointing_creation_info_at_package()

        assert CreatorsRule().evaluate(doc, _context()) == []
        assert SpecVersionRule().evaluate(doc, _context()) == []
        adapter = Spdx3Document.from_dict(doc)
        spdx_doc = adapter.spdx_document()
        assert spdx_doc is not None
        assert adapter.creation_info_for(spdx_doc) is None

    def test_wrong_type_inline_value_fails(self) -> None:
        """An inline creationInfo object of another type is also rejected."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "SpdxDocument")["creationInfo"] = {
            "type": "software_Package",
            "created": "2026-01-15T00:00:00Z",
        }

        messages = CreationTimestampRule().evaluate(doc, _context())
        assert len(messages) == 1
        assert "does not identify a CreationInfo" in messages[0].message


class TestDependencyEndpoints:
    """Only a package-to-different-package contains/dependsOn link counts."""

    SECOND = "https://qualcomm.example/spdx/pkg/second"

    def _doc_with(self, *relationships: dict[str, Any]) -> dict[str, Any]:
        doc = _copy(COMPLETE_DOC)
        doc["@graph"].append(_second_package(doc, self.SECOND, "second"))
        doc["@graph"].extend(relationships)
        return doc

    @pytest.mark.parametrize(
        "relationship",
        [
            _relationship("dependsOn", PKG_ID, []),
            _relationship("dependsOn", PKG_ID, ["https://example.test/absent"]),
            _relationship("dependsOn", "https://example.test/absent", [PKG_ID]),
            _relationship("dependsOn", None, [PKG_ID]),
            _relationship("contains", DOC_ID, [LICENSE_ID]),
            _relationship("contains", PKG_ID, [LICENSE_ID]),
            _relationship("contains", LICENSE_ID, [PKG_ID]),
            _relationship("dependsOn", PKG_ID, [PKG_ID]),
        ],
        ids=[
            "empty-to",
            "dangling-to",
            "dangling-from",
            "absent-from",
            "non-package-endpoints",
            "non-package-target",
            "non-package-source",
            "self-loop",
        ],
    )
    def test_unrelated_relationship_does_not_satisfy_rule(
        self, relationship: dict[str, Any]
    ) -> None:
        """Relationships without two distinct package endpoints still fire."""
        messages = DependencyRelationshipsRule().evaluate(
            self._doc_with(relationship), _context()
        )
        assert len(messages) == 1

    def test_package_to_package_passes(self) -> None:
        """A dependsOn from one package to another passes."""
        doc = self._doc_with(_relationship("dependsOn", self.SECOND, [PKG_ID]))
        assert DependencyRelationshipsRule().evaluate(doc, _context()) == []


class TestIsolatedNonPackageArtifacts:
    """no_isolated_elements covers snippets and exempts property-linked types."""

    def test_disconnected_snippet_is_reported(self) -> None:
        """A software_Snippet with no path from the document is reported."""
        doc = _copy(COMPLETE_DOC)
        doc["@graph"].append(
            {
                "type": "software_Snippet",
                "spdxId": "https://qualcomm.example/spdx/snippet/orphan",
                "creationInfo": "_:creationInfo",
                "software_snippetFromFile": "https://qualcomm.example/spdx/file/x",
            }
        )

        messages = NoIsolatedElementsRule().evaluate(doc, _context())
        assert [m.field_path for m in messages] == [
            "https://qualcomm.example/spdx/snippet/orphan"
        ]

    def test_property_linked_agent_and_license_are_exempt(self) -> None:
        """Agents and licenses are reached via properties, not relationships."""
        doc = _copy(COMPLETE_DOC)
        doc["@graph"].append(
            {
                "type": "Person",
                "spdxId": "https://qualcomm.example/spdx/agent/unlinked",
                "creationInfo": "_:creationInfo",
                "name": "Unlinked",
            }
        )
        assert NoIsolatedElementsRule().evaluate(doc, _context()) == []


class TestLicenseListVersionFullMatch:
    """license_list_version must match the whole value."""

    @pytest.mark.parametrize(
        "value", ["3.25.0junk", "3.25.0 ", "3.25.0.1", "v3.25.0", "3.25", "03.25.0"]
    )
    def test_trailing_or_invalid_text_fires(self, value: str) -> None:
        """Trailing text and other invalid suffixes are rejected."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "simplelicensing_LicenseExpression")[
            "simplelicensing_licenseListVersion"
        ] = value

        assert len(LicenseListVersionRule().evaluate(doc, _context())) == 1

    @pytest.mark.parametrize("value", ["3.25.0", "3.26.0-rc.1", "3.25.0+build.5"])
    def test_semver_values_pass(self, value: str) -> None:
        """Full semver values, including pre-release and build, pass."""
        doc = _copy(COMPLETE_DOC)
        _element(doc, "simplelicensing_LicenseExpression")[
            "simplelicensing_licenseListVersion"
        ] = value

        assert LicenseListVersionRule().evaluate(doc, _context()) == []
