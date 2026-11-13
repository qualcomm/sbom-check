# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for the SPDX 3.0.1 Qualcomm completeness profile rules."""

from __future__ import annotations

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
    DocumentDescribesRule,
    DocumentIdentifierRule,
    NoIsolatedElementsRule,
    PackageCpeRule,
    PackageIdentifierRule,
    PackageNameRule,
    PackageSupplierRule,
    SpecVersionRule,
    register_spdx3_rules,
)

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
