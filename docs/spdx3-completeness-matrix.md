# SPDX 3.0.1 Completeness and Qualcomm Profile Validation — Requirements Matrix

## Status: PROPOSED — awaiting approval by Qualcomm SBOM owners

- **Document status:** This is a decision document, not an implementation record. Nothing in
  it has been approved. It exists to get a row-by-row sign-off from the Qualcomm SBOM owners
  before any SPDX 3.0.1 completeness rule is enabled.
- **Default behavior until approved:** every row in this matrix ships **disabled** in
  configuration. No `spdx3_completeness.*` rule may be turned on for any shipped profile
  (including `default`) until the corresponding row is explicitly approved below. Rows marked
  `NEEDS_DECISION` must additionally never be able to make a document silently "pass" — see
  Open Question 4.

---

## 1. Purpose

SBOM-Check today enforces two different things that are easy to conflate: core SPDX schema/
semantic conformance (is this a structurally valid SPDX document) and Qualcomm's own
completeness policy (does this SBOM contain the supplier, licensing, and traceability
information Qualcomm requires to consume it). Those two questions are independent of the SPDX
version in use. As SPDX 3.0.1 adoption grows, Qualcomm needs the same completeness policy
enforced against 3.0.1 documents — but the 3.0.1 object model is not a superset or a strict
re-encoding of 2.3; it changes what a "field" is for several of today's requirements. This
matrix is the decision record for which existing Qualcomm completeness requirements translate
directly into SPDX 3.0.1, which translate into a structurally different shape (an element or a
relationship instead of a field), which have no 3.0.1 equivalent at all, and which require a
Qualcomm product decision before anything can be implemented. Engineering will build only the
rows this document records as approved.

---

## 2. How SPDX 2.3 and SPDX 3.0.1 differ structurally

> **Provenance of the mappings below.** Every SPDX 3.0.1 property, class and relationship type
> cited in this document was checked against the normative SPDX 3.0.1 artifacts —
> `https://spdx.org/rdf/3.0.1/spdx-context.jsonld` (the JSON-LD term context) and
> `https://spdx.org/rdf/3.0.1/spdx-model.ttl` (the OWL/SHACL model). Where a row says a term
> exists, it was found in those files; where a row says a term is absent, it was searched for
> and not found. Rows marked `NEEDS_DECISION` are policy questions, not unresolved facts.
> Three distinctions that are easy to get wrong and are therefore called out explicitly:
> `suppliedBy` and `originatedBy` are **direct properties on `Artifact`**, not relationship
> types; `hasConcludedLicense` and `hasDeclaredLicense` **are** members of the
> `Core/RelationshipType` enumeration; and `PackageVerificationCode` **is retained** in 3.0.1
> as an `IntegrityMethod` subclass rather than removed.


This is a factual summary, not an opinion, used to justify the classifications below.

| Aspect | SPDX 2.3 | SPDX 3.0.1 |
|---|---|---|
| Top-level shape | Single JSON object with `packages[]`, `files[]`, `relationships[]` arrays | JSON-LD document with one `@graph` array of typed elements |
| Element typing | Implicit by array membership (`packages`, `files`) | Explicit `type` per graph entry: `SpdxDocument`, `software_Package`, `software_File`, `Agent`, `Organization`, `Relationship`, `CreationInfo`, etc. |
| Identifiers | `SPDXID` — a document-local string ref (e.g. `SPDXRef-Package-foo`) | `spdxId` — a globally unique IRI |
| Relationships | Flat `relationships[]` array; each entry has `spdxElementId`, `relationshipType`, `relatedSpdxElement` | `Relationship` is itself a graph element with `from`, `to` (IRIs), and `relationshipType`; there is no separate flat array |
| Document-describes-package | `relationships[]` entry with `relationshipType: DESCRIBES` | Typically expressed via a `Relationship` element (`relationshipType: describes`) and/or the `rootElement` property on the `SpdxDocument` element |
| Property naming | Flat camelCase (`versionInfo`, `downloadLocation`, `licenseConcluded`) | Namespace-prefixed per profile for non-core properties, e.g. `software_packageVersion`, `software_downloadLocation`, `software_packageUrl`, `software_copyrightText`; core properties (`name`, `created`, `spdxId`) stay unprefixed |
| Licensing | Scalar fields on the package (`licenseConcluded`, `licenseDeclared`) | `Relationship` elements using the `hasConcludedLicense` / `hasDeclaredLicense` relationship types rather than scalar package fields |
| External identifiers | `externalRefs[]` array on the package, keyed by `referenceType` | `ExternalIdentifier` elements keyed by `externalIdentifierType` (members include `packageUrl`, `cpe23`, `cpe22`, `swid`, `swhid`, `gitoid`, `cve`), and in some cases an equivalent namespaced property such as `software_packageUrl` — the shape is not uniform per identifier type and is called out per row below |

---

## 3. Classification legend

| Status | Definition | Resulting implementation behavior |
|---|---|---|
| `EQUIVALENT` | Same intent, direct property mapping from the 2.3 field to a 3.0.1 property. | Implement as a straightforward field check against the 3.0.1 property. |
| `REPRESENTED_DIFFERENTLY` | Same intent, but the 3.0.1 model expresses it as a different shape (an element, a relationship, or a differently-named/namespaced property) rather than a flat field. | Implement against the 3.0.1 shape (traverse `@graph` for the relevant element/relationship type), not as a field lookup. |
| `CONDITIONAL` | Applies only to certain element types or contexts and needs a stated business rule to know when it applies. | Implement only with the applicability rule written out explicitly; do not apply unconditionally. |
| `NOT_APPLICABLE` | The 2.3 concept does not exist in the 3.0.1 object model. | Do not implement for SPDX 3.0.1. Record why in the matrix; do not silently drop the row from documentation. |
| `NEEDS_DECISION` | Cannot be mapped without a Qualcomm product decision (policy choice, not a structural fact). | Ships disabled. Must never allow a document to be reported "complete" by omission — see Open Question 4 for the required disabled-row behavior. |

---

## 4. The matrix

Severity column is **proposed**, not decided — see Section 7 for the rationale and Section 8
for open questions. "SPDX 2.3 source" cites the exact `rule_id` string from
`src/sbom_check/engine.py` where one exists today, or the relevant config field in
`SbomCheckConfig.create_default()` (`src/sbom_check/config/models.py`). Where no current rule
or config field exists, that is stated explicitly rather than implied.

### Document metadata

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.document_name` | `missing_required_field` (`name`) | `SpdxDocument.name` | EQUIVALENT | ERROR | Direct 1:1 property. |
| `spdx3_completeness.document_identifier` | `missing_required_field` (`SPDXID`, `documentNamespace`), `invalid_field_value` (`SPDXID` exact value), `invalid_uri_scheme`, `prohibited_uri_fragment` | `SpdxDocument.spdxId` (IRI) | REPRESENTED_DIFFERENTLY | ERROR | 2.3 splits identity into a local `SPDXID` string plus a separate `documentNamespace` URI with its own scheme/fragment rules; 3.0.1 collapses both into a single `spdxId` IRI. The four 2.3 rule_ids above all fold into one IRI well-formedness check. |
| `spdx3_completeness.creation_timestamp` | `missing_required_field` / `invalid_field_value` (`creationInfo.created`, ISO-8601 UTC pattern) | `CreationInfo.created` | EQUIVALENT | ERROR | Same property, same intent, still on a `CreationInfo` element rather than nested document JSON, but the lookup is a direct field read. |
| `spdx3_completeness.creators` | `missing_required_field` (`creationInfo.creators`) | `CreationInfo.createdBy` referencing `Agent`/`Organization` graph elements | REPRESENTED_DIFFERENTLY | ERROR | 2.3 stores creators as strings (`"Tool: X"`, `"Organization: Y"`) inline; 3.0.1 requires real `Agent`/`Organization` elements linked via `createdBy`, so the check becomes "does `createdBy` resolve to at least one such element" rather than a string-count check. |
| `spdx3_completeness.spec_version` | `invalid_field_value` (`spdxVersion` exact value `SPDX-2.3`) | `CreationInfo.specVersion` | REPRESENTED_DIFFERENTLY | ERROR | Same intent (pin the spec version), but 3.0.1 has no top-level `spdxVersion` field; the value lives on `CreationInfo.specVersion` and the expected exact value becomes `3.0.1`. |
| `spdx3_completeness.data_license` | `invalid_field_value` (`dataLicense` exact value `CC0-1.0`) | `dataLicense` on `SpdxDocument` (`Core/dataLicense`, range `SimpleLicensing/AnyLicenseInfo`, `sh:maxCount 1`, IRI-valued) | REPRESENTED_DIFFERENTLY | ERROR | Verified against `spdx-model.ttl`: `dataLicense` **does** exist in 3.0.1 on `SpdxDocument`. The difference is shape, not existence: 2.3 compares a literal string to `CC0-1.0`, whereas 3.0.1 requires an IRI reference to an `AnyLicenseInfo` element, so the check must resolve the referenced license element rather than string-compare. Note it is optional in 3.0.1 (`maxCount 1`, no `minCount`), unlike 2.3 where it is mandatory. |
| `spdx3_completeness.license_list_version` | `missing_required_field` (`creationInfo.licenseListVersion`) | `simplelicensing_licenseListVersion` on each `simplelicensing_LicenseExpression` element (`SimpleLicensing/licenseListVersion`, `xsd:string`, `sh:maxCount 1`, semver-patterned) | REPRESENTED_DIFFERENTLY | WARNING | Verified against `spdx-model.ttl`: the property is declared on the **`LicenseExpression`** shape, not on `CreationInfo`. In 2.3 the licence-list version is document-level creation metadata; in 3.0.1 it is per-licence-expression and optional, so there is no single document-wide value to require. The check therefore applies per `LicenseExpression` element. Proposed advisory for that reason — see Open Question 6. |

### Package & component metadata

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.package_name` | `missing_package_field` (`name`) | `software_Package.name` | EQUIVALENT | ERROR | Direct mapping. |
| `spdx3_completeness.package_homepage` | `missing_package_field` (`homepage`) | `software_homePage` | EQUIVALENT | WARNING | Direct mapping; proposed as advisory — see Section 7. |

### Supplier & originator

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.package_supplier` | `missing_package_field` (`supplier`) | `suppliedBy` property on the `Artifact` (which `software_Package` subclasses) — `Core/suppliedBy`, an `owl:ObjectProperty` with `rdfs:range Core/Agent`, `sh:maxCount 1` | REPRESENTED_DIFFERENTLY | ERROR | Verified against `spdx-model.ttl`: `suppliedBy` is a **direct property on `Artifact`**, NOT a `RelationshipType`. It is absent from the `RelationshipType` enumeration. The check must therefore read the `suppliedBy` property on the package element and resolve the referenced `Agent` IRI — it must not scan for a `Relationship` element. 2.3 by contrast stores supplier as an inline string. |
| `spdx3_completeness.package_originator` | None today — `originator` is not in `PackageRequirementsConfig.required_fields` in `create_default()`, so no 2.3 rule currently enforces it. | `originatedBy` property on the `Artifact` — `Core/originatedBy`, an `owl:ObjectProperty` with `rdfs:range Core/Agent` (no `maxCount`, so repeatable) | NEEDS_DECISION | n/a (disabled) | Verified: like `suppliedBy`, `originatedBy` is a **direct `Artifact` property, not a `RelationshipType`**. The structural mapping is therefore settled; what is undecided is policy. Qualcomm has never required `originator` in 2.3 either, so requiring it for 3.0.1 would be a new requirement — see Open Question 2. |

### Version & source location

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.package_version` | `missing_package_field` (`versionInfo`) | `software_packageVersion` | EQUIVALENT | ERROR | Direct mapping, namespaced property name. |
| `spdx3_completeness.package_download_location` | `missing_package_field` (`downloadLocation`) | `software_downloadLocation` | EQUIVALENT | ERROR | Direct mapping, namespaced property name. |

### Licensing & copyright

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.license_concluded` | `missing_package_field` (`licenseConcluded`) | `Relationship` element with `relationshipType: hasConcludedLicense` from the package to a `simplelicensing_LicenseExpression` (or other `AnyLicenseInfo`) element | REPRESENTED_DIFFERENTLY | ERROR | Verified: `hasConcludedLicense` is a genuine member of the `Core/RelationshipType` enumeration in `spdx-model.ttl` (unlike `suppliedBy`). There is no scalar `licenseConcluded` property in 3.0.1, so the check is a graph traversal for a matching `Relationship` element whose `to` resolves to a licensing element. |
| `spdx3_completeness.license_declared` | `missing_package_field` (`licenseDeclared`) | `Relationship` element with `relationshipType: hasDeclaredLicense` | REPRESENTED_DIFFERENTLY | ERROR | Verified in the `Core/RelationshipType` enumeration. Same shape change and same traversal approach as concluded license. |
| `spdx3_completeness.copyright_text` | `missing_package_field` (`copyrightText`) | `software_copyrightText` | EQUIVALENT | WARNING | Stays a scalar property; direct mapping. |

### Identifiers

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.package_identifier` | `missing_package_field` (`SPDXID`) | `software_Package.spdxId` (IRI) | REPRESENTED_DIFFERENTLY | ERROR | Same identity concept, same IRI-collapse reasoning as the document identifier row. |
| `spdx3_completeness.package_purl` | `missing_external_ref` (`referenceType: purl`, config: `ExternalRefsConfig.required_types`) | **Two valid shapes, both verified to exist:** (a) the `software_packageUrl` property (`Software/packageUrl`, `xsd:anyURI`) directly on the package, or (b) an `externalIdentifier` → `ExternalIdentifier` element with `externalIdentifierType: packageUrl` | NEEDS_DECISION | n/a (disabled) | The ambiguity here is **policy, not fact**: both shapes are confirmed present in the 3.0.1 model, and a conforming document may use either. A supplier could satisfy one and not the other. Qualcomm must decide whether to accept either, require one specifically, or require both — see Open Question 5. Note the enum member is spelled `packageUrl`, not `purl`. |
| `spdx3_completeness.package_cpe` | `missing_external_ref` is the rule_id family; CPE itself is only in `ExternalRefsConfig.conditional_types` (`reference_type: cpe23Type`, `required_when: official_cpe_exists`), not currently wired to an enforced rule_id | `externalIdentifier` → `ExternalIdentifier` element with `externalIdentifierType: cpe23` (verified; `cpe22` also exists as a separate member) | CONDITIONAL | WARNING | Already conditional in 2.3 config (only required when an official CPE exists); the same conditionality should carry over rather than becoming unconditional. See Open Question 3. |

### Build tools & generated components

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.build_tools_coverage` | `missing_build_tools` (name-substring heuristic against `BuildToolsConfig.examples`) | No direct equivalent; build tooling would appear as ordinary `software_Package` elements connected via `generates`/build-related `Relationship` types | NEEDS_DECISION | n/a (disabled) | The 2.3 rule is already a weak heuristic (substring match on package names), not a structural check. For 3.0.1 we could require an explicit generation relationship instead of guessing from names, but that is a policy change, not a mechanical port, and needs a decision. |

### Relationships

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.document_describes` | `missing_describes_relationship` | `Relationship` element with `relationshipType: describes` from the `SpdxDocument`, and/or the `rootElement` property on `SpdxDocument` | REPRESENTED_DIFFERENTLY | ERROR | 2.3 looks for a `DESCRIBES` entry in the flat `relationships[]` array; 3.0.1 has no flat array, so this becomes a graph traversal for a matching `Relationship` element (or a `rootElement` check). |
| `spdx3_completeness.files_analyzed_true` | `files_analyzed_missing_field` (`FilesAnalyzedRule.when_true_requires`) | — | NOT_APPLICABLE | n/a | `filesAnalyzed` is a 2.3-specific boolean construct describing whether file-level analysis was performed. 3.0.1 has no `filesAnalyzed` property; file completeness is instead a question of whether `software_File` elements and `contains`-type relationships are present at all, which is a different question, not a renamed one. |
| `spdx3_completeness.files_analyzed_false` | `files_analyzed_prohibited_field` (`FilesAnalyzedRule.when_false_prohibits`) | — | NOT_APPLICABLE | n/a | Same reasoning as above — there is no `filesAnalyzed: false` state to prohibit fields against in 3.0.1. |
| `spdx3_completeness.package_verification_code` | None today — `packageVerificationCode` has no rule_id in `engine.py` and no field in `SbomCheckConfig`. | `verifiedUsing` → a `PackageVerificationCode` element (`Core/PackageVerificationCode`, `rdfs:subClassOf Core/IntegrityMethod`, carrying `hashValue`, `algorithm`, and `packageVerificationCodeExcludedFile`) | REPRESENTED_DIFFERENTLY | WARNING | Verified against `spdx-model.ttl`: the concept **is retained** in 3.0.1, as a class the spec itself annotates "An SPDX version 2.X compatible verification method for software packages." It is no longer a scalar field on the package but an `IntegrityMethod` element reached via `verifiedUsing`. Proposed advisory because no 2.3 rule enforces it today, so requiring it would be a new requirement rather than a port. |
| `spdx3_completeness.dependency_relationships` | No enforced rule today — `RelationshipRequirementsConfig.required_relationships` exists as a config shape but `create_default()` leaves it empty, so no `CONTAINS`/`DEPENDS_ON` requirement is enforced in the shipped default profile. | `Relationship` elements with `relationshipType: contains` / `dependsOn` | REPRESENTED_DIFFERENTLY | WARNING | The structural mapping (flat relationship entries → `Relationship` elements) is clear. What is not yet decided is whether to start enforcing dependency-relationship completeness by default when 2.3 never did — flagged for owner awareness, not because the mapping itself is in doubt. |
| `spdx3_completeness.no_isolated_elements` | `RelationshipRequirementsConfig.no_isolated_elements` (today only partially enforced via the `missing_describes_relationship` check; a full isolated-element graph walk is not implemented in `engine.py`) | Every graph element must be reachable from the `SpdxDocument` via some `Relationship` chain (or listed under `rootElement`) | REPRESENTED_DIFFERENTLY | WARNING | Same policy intent as 2.3, but a full implementation requires walking the `@graph` relationship edges rather than scanning one flat array. |

### Vulnerability & provenance

| Proposed rule ID | SPDX 2.3 source (rule_id / config field) | SPDX 3.0.1 mapping | Status | Proposed severity | Notes |
|---|---|---|---|---|---|
| `spdx3_completeness.vulnerability_info` | None today — no rule_id, no config field; SBOM-Check does not check vulnerability data in either SPDX version currently. | SPDX 3.0.1 Security Profile (`security_Vulnerability` elements and VEX-style assessment relationships) | NEEDS_DECISION | n/a (disabled) | This would be a wholly new completeness requirement, not a port of an existing one. Needs an explicit Qualcomm decision on whether vulnerability/VEX linkage is in scope for this profile at all. |
| `spdx3_completeness.provenance_info` | None today — no rule_id, no config field. | Build/generation provenance via `Agent`/tool elements and `generatedBy`-style relationships in the 3.0.1 Build Profile | NEEDS_DECISION | n/a (disabled) | Same situation as vulnerability info: new ground, not a migration of an existing 2.3 rule. Needs a scoping decision before any rule is drafted. |

**Row count: 28.** Status counts: EQUIVALENT = 7, REPRESENTED_DIFFERENTLY = 13, CONDITIONAL = 1,
NOT_APPLICABLE = 2, NEEDS_DECISION = 5.

---

## 5. Rules with no SPDX 3.0.1 equivalent

Each of these has a stated behavior — none are left ambiguous:

| Rule | Behavior |
|---|---|
| `files_analyzed_missing_field` / `files_analyzed_true` requirement | Not applicable to SPDX 3.0.1. `filesAnalyzed` does not exist as a concept; no replacement check is substituted. |
| `files_analyzed_prohibited_field` / `files_analyzed_false` requirement | Not applicable to SPDX 3.0.1, for the same reason. |

---

## 6. Severity rationale

Severity is a policy choice about who is blocked, not a reflection of how hard a rule was to
implement. The proposed split:

- **ERROR (blocking):** the rule protects information a downstream supplier or Qualcomm
  consumer cannot meaningfully operate without — identity (document/package identifiers),
  provenance of the document itself (creators, creation timestamp, spec version), what the
  package is and where it came from (name, version, download location, supplier), and license
  obligations (concluded/declared license). Failing these means the SBOM cannot be trusted or
  consumed at all, matching how these are already enforced as hard failures in the 2.3 default
  profile today.
- **WARNING (advisory):** the rule adds useful context but a consumer can still make a
  reasonable decision without it — homepage, copyright text, CPE (already conditional in 2.3),
  dependency-relationship completeness, and isolated-element detection. These degrade quality
  but do not by themselves block consumption.
- **n/a / disabled (`NEEDS_DECISION` rows):** no severity is proposed because the rule itself
  is not yet approved for implementation. Assigning a severity to an unapproved rule would
  imply a policy decision this document is not authorized to make.

This is a proposed split, not a decided one — see Open Question 1 below for the specific
default-profile question.

---

## 7. Open questions for the Qualcomm SBOM owners

1. Should SPDX 3.0.1 completeness be enabled by default in the `default` profile? **The
   current proposal is YES, default-on.** This is a behavior change for any existing SPDX 3
   users of sbom-check today, who currently receive no completeness checking beyond core
   schema/semantic validation. Do you approve default-on, or should 3.0.1 completeness ship
   opt-in only (e.g. via a separate `spdx3-default` profile) until adoption data exists?
2. Is `originator` required when `supplier` is present, mirroring (or diverging from) the
   current 2.3 policy of not requiring `originator` at all? Yes/no, and if yes, under what
   condition.
3. Does CPE remain conditional (required only when an official CPE identifier exists, as in
   2.3 today), or should Qualcomm's 3.0.1 profile make CPE unconditionally required for some
   package category? Yes/no, and if conditional, what is the exact condition.
4. Until a `NEEDS_DECISION` row is resolved, how should SBOM-Check behave? Specifically:
   should the engine (a) skip the check entirely and say nothing, (b) emit an explicit `info`
   -severity message stating the rule is pending a Qualcomm decision so it is visible but
   non-blocking, or (c) something else? A document must never be reported "complete"
   while a `NEEDS_DECISION` row is silently skipped — which of these satisfies that
   for you?
5. For `spdx3_completeness.package_purl`, should validation target the `software_packageUrl`
   property, an `ExternalIdentifier` element with `externalIdentifierType: purl`, or both?
6. For `spdx3_completeness.license_list_version`, is tracking the SPDX license-list version a
   requirement Qualcomm wants carried into SPDX 3.0.1 at all, and if so, where in the 3.0.1
   model should it be recorded?
7. Are vulnerability/VEX information (`spdx3_completeness.vulnerability_info`) and build
   provenance (`spdx3_completeness.provenance_info`) in scope for this completeness profile,
   or should they be deferred to a separate profile entirely?

---

## 8. Approval record

| Name | Role | Date | Decision |
|---|---|---|---|
| | | | |
| | | | |
| | | | |
