# SPDX 3.0.1 test fixtures

Documents used to exercise the Qualcomm SPDX 3.0.1 completeness profile.
Each is a structurally well-formed SPDX 3.0.1 JSON-LD document, so a
profile failure here reflects a Qualcomm completeness requirement rather
than an SPDX specification violation.

| Fixture | Purpose |
|---|---|
| `complete.spdx.json` | Satisfies every implemented completeness rule. Profile validation must pass. |
| `incomplete-package.spdx.json` | Package carries only `name` and `creationInfo` — no version, download location, supplier, licence or identifier. |
| `missing-supplier.spdx.json` | Package states no `suppliedBy` at all. |
| `dangling-supplier.spdx.json` | Package states `suppliedBy`, but the referenced `Agent` element is absent from the graph. Distinct from stating no supplier. |
| `no-describes.spdx.json` | Document neither declares `rootElement` nor has a `describes` relationship, leaving the package unreachable. |

Property and relationship names follow the normative SPDX 3.0.1 model:
`suppliedBy` is a direct property on the package, while licence links are
`Relationship` elements using `hasConcludedLicense` / `hasDeclaredLicense`.
