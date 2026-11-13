# Migration notes — SPDX 3.0.1 completeness profile

For maintainers of custom SBOM-Check configuration files. Covers what
changes when SPDX 3.0.1 completeness validation lands, and what you need to
do about it.

Requirements matrix:
[`spdx3-completeness-matrix.md`](spdx3-completeness-matrix.md).

## Summary

| If you… | You need to… |
|---|---|
| Validate only SPDX 2.3 documents | Nothing. Results are unchanged. |
| Have a custom config file | Nothing required. Existing files keep loading, including the legacy boolean `completeness_checks` shape. |
| Validate SPDX 3.0.1 documents with `--profile default` | Expect new completeness failures. See [Behaviour change](#behaviour-change). |
| Parse the JSON output | Two new fields (`rule_coverage`, and new `profile_status` values) and one bug fix. See [Output changes](#output-changes). |
| Use `--profile basic_spdx` | Nothing. It remains core-specification-only. |

## SPDX 2.3 is unchanged

Existing SPDX 2.3 profile rules keep their rule IDs, messages, and
severities. The new completeness rules are all scoped to
`spdx_versions: ["3.0.1"]`, so they never evaluate against a 2.3 document.

This was verified by diffing the CLI JSON output for the sample documents
before and after the change; the output is byte-identical.

## Behaviour change

**SPDX 3.0.1 documents validated with `--profile default` now report
completeness failures that previously went unchecked.** The default profile
enables all eighteen implemented rules — fourteen as errors, four as
warnings. A document that previously reported no profile findings may now
fail.

This was a deliberate decision, recorded in matrix Open Question 1: a
supplier submitting an SPDX 3.0.1 SBOM should be held to the same
completeness requirements as one submitting SPDX 2.3.

To opt out while you adjust, disable the rules in your own config:

```yaml
compliance_requirements:
  completeness_checks:
    spdx3_completeness.package_supplier:
      enabled: false
```

A disabled rule reports outcome `skipped` and does not block. To keep a rule
visible without blocking, downgrade it instead:

```yaml
compliance_requirements:
  completeness_checks:
    spdx3_completeness.copyright_text:
      severity: WARNING
```

## Configuration changes

### `completeness_checks` is now structured

`compliance_requirements.completeness_checks` was `dict[str, bool]` and read
by nothing. It is now a mapping of rule ID to a structured rule and is the
mechanism that drives completeness validation.

The legacy boolean form still loads and is coerced to `enabled`:

```yaml
# Still valid.
compliance_requirements:
  completeness_checks:
    require_package_identifier: true
```

Note that a legacy key only has an effect if it matches a real rule ID.
Keys such as `require_package_identifier` were never read before and are
still not read now, because no rule is registered under that name. They load
without error so your file keeps working; they do not silently become
active rules.

### Per-rule fields

| Field | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Whether the rule runs. Disabled rules report `skipped` and do not block. |
| `severity` | `ERROR` | `ERROR`, `WARNING`, or `INFO`. Overrides whatever the rule itself reports. |
| `spdx_versions` | `["2.3", "3.0.1"]` | Specification versions the rule applies to, as bare versions. |
| `description` | unset | Vendor-facing description of the requirement. |
| `remediation` | unset | Vendor-facing fix instruction, used when the rule does not supply one. |
| `supported` | `true` | Set `false` for a requirement with no approved mapping. Reports `unsupported` and **blocks**. |

### Merging keeps your overrides narrow

Overriding one rule leaves the rest at their defaults — the merge only
descends into keys present in both configurations. Overriding
`spdx3_completeness.package_supplier` does not drop the other seventeen
rules.

## Output changes

### `rule_coverage` is new

Results now carry one entry per completeness rule considered, so a consumer
can distinguish a rule that passed from one that never ran:

```json
{
  "rule_coverage": [
    {
      "rule_id": "spdx3_completeness.package_supplier",
      "outcome": "failed",
      "severity": "ERROR",
      "description": "Package must identify its supplier",
      "reason": null
    }
  ]
}
```

Outcomes: `passed`, `failed`, `skipped` (disabled by configuration),
`not_applicable` (does not apply to this specification version), and
`unsupported` (no approved mapping, or the rule could not be evaluated).

**Only `unsupported` blocks a document from being reported complete.** An
unevaluated required rule fails closed, because a document must never be
reported complete on the strength of a check that did not run.

### `profile_status` has two new values

`skipped` and `unsupported` join `passed`, `failed`, and `not_applicable`.
If you branch on this field, treat anything other than `passed` as "not
verified" rather than assuming `failed`. A profile that could not be
evaluated did not fail — it did not run.

### JSON output is now parseable

JSON output was printed through the console renderer, which word-wrapped
long string values and injected newlines inside JSON strings. Any
sufficiently long message produced output that `json.loads` rejected; this
is reproducible on `main` with the bundled `sample-invalid.spdx.json`. JSON
now goes to stdout verbatim.

If you worked around this by stripping newlines or using the text output,
you can stop.

### Saved configuration files reload

`save_to_file` serialised enum values as Python object tags that
`yaml.safe_load` refuses to read, so a saved configuration containing a
severity could not be loaded back. Configuration is now serialised in JSON
mode. Files saved by an earlier build that contain
`!!python/object/apply` tags must be regenerated.

## SPDX 3.0.1 core validation is still unavailable

Validating an SPDX 3.0.1 document against the SPDX 3.0.1 schema and SHACL
shapes is delivered separately. Until it lands, SPDX 3.0.1 documents report
`core_valid: false` with rule `spdx3_core_validation_unavailable`, and
`overall_valid` is therefore `false` regardless of profile outcome.

Profile validation still runs and reports independently, so completeness
findings are actionable now. To see profile results in isolation, read
`profile_status` and `rule_coverage` rather than `overall_valid`.

## Rules pending a Qualcomm decision

Matrix rows marked `NEEDS_DECISION` are not implemented and ship no
configuration entry. Most consequential is
`spdx3_completeness.package_purl`: SPDX 3.0.1 permits both a
`software_packageUrl` property and an `ExternalIdentifier` of type
`packageUrl`, and a conforming document may use either. Requiring one would
reject documents using the other, so the choice is left to the SBOM owners
(matrix Open Question 5).

If your organisation needs PURL enforcement before that is settled, add a
custom rule rather than assuming a shape.
