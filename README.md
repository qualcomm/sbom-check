Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.  
SPDX-License-Identifier: BSD-3-Clause

# SBOM-Check

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green.svg)](LICENSE)

A multi-format SBOM validator supporting SPDX 2.3 and CycloneDX JSON documents. SPDX documents receive configurable completeness requirements; CycloneDX documents currently receive structural schema validation.

## Features

- **Multi-format validation**: Automatic detection and validation of SPDX 2.3 and CycloneDX JSON 1.3–1.7 documents
- **CLI Tools**: Both `sbom-check`, `spdx-validate`, and `cyclonedx-validate` commands available
- **Configurable Requirements**: YAML-based configuration system with inheritance
- **Multiple Profiles**: Built-in profiles for different use cases (basic, default, automotive, etc.)
- **Rich Reporting**: Text and JSON output formats with detailed error messages
- **Schema Validation**: JSON Schema validation against the declared document format and version
- **Extensible**: Plugin system for custom validation rules

## Quick Start

### Installation

Clone the repository:
```bash
git clone <repository-url>
```

Navigate to the project directory:
```bash
cd sbom-check
```

**Option 1: Use uv run (recommended - no installation needed)**

uv run automatically syncs dependencies and runs commands:
```bash
uv run sbom-check --help
```

**Option 2: Install dependencies first, then run**

Install with dev dependencies:
```bash
uv sync
```

Or install production dependencies only:
```bash
uv sync --no-dev
```

**Option 3: Traditional pip installation**
```bash
pip install -e .
```

**Note:** All examples in this documentation use `uv run` commands. If you installed via pip, simply omit the `uv run` prefix (e.g., use `sbom-check --help` instead of `uv run sbom-check --help`).

### Basic Usage

SBOM-Check: Comprehensive validation with configurable requirements
```bash
uv run sbom-check my-sbom.spdx.json
```

SPDX-Validate: Core SPDX 2.3 specification validation
```bash
uv run spdx-validate my-sbom.spdx.json
```

Validate multiple files:
```bash
uv run sbom-check file1.spdx.json file2.spdx.json file3.spdx.json
```

Validate directory of SBOM files:
```bash
uv run sbom-check sbom-directory/
```

JSON output for CI/CD:
```bash
uv run sbom-check --output-format json my-sbom.spdx.json
```

```bash
uv run spdx-validate --output-format json my-sbom.spdx.json
```

## CycloneDX JSON Validation

Validate a CycloneDX JSON document with the same command used for SPDX documents:

```bash
uv run sbom-check supplier-bom.cdx.json
```

SBOM-Check supports CycloneDX JSON versions 1.3, 1.4, 1.5, 1.6, and 1.7. The document's `specVersion` selects the corresponding schema bundled with `cyclonedx-python-lib`; validation does not require network access. JSON Schema validation rejects additional properties as schema errors. These violations make the document invalid (`core_valid: false` and `overall_valid: false`). CycloneDX XML is not supported.

CycloneDX validation is currently limited to structural JSON Schema validation. SPDX-specific Qualcomm completeness and profile checks are not applied to CycloneDX documents. Results therefore report `profile_status: "not_applicable"`, with `core_valid` indicating schema status. CycloneDX semantic, completeness, and business validation are planned separately.

Example JSON result:

```json
{
  "document_format": "CycloneDX",
  "spec_version": "1.7",
  "overall_valid": true,
  "core_valid": true,
  "profile_status": "not_applicable",
  "spdx_valid": null,
  "profile_valid": null
}
```


## Configuration Profiles

### Basic SPDX Profile
- Minimal SPDX 2.3 compliance validation only
- Uses spdx-validator with no additional requirements
- Suitable for basic compliance checking

### Default Profile
- Comprehensive requirements based on enterprise SBOM standards
- Includes build tools validation
- Enforces completeness and quality standards
- Document namespace validation
- External references requirements (PURL, CPE)
- Files analyzed business logic validation

## Configuration System

SBOM-Check uses YAML configuration files to define validation requirements:

```yaml
metadata:
  name: "My Custom Requirements"
  version: "1.0"
  description: "Custom SBOM validation requirements"

spdx_validation:
  enable_schema_validation: true
  enable_semantic_validation: true
  require_zero_validation_errors: true

document_requirements:
  required_fields:
    - spdxVersion
    - dataLicense
    - SPDXID
    - name
    - documentNamespace
  
  field_validation:
    spdxVersion:
      exact_value: "SPDX-2.3"
    documentNamespace:
      require_https_scheme: true
      prohibit_fragment: true

package_requirements:
  build_tools:
    require_build_tools: true
    examples: ["GCC", "Clang", "Maven", "CMake"]
  
  external_refs:
    required_types:
      - reference_type: "purl"
        reference_category: "PACKAGE-MANAGER"
        description: "Required for ALL packages"
```


## Integrated SPDX Validator

SBOM-Check includes an integrated spdx-validator library that provides:

- **Core SPDX 2.3 Validation**: JSON Schema validation against official SPDX specification
- **Standalone CLI**: `spdx-validate` command for direct SPDX validation
- **Standalone CycloneDX CLI**: `cyclonedx-validate` command for direct CycloneDX JSON schema validation
- **Library Integration**: Used internally by SBOM-Check for base validation
- **Unified Results**: Combined validation results with detailed error reporting


## Exit Codes

- **0**: All validations passed
- **1**: Validation errors found
- **2**: Configuration or input file errors
- **3**: Internal application errors

## Examples

### Using Profiles

Use basic SPDX profile (minimal validation):
```bash
uv run sbom-check --profile basic_spdx my-sbom.spdx.json
```

List available profiles:
```bash
uv run sbom-check --list-profiles
```

### Custom Configuration

Generate configuration template:
```bash
uv run sbom-check --generate-config --profile default > company-requirements.yaml
```

Edit the configuration file to match your requirements, then use it for validation:
```bash
uv run sbom-check --config company-requirements.yaml my-sbom.spdx.json
```

### Directory Traversal and Multiple Files

Validate multiple individual files:
```bash
uv run sbom-check file1.spdx.json file2.spdx.json file3.spdx.json
```

Validate all SBOM files in a directory:
```bash
uv run sbom-check sbom-directory/
```

Recursively scan directories for SBOM files:
```bash
uv run sbom-check --recursive project-root/
```

Directory scans default to `*.{spdx,cdx}.json` so unrelated JSON files are ignored. Use `--pattern` to select a different file pattern when needed.

Use custom file pattern:
```bash
uv run sbom-check --pattern "*.json" --recursive project/
```

Mix files and directories:
```bash
uv run sbom-check main.spdx.json deps/ libs/external.spdx.json
```

Parallel processing for large numbers of files:
```bash
uv run sbom-check --jobs 8 --recursive large-project/
```

### Advanced SPDX Validation

Schema validation only:
```bash
uv run spdx-validate --schema-only my-sbom.spdx.json
```

Semantic constraint validation only:
```bash
uv run spdx-validate --semantic-only my-sbom.spdx.json
```

Validate multiple files in parallel:
```bash
uv run spdx-validate --recursive --jobs 4 ./sbom-directory/
```

Custom schema file:
```bash
uv run spdx-validate --schema-path custom-schema.json my-sbom.spdx.json
```

### CI/CD Integration

Run SBOM validation in your CI pipeline:
```bash
uv run sbom-check --output-format json --profile default *.spdx.json > validation-results.json
```

Check validation results and exit on failure:
```bash
if [ $? -ne 0 ]; then
  echo "SBOM validation failed"
  exit 1
fi
```


## CLI Tools

This project provides three complementary CLI tools:

### sbom-check
Comprehensive SBOM validation with configurable requirements and profiles.

```
Usage: sbom-check [OPTIONS] [PATHS]...

Options:
  --profile TEXT               Configuration profile to use (default: default)
  --config PATH                Custom configuration file to use
  --output-format [text|json]  Output format (default: text)
  -r, --recursive              Recursively scan directories for SBOM files
  --pattern TEXT               File pattern to match when scanning directories (default: *.{spdx,cdx}.json)
  -j, --jobs INTEGER           Number of parallel jobs for validation (default: number of CPU cores)
  --list-profiles              List available configuration profiles
  --generate-config            Generate a configuration template
  --validate-config PATH       Validate a configuration file
  --version                    Show the version and exit.
  --help                       Show this message and exit.
```

### cyclonedx-validate

Direct CycloneDX JSON schema validation for versions 1.3–1.7. Semantic and Qualcomm completeness validation are not performed.

```bash
uv run cyclonedx-validate --output-format json supplier-bom.cdx.json
```

### spdx-validate
Core SPDX 2.3 specification validation with schema and semantic constraint checking.

```
Usage: spdx-validate [OPTIONS] PATHS...

Options:
  --schema-only                Only perform JSON schema validation
  --semantic-only              Only perform semantic constraint validation
  --output-format [text|json]  Output format for validation results
  --schema-path PATH           Path to custom SPDX 2.3 JSON schema file
  -r, --recursive              Recursively scan directories for SPDX files
  --pattern TEXT               File pattern to match when scanning directories
  -j, --jobs INTEGER           Number of parallel jobs for validation
  --help                       Show this message and exit.
```

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Related Projects

- [SPDX Specification](https://spdx.github.io/spdx-spec/)

## License

This project is licensed under the BSD-3-Clause "New" or "Revised" License. See [LICENSE](LICENSE) for the full license text.
