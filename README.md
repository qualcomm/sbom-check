Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.  
SPDX-License-Identifier: BSD-3-Clause

# SBOM-Check

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-green.svg)](LICENSE)

A multi-format SBOM validator supporting SPDX 2.3 and SPDX 3.0.1 JSON documents. SPDX 2.3 documents support configurable additional requirements for completeness validation.

## Features

- **Multi-format validation**: Automatic detection and validation of SPDX 2.3 and SPDX 3.0.1 documents
- **CLI Tools**: `sbom-check`, `spdx-validate`, and `sbom-spdx3-validate` commands available
- **Configurable Requirements**: YAML-based configuration system with inheritance
- **Multiple Profiles**: Built-in profiles for different use cases (basic, default, automotive, etc.)
- **Rich Reporting**: Text and JSON output formats with detailed error messages
- **Schema Validation**: JSON Schema validation against the declared document format and version
- **Extensible**: Plugin system for custom validation rules

## SPDX 3.0.1 validation scope

SPDX 3.0.1 documents receive core SPDX validation only. This includes the
SPDX 3.0.1 schema and semantic SHACL validation provided by the SPDX 3
validator.

When using the combined `sbom-check` result, `profile_status` describes the
profile portion of validation:

- `passed`: the applicable profile completed without profile errors.
- `failed`: the applicable profile ran and reported profile errors.
- `not_applicable`: no profile was run. This is the expected value for SPDX
  3.0.1 documents.

`profile_status` is independent of the core SPDX result. For the combined
`SbomCheckResult`, use `overall_valid`, `core_valid`, `summary`, and the
validation messages to assess validation. `document_format` and `spec_version`
identify which core validator was used. A `not_applicable` profile status is
not itself a profile failure.

### Operational notes

- Validation requires outbound access to SPDX-hosted contexts, schemas, and SHACL resources.
- Resource failures return an error with rule ID
  `remote_resource_unavailable`. They set `is_valid` to `false`, but leave
  `schema_valid` and `semantic_valid` as `null` because those checks were not
  evaluated. They are not SBOM content or semantic failures.
- Each input file is validated independently; merged or cross-document validation is not supported.

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

SPDX 3.0.1 validation with batch processing:
```bash
uv run sbom-spdx3-validate my-sbom.spdx.json
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
- **Library Integration**: Used internally by SBOM-Check for base validation
- **Unified Results**: Combined validation results with detailed error reporting


## Exit Codes

- **0**: All validations passed
- **1**: Validation errors found
- **2**: Configuration or input file errors
- **3**: Internal application errors
- **4**: Validation could not run because a required remote SPDX resource was unavailable

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
  --pattern TEXT               File pattern to match when scanning directories (default: *.spdx.json)
  -j, --jobs INTEGER           Number of parallel jobs for validation (default: number of CPU cores)
  --list-profiles              List available configuration profiles
  --generate-config            Generate a configuration template
  --validate-config PATH       Validate a configuration file
  --version                    Show the version and exit.
  --help                       Show this message and exit.
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

### sbom-spdx3-validate
Project CLI for SPDX 3.0.1 validation. It adds recursive file discovery, batch
processing, parallel jobs, normalized text or JSON output, and project-specific
diagnostics, including parsing upstream SHACL errors into more human-readable
messages, around the upstream SPDX 3 validator.

```
Usage: sbom-spdx3-validate [OPTIONS] PATHS...

Options:
  --output-format [text|json]  Output format for validation results
  -r, --recursive              Recursively scan directories for SPDX files
  --pattern TEXT               File pattern to match when scanning directories
  -j, --jobs INTEGER           Number of parallel jobs for validation
  --help                       Show this message and exit.
```

The `spdx3-validate` command is provided by the upstream `spdx3-validate`
dependency. It offers the dependency's native single-document interface,
including URL or standard-input support and SPDX version selection. Use
`sbom-spdx3-validate` when you need this project's batch-oriented CLI and
output format.

## Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Related Projects

- [SPDX Specification](https://spdx.github.io/spdx-spec/)

## License

This project is licensed under the BSD-3-Clause "New" or "Revised" License. See [LICENSE](LICENSE) for the full license text.
