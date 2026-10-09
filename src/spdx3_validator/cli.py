# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Command-line interface for SPDX 3.0.1 SBOM validation."""

import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click

from sbom_validator.cli_utils import collect_spdx_files, output_text_multiple
from spdx3_validator.engine import ValidationEngine
from spdx3_validator.models import (
    REMOTE_RESOURCE_UNAVAILABLE_RULE_ID,
    ValidationResult,
    ValidationSeverity,
)

REMOTE_RESOURCE_FAILURE_EXIT_CODE = 4


def _has_remote_resource_failure(result: ValidationResult) -> bool:
    """Return whether validation could not run because a remote resource failed."""
    return any(
        message.rule_id == REMOTE_RESOURCE_UNAVAILABLE_RULE_ID
        for message in result.messages
    )



def validate_single_file(
    file_path: Path,
) -> tuple[Path, ValidationResult]:
    """Validate a single SPDX 3.0.1 file."""
    engine = ValidationEngine()
    result = engine.validate_file(file_path=file_path)
    return file_path, result


def output_text(result: Any, file_path: Path) -> None:
    """Output validation results in human-readable text format."""
    click.echo(f"Validating: {file_path}")

    # Color-coded validation status
    if result.is_valid:
        status_text = click.style("Valid: True ✅", fg="green", bold=True)
    else:
        status_text = click.style("Valid: False ❌", fg="red", bold=True)
    click.echo(status_text)

    if result.messages:
        click.echo("\nValidation Messages:")
        click.echo("-" * 50)

        for msg in result.messages:
            severity_color = {
                ValidationSeverity.ERROR: "red",
                ValidationSeverity.WARNING: "yellow",
                ValidationSeverity.INFO: "blue",
            }.get(msg.severity, "white")

            click.echo(
                f"[{click.style(msg.severity.value.upper(), fg=severity_color)}] "
                f"{msg.message}"
            )

            if msg.field_path:
                click.echo(f"  Field: {msg.field_path}")

            if msg.json_path:
                click.echo(f"  JSON path: {msg.json_path}")

            if msg.affected_element:
                click.echo(f"  Affected element: {msg.affected_element}")

            if msg.found_value is not None:
                click.echo(f"  Found: {msg.found_value}")

            if msg.expected_value is not None:
                click.echo(f"  Expected: {msg.expected_value}")

            if msg.rule_id:
                click.echo(f"  Rule: {msg.rule_id}")

            if msg.remediation:
                click.echo(f"  Remediation: {msg.remediation}")

            click.echo()

    # Summary
    error_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    )
    warning_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.WARNING
    )

    click.echo(f"Summary: {error_count} errors, {warning_count} warnings")


def output_json_multiple(results: list[tuple[Path, ValidationResult]]) -> None:
    """Output validation results for multiple files in JSON format."""
    output_data = {
        "summary": {
            "total_files": len(results),
            "valid_files": sum(1 for _, result in results if result.is_valid),
            "invalid_files": sum(1 for _, result in results if not result.is_valid),
        },
        "results": [
            {
                "file": str(file_path),
                "is_valid": result.is_valid,
                "schema_valid": result.schema_valid,
                "semantic_valid": result.semantic_valid,
                "messages": [
                    {
                        "severity": message.severity.value,
                        "message": message.message,
                        "rule_id": message.rule_id,
                        "field_path": message.field_path,
                        "json_path": message.json_path,
                        "affected_element": message.affected_element,
                        "section_reference": message.section_reference,
                        "found_value": message.found_value,
                        "expected_value": message.expected_value,
                        "remediation": message.remediation,
                    }
                    for message in result.messages
                ],
            }
            for file_path, result in results
        ],
    }

    click.echo(json.dumps(output_data, indent=2))



@click.command()
@click.argument(
    "paths",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for validation results",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan directories for SPDX files",
)
@click.option(
    "--pattern",
    default="*.spdx.json",
    help="File pattern to match when scanning directories (default: *.spdx.json)",
)
@click.option(
    "--jobs",
    "-j",
    type=click.IntRange(min=1),
    default=None,
    help="Number of parallel jobs for validation (default: number of CPU cores)",
)
def main(
    paths: tuple[Path, ...],
    output_format: str,
    recursive: bool,
    pattern: str,
    jobs: int | None,
) -> None:
    """Validate SPDX 3.0.1 JSON-LD format documents."""

    if not (files_to_validate := collect_spdx_files(paths, recursive, pattern)):
        click.echo("No SPDX files found to validate.", err=True)
        sys.exit(1)

    overall_valid = True
    remote_resource_failure = False
    results = []

    if len(files_to_validate) == 1:
        # Single file - no need for parallel processing
        file_path = files_to_validate[0]
        _, result = validate_single_file(file_path)
        results.append((file_path, result))
        if not result.is_valid:
            overall_valid = False
        remote_resource_failure = _has_remote_resource_failure(result)
    else:
        # Multiple files - use parallel processing
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            # Submit all validation tasks
            future_to_file = {
                executor.submit(validate_single_file, file_path): file_path
                for file_path in files_to_validate
            }

            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path, result = future.result()
                results.append((file_path, result))
                if not result.is_valid:
                    overall_valid = False
                if _has_remote_resource_failure(result):
                    remote_resource_failure = True

        # Sort results by file path for consistent output
        results.sort(key=lambda x: x[0])

    # Output results
    if output_format == "json":
        output_json_multiple(results)
    else:
        output_text_multiple(results, output_text)

    # A remote-resource failure means validation was incomplete. Give it a
    # distinct status, including when a batch also contains invalid documents.
    if remote_resource_failure:
        sys.exit(REMOTE_RESOURCE_FAILURE_EXIT_CODE)
    sys.exit(0 if overall_valid else 1)
