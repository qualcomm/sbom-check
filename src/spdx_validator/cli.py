# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Command-line interface for SPDX validator."""

from __future__ import annotations

import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click

from spdx_validator.engine import ValidationEngine
from spdx_validator.models import ValidationResult, ValidationSeverity


def validate_single_file(
    file_path: Path,
    schema_path: Path | None,
    enable_schema: bool,
    enable_semantic: bool,
) -> tuple[Path, ValidationResult]:
    """Validate a single SPDX file. Used for parallel processing."""
    engine = ValidationEngine(
        schema_path=schema_path,
        enable_schema_validation=enable_schema,
        enable_semantic_validation=enable_semantic,
    )
    result = engine.validate_file(file_path)
    return file_path, result


def collect_spdx_files(
    paths: tuple[Path, ...], recursive: bool, pattern: str
) -> list[Path]:
    """Collect all SPDX files from the given paths."""
    files = []

    for path in paths:
        if path.is_file():
            files.append(path.resolve())
        elif path.is_dir():
            if recursive:
                files.extend(p.resolve() for p in path.rglob(pattern))
            else:
                files.extend(p.resolve() for p in path.glob(pattern))
        else:
            click.echo(f"Warning: {path} is neither a file nor directory", err=True)

    # Sort for consistent output
    return sorted(files)


def output_text_multiple(results: list[tuple[Path, ValidationResult]]) -> None:
    """Output validation results for multiple files in human-readable text format."""
    total_files = len(results)
    valid_files = sum(1 for _, result in results if result.is_valid)
    invalid_files = total_files - valid_files

    # Color-coded summary header
    valid_text = click.style(f"{valid_files} valid", fg="green", bold=True)
    invalid_text = click.style(f"{invalid_files} invalid", fg="red", bold=True)
    click.echo(f"Validated {total_files} files: {valid_text}, {invalid_text}")
    click.echo("=" * 80)

    for file_path, result in results:
        output_text(result, file_path)
        if result != results[-1][1]:  # Not the last result
            click.echo()

    # Color-coded overall summary
    click.echo("=" * 80)
    if valid_files == total_files:
        summary_color = "green"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ✅"
    elif valid_files == 0:
        summary_color = "red"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ❌"
    else:
        summary_color = "yellow"
        summary_text = f"Overall: {valid_files}/{total_files} files valid ⚠️"

    click.echo(click.style(summary_text, fg=summary_color, bold=True))


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
                        "severity": msg.severity.value,
                        "message": msg.message,
                        "path": msg.path,
                        "element_id": msg.element_id,
                        "rule_id": msg.rule_id,
                    }
                    for msg in result.messages
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
@click.option("--schema-only", is_flag=True, help="Only perform JSON schema validation")
@click.option(
    "--semantic-only", is_flag=True, help="Only perform semantic constraint validation"
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format for validation results",
)
@click.option(
    "--schema-path",
    type=click.Path(exists=True, path_type=Path),  # type: ignore[type-var]
    help="Path to custom SPDX 2.3 JSON schema file",
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
    type=int,
    default=None,
    help="Number of parallel jobs for validation (default: number of CPU cores)",
)
def main(  # pylint: disable=too-many-positional-arguments,too-many-locals  # noqa: PLR0917
    paths: tuple[Path, ...],
    schema_only: bool,
    semantic_only: bool,
    output_format: str,
    schema_path: Path | None,
    recursive: bool,
    pattern: str,
    jobs: int | None,
) -> None:
    """Validate SPDX 2.3 JSON documents against specification.

    PATHS can be individual files or directories. When directories are provided,
    they will be scanned for SPDX files matching the specified pattern.
    """

    # Determine validation modes
    enable_schema = not semantic_only
    enable_semantic = not schema_only

    # Create validation engine
    engine = ValidationEngine(
        schema_path=schema_path,
        enable_schema_validation=enable_schema,
        enable_semantic_validation=enable_semantic,
    )

    # Collect all files to validate
    if not (files_to_validate := collect_spdx_files(paths, recursive, pattern)):
        click.echo("No SPDX files found to validate.", err=True)
        sys.exit(1)

    # Validate all files (in parallel if multiple files)
    results = []
    overall_valid = True

    if len(files_to_validate) == 1:
        # Single file - no need for parallel processing
        file_path = files_to_validate[0]
        result = engine.validate_file(file_path)
        results.append((file_path, result))
        if not result.is_valid:
            overall_valid = False
    else:
        # Multiple files - use parallel processing
        with ProcessPoolExecutor(max_workers=jobs) as executor:
            # Submit all validation tasks
            future_to_file = {
                executor.submit(
                    validate_single_file,
                    file_path,
                    schema_path,
                    enable_schema,
                    enable_semantic,
                ): file_path
                for file_path in files_to_validate
            }

            # Collect results as they complete
            for future in as_completed(future_to_file):
                file_path, result = future.result()
                results.append((file_path, result))
                if not result.is_valid:
                    overall_valid = False

        # Sort results by file path for consistent output
        results.sort(key=lambda x: x[0])

    # Output results
    if output_format == "json":
        output_json_multiple(results)
    else:
        output_text_multiple(results)

    # Exit with appropriate code
    sys.exit(0 if overall_valid else 1)


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

            if msg.path:
                click.echo(f"  Path: {msg.path}")

            if msg.element_id:
                click.echo(f"  Element: {msg.element_id}")

            if msg.rule_id:
                click.echo(f"  Rule: {msg.rule_id}")

            click.echo()

    # Summary
    error_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.ERROR
    )
    warning_count = sum(
        1 for msg in result.messages if msg.severity == ValidationSeverity.WARNING
    )

    click.echo(f"Summary: {error_count} errors, {warning_count} warnings")


def output_json(result: Any) -> None:
    """Output validation results in JSON format."""
    output_data = {
        "is_valid": result.is_valid,
        "schema_valid": result.schema_valid,
        "semantic_valid": result.semantic_valid,
        "messages": [
            {
                "severity": msg.severity.value,
                "message": msg.message,
                "path": msg.path,
                "element_id": msg.element_id,
                "rule_id": msg.rule_id,
            }
            for msg in result.messages
        ],
    }

    click.echo(json.dumps(output_data, indent=2))


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
