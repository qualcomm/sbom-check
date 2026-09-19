# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

# pylint: disable=broad-exception-caught
# pylint: disable=too-many-branches
# pylint: disable=too-many-positional-arguments

"""Command-line interface for SBOM-Check."""

from __future__ import annotations

import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import click
from rich.console import Console

from sbom_check.config.loader import ConfigLoader
from sbom_check.engine import SbomCheckEngine
from sbom_check.models import ValidationSeverity

try:
    from sbom_check._version import version as __version__
except ImportError:
    # Fallback for development/editable installs
    __version__ = "dev"

console = Console()


def collect_sbom_files(
    paths: tuple[Path, ...], recursive: bool, pattern: str
) -> list[Path]:
    """Collect all SBOM files from the given paths."""
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
            console.print(f"[yellow]Warning: {path} is neither a file nor directory[/yellow]")

    # Sort for consistent output
    return sorted(files)


def validate_single_file(
    file_path: Path,
    profile: str,
    config_path: str | None,
) -> tuple[Path, Any]:
    """Validate a single SBOM file. Used for parallel processing."""
    loader = ConfigLoader()

    # Load configuration
    if config_path:
        sbom_config = loader.load_with_profile(profile, config_path)
    else:
        sbom_config = loader.load_profile(profile)

    # Initialize engine and validate
    engine = SbomCheckEngine(sbom_config)
    result = engine.validate_file(file_path)
    return file_path, result


def output_text_multiple(results: list[tuple[Path, Any]]) -> None:
    """Output validation results for multiple files in human-readable text format."""
    total_files = len(results)
    valid_files = sum(1 for _, result in results if result.overall_valid)
    invalid_files = total_files - valid_files

    # Color-coded summary header
    console.print(f"Validated {total_files} files: [green]{valid_files} valid[/green], [red]{invalid_files} invalid[/red]")
    console.print("=" * 80)

    for file_path, result in results:
        _print_text_result(result, str(file_path))
        if result != results[-1][1]:  # Not the last result
            console.print()

    # Color-coded overall summary
    console.print("=" * 80)
    if valid_files == total_files:
        summary_text = f"[green]Overall: {valid_files}/{total_files} files valid ✅[/green]"
    elif valid_files == 0:
        summary_text = f"[red]Overall: {valid_files}/{total_files} files valid ❌[/red]"
    else:
        summary_text = f"[yellow]Overall: {valid_files}/{total_files} files valid ⚠️[/yellow]"

    console.print(summary_text)


def output_json_multiple(results: list[tuple[Path, Any]]) -> None:
    """Output validation results for multiple files in JSON format."""
    output_data = {
        "summary": {
            "total_files": len(results),
            "valid_files": sum(1 for _, result in results if result.overall_valid),
            "invalid_files": sum(1 for _, result in results if not result.overall_valid),
        },
        "results": [
            {
                "file": str(file_path),
                "overall_valid": result.overall_valid,
                "spdx_valid": result.spdx_valid,
                "profile_valid": result.profile_valid,
                "profile_name": result.profile_name,
                "summary": {
                    "errors": result.summary.errors,
                    "warnings": result.summary.warnings,
                    "info": result.summary.info,
                    "total_rules": result.summary.total_rules,
                    "passed_rules": result.summary.passed_rules,
                    "failed_rules": result.summary.failed_rules,
                },
                "messages": [
                    {
                        "severity": msg.severity.value,
                        "message": msg.message,
                        "rule_id": msg.rule_id,
                        "field_path": msg.field_path,
                        "section_reference": msg.section_reference,
                        "found_value": msg.found_value,
                        "expected_value": msg.expected_value,
                        "remediation": msg.remediation,
                    }
                    for msg in result.messages
                ],
            }
            for file_path, result in results
        ],
    }

    console.print(json.dumps(output_data, indent=2))


@click.command()
@click.argument(
    "paths",
    nargs=-1,
    required=False,  # Will be checked manually to allow special commands
    type=click.Path(exists=True),
)
@click.option(
    "--profile",
    default="default",
    help="Configuration profile to use (default: default)",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    help="Custom configuration file to use",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--recursive",
    "-r",
    is_flag=True,
    help="Recursively scan directories for SBOM files",
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
@click.option(
    "--list-profiles",
    is_flag=True,
    help="List available configuration profiles",
)
@click.option(
    "--generate-config",
    is_flag=True,
    help="Generate a configuration template",
)
@click.option(
    "--validate-config",
    type=click.Path(),
    help="Validate a configuration file",
)
@click.version_option(version=__version__, prog_name="sbom-check")
def main(  # pylint: disable=too-many-positional-arguments,too-many-locals,too-many-statements  # noqa: PLR0917
    paths: tuple[str, ...],
    profile: str,
    config: str | None,
    output_format: str,
    recursive: bool,
    pattern: str,
    jobs: int | None,
    list_profiles: bool,
    generate_config: bool,
    validate_config: str | None,
) -> None:
    """Validate SPDX 2.3 SBOM documents with configurable requirements.

    PATHS can be individual files or directories. When directories are provided,
    they will be scanned for SBOM files matching the specified pattern.
    """
    loader = ConfigLoader()

    # Handle special commands
    if list_profiles:
        _list_profiles(loader)
        return

    if generate_config:
        _generate_config(loader, profile)
        return

    if validate_config:
        _validate_config_file(loader, validate_config)
        return

    # Validate paths
    if not paths:
        console.print("[red]Error: No paths specified for validation[/red]")
        console.print("Use --help for usage information")
        sys.exit(2)

    try:
        # Collect all files to validate
        path_objects: tuple[Path, ...] = tuple(Path(p) for p in paths)
        files_to_validate = collect_sbom_files(path_objects, recursive, pattern)

        if not files_to_validate:
            console.print("[red]No SBOM files found to validate.[/red]")
            sys.exit(1)

        # Validate all files (in parallel if multiple files)
        results = []
        overall_valid = True

        if len(files_to_validate) == 1:
            # Single file - no need for parallel processing
            file_path = files_to_validate[0]

            # Load configuration
            if config:
                sbom_config = loader.load_with_profile(profile, config)
            else:
                sbom_config = loader.load_profile(profile)

            # Initialize engine and validate
            engine = SbomCheckEngine(sbom_config)
            result = engine.validate_file(file_path)
            results.append((file_path, result))

            if not result.overall_valid:
                overall_valid = False
        else:
            # Multiple files - use parallel processing
            with ProcessPoolExecutor(max_workers=jobs) as executor:
                # Submit all validation tasks
                future_to_file = {
                    executor.submit(
                        validate_single_file,
                        file_path,
                        profile,
                        config,
                    ): file_path
                    for file_path in files_to_validate
                }

                # Collect results as they complete
                for future in as_completed(future_to_file):
                    file_path, result = future.result()
                    results.append((file_path, result))
                    if not result.overall_valid:
                        overall_valid = False

            # Sort results by file path for consistent output
            results.sort(key=lambda x: x[0])

        # Output results
        if len(results) == 1:
            # Single file - use existing output format
            file_path, result = results[0]
            if output_format == "text":
                _print_text_result(result, str(file_path))
            elif output_format == "json":
                _print_json_result(result)
        elif output_format == "text":
            # Multiple files - use enhanced output format
            output_text_multiple(results)
        elif output_format == "json":
            output_json_multiple(results)

        # Exit with appropriate code
        sys.exit(0 if overall_valid else 1)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(3)


def _list_profiles(loader: ConfigLoader) -> None:
    """List available configuration profiles."""
    profiles = loader.list_profiles()

    console.print("[bold]Available Configuration Profiles:[/bold]")
    for profile_name in profiles:
        try:
            config = loader.load_profile(profile_name)
            console.print(
                f"  [cyan]{profile_name}[/cyan]: {config.metadata.description}"
            )
        except Exception:
            console.print(f"  [cyan]{profile_name}[/cyan]: (error loading description)")


def _generate_config(loader: ConfigLoader, profile: str) -> None:
    """Generate a configuration template."""
    try:
        template = loader.generate_template(profile, include_comments=True)
        console.print(template)
    except Exception as e:
        console.print(f"[red]Error generating config template: {e}[/red]")
        sys.exit(3)


def _validate_config_file(loader: ConfigLoader, config_path: str) -> None:
    """Validate a configuration file."""
    try:
        # Check if file exists first
        if not Path(config_path).exists():
            console.print(
                f"[red]Error validating config file: File not found: {config_path}[/red]"
            )
            sys.exit(3)

        is_valid, errors = loader.validate_config_file(Path(config_path))

        if is_valid:
            console.print(
                f"[green]✅ Configuration file is valid: {config_path}[/green]"
            )
        else:
            console.print(f"[red]❌ Configuration file has errors: {config_path}[/red]")
            for error in errors:
                console.print(f"  [red]• {error}[/red]")
            sys.exit(1)

    except Exception as e:
        console.print(f"[red]Error validating config file: {e}[/red]")
        sys.exit(3)


def _print_text_result(result: Any, file_path: str) -> None:
    """Print validation result in text format."""
    console.print(f"\n[bold]Validation Results for: {file_path}[/bold]")
    console.print(f"Profile: {result.profile_name or 'Unknown'}")

    # Overall status
    if result.overall_valid:
        console.print("[green]✅ Overall Result: PASSED[/green]")
    else:
        console.print("[red]❌ Overall Result: FAILED[/red]")

    # SPDX validation status
    if result.spdx_valid:
        console.print("[green]✅ SPDX 2.3 Validation: PASSED[/green]")
    else:
        console.print("[red]❌ SPDX 2.3 Validation: FAILED[/red]")

    # Profile validation status
    if result.profile_valid:
        console.print("[green]✅ Profile Validation: PASSED[/green]")
    else:
        console.print("[red]❌ Profile Validation: FAILED[/red]")

    # Messages
    if result.messages:
        console.print("\n[bold]Validation Messages:[/bold]")

        # Group messages by severity
        errors = result.get_messages_by_severity(ValidationSeverity.ERROR)
        warnings = result.get_messages_by_severity(ValidationSeverity.WARNING)
        info = result.get_messages_by_severity(ValidationSeverity.INFO)

        if errors:
            console.print(f"\n[red]Errors ({len(errors)}):[/red]")
            for msg in errors:
                _print_message(msg, "red")

        if warnings:
            console.print(f"\n[yellow]Warnings ({len(warnings)}):[/yellow]")
            for msg in warnings:
                _print_message(msg, "yellow")

        if info:
            console.print(f"\n[blue]Info ({len(info)}):[/blue]")
            for msg in info:
                _print_message(msg, "blue")

    # Summary
    summary = result.summary
    console.print(
        f"\n[bold]Summary:[/bold] {summary.errors} errors, {summary.warnings} warnings"
    )


def _print_message(msg: Any, color: str) -> None:
    """Print a single validation message."""
    console.print(f"  [{color}]• {msg.message}[/{color}]")

    if msg.field_path:
        console.print(f"    Field: {msg.field_path}")

    if msg.found_value is not None:
        console.print(f"    Found: {msg.found_value}")

    if msg.expected_value is not None:
        console.print(f"    Expected: {msg.expected_value}")

    if msg.section_reference:
        console.print(f"    Reference: {msg.section_reference}")

    if msg.remediation:
        console.print(f"    Remediation: {msg.remediation}")


def _print_json_result(result: Any) -> None:
    """Print validation result in JSON format."""
    # Convert result to JSON-serializable format
    json_result = {
        "overall_valid": result.overall_valid,
        "spdx_valid": result.spdx_valid,
        "profile_valid": result.profile_valid,
        "profile_name": result.profile_name,
        "file_path": result.file_path,
        "summary": {
            "errors": result.summary.errors,
            "warnings": result.summary.warnings,
            "info": result.summary.info,
            "total_rules": result.summary.total_rules,
            "passed_rules": result.summary.passed_rules,
            "failed_rules": result.summary.failed_rules,
        },
        "messages": [
            {
                "severity": msg.severity.value,
                "message": msg.message,
                "rule_id": msg.rule_id,
                "field_path": msg.field_path,
                "section_reference": msg.section_reference,
                "found_value": msg.found_value,
                "expected_value": msg.expected_value,
                "remediation": msg.remediation,
            }
            for msg in result.messages
        ],
    }

    console.print(json.dumps(json_result, indent=2))


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
