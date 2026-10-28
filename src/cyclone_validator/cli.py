# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Standalone CycloneDX JSON schema validation CLI."""

from __future__ import annotations

import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import TYPE_CHECKING

import click

from cyclone_validator.engine import CycloneDXValidationEngine

try:
    __version__ = version("sbom-check")
except PackageNotFoundError:
    __version__ = "dev"

if TYPE_CHECKING:
    from cyclone_validator.models import CycloneDXValidationResult, ValidationMessage


_worker_state: dict[str, CycloneDXValidationEngine] = {}


def _initialize_worker() -> None:
    """Create the reusable validation engine for one worker process."""
    _worker_state["engine"] = CycloneDXValidationEngine(
        enable_semantic_validation=False
    )


def collect_cyclonedx_files(
    paths: tuple[Path, ...], recursive: bool, pattern: str
) -> list[Path]:
    """Collect CycloneDX JSON files from paths."""
    files: list[Path] = []
    for path in paths:
        if path.is_file():
            files.append(path.resolve())
        elif path.is_dir():
            files.extend(path.rglob(pattern) if recursive else path.glob(pattern))
        else:
            click.echo(f"Warning: {path} is neither a file nor directory", err=True)
    return sorted({path.resolve() for path in files})


def validate_single_file(file_path: Path) -> tuple[Path, CycloneDXValidationResult]:
    """Validate one CycloneDX document using schema validation only."""
    if (engine := _worker_state.get("engine")) is None:
        _initialize_worker()
        engine = _worker_state["engine"]
    return file_path, engine.validate_file(file_path)


def _message_dict(message: ValidationMessage) -> dict[str, str | None]:
    """Convert a validation message to JSON-compatible data."""
    return {
        "severity": message.severity.value,
        "message": message.message,
        "field_path": message.field_path,
        "rule_id": message.rule_id,
    }


def output_json(results: list[tuple[Path, CycloneDXValidationResult]]) -> None:
    """Print validation results as JSON."""
    click.echo(
        json.dumps(
            {
                "summary": {
                    "total_files": len(results),
                    "valid_files": sum(1 for _, result in results if result.is_valid),
                    "invalid_files": sum(
                        1 for _, result in results if not result.is_valid
                    ),
                },
                "results": [
                    {
                        "file": str(path),
                        "is_valid": result.is_valid,
                        "messages": [
                            _message_dict(message) for message in result.messages
                        ],
                    }
                    for path, result in results
                ],
            },
            indent=2,
        )
    )


def output_text(results: list[tuple[Path, CycloneDXValidationResult]]) -> None:
    """Print validation results as human-readable text."""
    valid_files = sum(1 for _, result in results if result.is_valid)
    click.echo(
        f"Validated {len(results)} files: {valid_files} valid, {len(results) - valid_files} invalid"
    )
    for path, result in results:
        status = "PASSED" if result.is_valid else "FAILED"
        click.echo(f"{path}: {status}")
        for message in result.messages:
            click.echo(f"  [{message.severity.value}] {message.message}")
            if message.field_path:
                click.echo(f"    Path: {message.field_path}")


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
    help="Output format (default: text)",
)
@click.option("--recursive", "-r", is_flag=True, help="Recursively scan directories")
@click.option(
    "--pattern",
    default="*.cdx.json",
    help="File pattern to match when scanning directories (default: *.cdx.json)",
)
@click.option(
    "--jobs",
    "-j",
    type=click.IntRange(min=1),
    default=None,
    help="Number of parallel jobs (default: number of CPU cores)",
)
@click.version_option(version=__version__, prog_name="cyclonedx-validate")
def main(
    paths: tuple[Path, ...],
    output_format: str,
    recursive: bool,
    pattern: str,
    jobs: int | None,
) -> None:
    """Validate CycloneDX JSON documents against their declared schemas."""
    if not (files := collect_cyclonedx_files(paths, recursive, pattern)):
        click.echo("No CycloneDX JSON files found to validate.", err=True)
        sys.exit(1)

    if len(files) == 1:
        results = [validate_single_file(files[0])]
    else:
        with ProcessPoolExecutor(
            max_workers=jobs,
            initializer=_initialize_worker,
        ) as executor:
            futures = [executor.submit(validate_single_file, path) for path in files]
            results = [future.result() for future in as_completed(futures)]
        results.sort(key=lambda item: item[0])

    if output_format == "json":
        output_json(results)
    else:
        output_text(results)
    sys.exit(0 if all(result.is_valid for _, result in results) else 1)


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
