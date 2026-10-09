# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Shared helpers for format-specific SBOM validator CLIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

import click


def collect_spdx_files(
    paths: tuple[Path, ...], recursive: bool, pattern: str
) -> list[Path]:
    """Collect SPDX files from files and directories."""
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

    return sorted(files)


def output_text_multiple(
    results: list[tuple[Path, Any]], output_text: Callable[[Any, Path], None]
) -> None:
    """Output multiple validation results using a format-specific formatter."""
    total_files = len(results)
    valid_files = sum(1 for _, result in results if result.is_valid)
    invalid_files = total_files - valid_files

    valid_text = click.style(f"{valid_files} valid", fg="green", bold=True)
    invalid_text = click.style(f"{invalid_files} invalid", fg="red", bold=True)
    click.echo(f"Validated {total_files} files: {valid_text}, {invalid_text}")
    click.echo("=" * 80)

    for index, (file_path, result) in enumerate(results):
        output_text(result, file_path)
        if index < total_files - 1:
            click.echo()

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
