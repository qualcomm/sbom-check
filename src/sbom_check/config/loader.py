# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Configuration loader for SBOM-Check."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from sbom_check.config.models import SbomCheckConfig


def _unknown_completeness_rule_errors(config: SbomCheckConfig) -> list[str]:
    """Report completeness-check keys that match no registered rule.

    A mistyped rule ID would otherwise be accepted and have no effect,
    leaving an operator believing they had disabled or downgraded a rule
    that in fact still runs at its default severity.

    Args:
        config: The loaded configuration to inspect.

    Returns:
        list[str]: One message per unrecognised rule ID, empty when all
        keys are known. Legacy boolean-style keys that predate the rule
        registry are not reported, since they were never executed.
    """
    # Imported here to avoid a module-level cycle: the rules package
    # depends on the config models.
    from sbom_check.profile.rules_spdx3 import (  # noqa: PLC0415  # pylint: disable=import-outside-toplevel,cyclic-import
        SPDX3_RULES,
    )

    known = {rule.rule_id for rule in SPDX3_RULES}
    configured = set(config.compliance_requirements.completeness_checks)
    unknown = sorted(
        key for key in configured - known if key.startswith("spdx3_completeness.")
    )
    return [
        f"Unknown completeness rule '{key}'; it will have no effect. "
        f"Known SPDX 3.0.1 rules: {', '.join(sorted(known))}"
        for key in unknown
    ]


class ConfigLoader:
    """Loads and manages SBOM-Check configurations."""

    def __init__(self) -> None:
        """Initialize the configuration loader."""
        self._builtin_profiles: dict[str, SbomCheckConfig] = {}
        self._load_builtin_profiles()

    def _load_builtin_profiles(self) -> None:
        """Load built-in configuration profiles."""
        # Basic SPDX profile
        self._builtin_profiles["basic_spdx"] = SbomCheckConfig.create_basic_spdx()

        # Default comprehensive profile
        self._builtin_profiles["default"] = SbomCheckConfig.create_default()

    def load_from_file(self, config_path: Path | str) -> SbomCheckConfig:
        """Load configuration from a YAML or JSON file.

        Args:
            config_path: Path to the configuration file

        Returns:
            Loaded configuration

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            ValueError: If the configuration file is invalid
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        try:
            with config_path.open(encoding="utf-8") as f:
                if config_path.suffix.lower() in {".yaml", ".yml"}:
                    config_data = yaml.safe_load(f)
                elif config_path.suffix.lower() == ".json":
                    config_data = json.load(f)
                else:
                    # Try to detect format by content
                    content = f.read()
                    try:
                        config_data = json.loads(content)
                    except json.JSONDecodeError:
                        config_data = yaml.safe_load(content)

            return SbomCheckConfig.model_validate(config_data)

        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise ValueError(f"Invalid configuration file format: {e}") from e
        except Exception as e:
            raise ValueError(f"Error loading configuration: {e}") from e

    def load_profile(self, profile_name: str) -> SbomCheckConfig:
        """Load a built-in configuration profile.

        Args:
            profile_name: Name of the profile to load

        Returns:
            Configuration for the specified profile

        Raises:
            ValueError: If the profile doesn't exist
        """
        if profile_name not in self._builtin_profiles:
            available = ", ".join(self._builtin_profiles.keys())
            raise ValueError(
                f"Unknown profile '{profile_name}'. Available profiles: {available}"
            )

        return self._builtin_profiles[profile_name]

    def list_profiles(self) -> list[str]:
        """List available built-in profiles.

        Returns:
            List of profile names
        """
        return list(self._builtin_profiles.keys())

    def load_with_profile(
        self,
        profile_name: str,
        config_path: Path | str | None = None,
        overrides: dict[str, Any] | None = None,
    ) -> SbomCheckConfig:
        """Load configuration starting with a profile and applying overrides.

        Args:
            profile_name: Base profile to start with
            config_path: Optional custom configuration file to merge
            overrides: Optional dictionary of configuration overrides

        Returns:
            Merged configuration
        """
        # Start with the base profile
        config = self.load_profile(profile_name)

        # Merge with custom configuration file if provided
        if config_path:
            custom_config = self.load_from_file(config_path)
            config = config.merge_with(custom_config)

        # Apply any direct overrides
        if overrides:
            override_config = SbomCheckConfig.model_validate(
                {"metadata": config.metadata.model_dump(), **overrides}
            )
            config = config.merge_with(override_config)

        return config

    def save_to_file(
        self,
        config: SbomCheckConfig,
        output_path: Path | str,
        format_type: str = "yaml",
    ) -> None:
        """Save configuration to a file.

        Args:
            config: Configuration to save
            output_path: Path where to save the configuration
            format_type: Output format ('yaml' or 'json')

        Raises:
            ValueError: If format_type is not supported
        """
        output_path = Path(output_path)
        # mode="json" renders enum values (for example completeness-check
        # severities) as plain strings. A plain model_dump() emits enum
        # objects, which yaml.dump writes as Python object tags that
        # yaml.safe_load then refuses to read back.
        config_data = config.model_dump(exclude_none=True, mode="json")

        with output_path.open("w", encoding="utf-8") as f:
            if format_type.lower() == "yaml":
                yaml.dump(
                    config_data,
                    f,
                    default_flow_style=False,
                    sort_keys=False,
                    indent=2,
                )
            elif format_type.lower() == "json":
                json.dump(config_data, f, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format_type}")

    def generate_template(
        self,
        profile_name: str = "default",
        include_comments: bool = True,
    ) -> str:
        """Generate a configuration template based on a profile.

        Args:
            profile_name: Base profile to use for the template
            include_comments: Whether to include explanatory comments

        Returns:
            YAML configuration template as string
        """
        config = self.load_profile(profile_name)
        config_data = config.model_dump(exclude_none=True, mode="json")

        if include_comments:
            # Add comments to explain configuration sections
            template_lines = [
                "# SBOM-Check Configuration Template",
                f"# Based on profile: {profile_name}",
                "# Customize this configuration for your specific requirements",
                "",
            ]

            yaml_content = yaml.dump(
                config_data,
                default_flow_style=False,
                sort_keys=False,
                indent=2,
            )

            template_lines.append(yaml_content)
            return "\n".join(template_lines)

        return yaml.dump(
            config_data,
            default_flow_style=False,
            sort_keys=False,
            indent=2,
        )

    def validate_config_file(self, config_path: Path | str) -> tuple[bool, list[str]]:
        """Validate a configuration file without loading it fully.

        Args:
            config_path: Path to the configuration file to validate

        Returns:
            Tuple of (is_valid, error_messages)
        """
        errors: list[str] = []

        try:
            config = self.load_from_file(config_path)
            # If we got here, the basic structure is valid

            # Perform additional validation checks
            if not config.metadata.name:
                errors.append("Configuration metadata.name is required")

            if not config.metadata.version:
                errors.append("Configuration metadata.version is required")

            errors.extend(_unknown_completeness_rule_errors(config))

            # Validate field validation rules
            for (
                field_name,
                rule,
            ) in config.document_requirements.field_validation.items():
                if hasattr(rule, "pattern") and rule.pattern:
                    try:
                        re.compile(rule.pattern)
                    except re.error as e:
                        errors.append(f"Invalid regex pattern in {field_name}: {e}")

            return len(errors) == 0, errors
        except (
            FileNotFoundError,
            PermissionError,
            yaml.YAMLError,
            json.JSONDecodeError,
        ) as e:
            errors.append(str(e))
            return False, errors
