# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Shared constants and helpers used by SBOM validators."""

from typing import Any

REMOTE_RESOURCE_UNAVAILABLE_RULE_ID = "remote_resource_unavailable"


def has_remote_resource_failure(result: Any) -> bool:
    """Return whether a validation result reports an unavailable remote resource."""
    return any(
        getattr(message, "rule_id", None) == REMOTE_RESOURCE_UNAVAILABLE_RULE_ID
        for message in getattr(result, "messages", [])
    )
