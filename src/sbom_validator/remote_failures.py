# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Lightweight process-local state for remote validation resource failures."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RemoteFailureState:
    """Opt-in flag and cached remote failure shared by validation workers."""

    reuse_enabled: bool = False
    failures: dict[tuple[bool, bool], Any] = field(default_factory=dict)


remote_failure_state = RemoteFailureState()


def enable_remote_failure_reuse() -> None:
    """Enable per-process reuse of remote resource failures and clear old state."""
    remote_failure_state.reuse_enabled = True
    remote_failure_state.failures.clear()


def disable_remote_failure_reuse() -> None:
    """Disable per-process reuse and clear any cached remote resource failure."""
    remote_failure_state.reuse_enabled = False
    remote_failure_state.failures.clear()
