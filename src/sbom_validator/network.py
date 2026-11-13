# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Network settings shared by SBOM validation command-line interfaces."""

from __future__ import annotations

import socket

VALIDATION_RESOURCE_TIMEOUT_SECONDS = 30


def configure_network_timeout() -> None:
    """Set a process socket timeout without replacing a caller's existing default.

    This changes process-global state and should be called once during CLI or
    worker initialization, not for each library validation.
    """
    if socket.getdefaulttimeout() is None:
        socket.setdefaulttimeout(VALIDATION_RESOURCE_TIMEOUT_SECONDS)
