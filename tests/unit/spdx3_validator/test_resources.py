# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for cached SPDX 3 validation resources."""

import json
from unittest.mock import Mock, patch

from spdx3_validator.resources import (
    VALIDATION_RESOURCE_TIMEOUT_SECONDS,
    load_validation_resources,
)


class _Response:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def read(self, *args):
        return self.content


def test_load_validation_resources_is_cached_per_process():
    """Download schema and SHACL resources only once for repeated calls."""
    schema = json.dumps({"type": "object"}).encode("utf-8")
    urlopen = Mock(side_effect=[_Response(schema), _Response(b"")])

    load_validation_resources.cache_clear()
    try:
        with patch("spdx3_validator.resources.urlopen", urlopen):
            first = load_validation_resources()
            second = load_validation_resources()

        assert first is second
        assert urlopen.call_count == 2
        assert all(
            call.kwargs["timeout"] == VALIDATION_RESOURCE_TIMEOUT_SECONDS
            for call in urlopen.call_args_list
        )
    finally:
        load_validation_resources.cache_clear()
