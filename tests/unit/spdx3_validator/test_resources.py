# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for cached SPDX 3 validation resources."""

import json
from unittest.mock import Mock, patch

import jsonschema
import pytest
from spdx3_validate.core import SpdxValidateError

from sbom_validator.network import (
    VALIDATION_RESOURCE_TIMEOUT_SECONDS,
    configure_network_timeout,
)
from spdx3_validator.resources import (
    _get_spdx_version,
    _load_schema_validator,
    _load_shacl_graph,
    load_validation_resources,
)


def _clear_resource_caches() -> None:
    """Reset cached resources between tests."""
    _load_schema_validator.cache_clear()
    _load_shacl_graph.cache_clear()
    _get_spdx_version.cache_clear()


class _Response:
    def __init__(self, content: bytes):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False

    def json(self):
        return json.loads(self.content)

    @staticmethod
    def raise_for_status():
        pass


def test_configure_network_timeout_sets_default_only_when_unset():
    """Set the CLI socket timeout without replacing a caller's existing default."""
    with (
        patch("sbom_validator.network.socket.getdefaulttimeout", return_value=None),
        patch("sbom_validator.network.socket.setdefaulttimeout") as set_timeout,
    ):
        configure_network_timeout()

    set_timeout.assert_called_once_with(VALIDATION_RESOURCE_TIMEOUT_SECONDS)


def test_configure_network_timeout_preserves_existing_default():
    """Keep an existing process socket timeout unchanged."""
    with (
        patch("sbom_validator.network.socket.getdefaulttimeout", return_value=5.0),
        patch("sbom_validator.network.socket.setdefaulttimeout") as set_timeout,
    ):
        configure_network_timeout()

    set_timeout.assert_not_called()


def test_load_validation_resources_is_cached_per_process():
    """Download schema and SHACL resources only once for repeated calls."""
    schema = json.dumps({"type": "object"}).encode("utf-8")
    get = Mock(side_effect=[_Response(schema), _Response(b"")])

    _clear_resource_caches()
    try:
        with patch("spdx3_validator.resources.requests.get", get):
            first = load_validation_resources()
            second = load_validation_resources()

        assert first.schema_validator is second.schema_validator
        assert first.shacl_graph is second.shacl_graph
        assert get.call_count == 2
        assert [call.args[0] for call in get.call_args_list] == [
            "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
            "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        ]
        assert all(
            call.kwargs["timeout"] == VALIDATION_RESOURCE_TIMEOUT_SECONDS
            for call in get.call_args_list
        )
    finally:
        _clear_resource_caches()


def test_schema_error_uses_bounded_message():
    """Avoid embedding jsonschema's verbose schema and metaschema dump."""
    schema_url = "https://spdx.org/schema/3.0.1/spdx-json-schema.json"
    schema_error = jsonschema.exceptions.SchemaError(
        "schema must declare a type",
        validator="type",
        validator_value="object",
        instance={"payload": "instance-fragment"},
        schema={"properties": {"payload": {"description": "schema-fragment"}}},
    )
    _clear_resource_caches()
    try:
        with (
            patch(
                "spdx3_validator.resources._get_spdx_version",
                return_value=Mock(schema_url=schema_url),
            ),
            patch(
                "spdx3_validator.resources.requests.get",
                return_value=_Response(b"{}"),
            ),
            patch(
                "spdx3_validator.resources.schema_validator",
                side_effect=schema_error,
            ),
            pytest.raises(SpdxValidateError) as raised,
        ):
            _load_schema_validator()
    finally:
        _clear_resource_caches()

    assert str(raised.value) == (
        f"Invalid schema {schema_url}: schema must declare a type"
    )
    assert "schema-fragment" not in str(raised.value)
    assert len(str(schema_error)) > len(str(raised.value))


@pytest.mark.parametrize(
    ("schema_enabled", "semantic_enabled", "expected_url"),
    [
        (
            True,
            False,
            "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        ),
        (False, True, "https://spdx.org/rdf/3.0.1/spdx-model.ttl"),
        (False, False, None),
    ],
)
def test_load_validation_resources_fetches_only_enabled_resources(
    schema_enabled: bool, semantic_enabled: bool, expected_url: str | None
):
    """Skip downloads for validation resources belonging to disabled stages."""
    schema = json.dumps({"type": "object"}).encode("utf-8")
    get = Mock(return_value=_Response(schema if schema_enabled else b""))
    try:
        with patch("spdx3_validator.resources.requests.get", get):
            resources = load_validation_resources(
                enable_schema_validation=schema_enabled,
                enable_semantic_validation=semantic_enabled,
            )

        assert (resources.schema_validator is not None) is schema_enabled
        assert (resources.shacl_graph is not None) is semantic_enabled
        if expected_url is None:
            get.assert_not_called()
        else:
            get.assert_called_once()
            assert get.call_args.args[0] == expected_url
    finally:
        _clear_resource_caches()
