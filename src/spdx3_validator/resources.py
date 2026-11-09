# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Process-local SPDX 3 validation resources."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from functools import lru_cache

import jsonschema
import rdflib
import requests
from spdx3_validate.core import SpdxValidateError, schema_validator
from spdx3_validate.spdx_versions import SpdxVersion, find_version

SPDX_VERSION = "3.0.1"
SPDX_CONTEXT_URL = f"https://spdx.org/rdf/{SPDX_VERSION}/spdx-context.jsonld"
VALIDATION_RESOURCE_TIMEOUT_SECONDS = 30


@dataclass(frozen=True)
class ValidationResources:
    """Resources required by the enabled SPDX validation stages."""

    schema_validator: jsonschema.protocols.Validator | None
    shacl_graph: rdflib.Graph | None
    version: SpdxVersion


def configure_network_timeout() -> None:
    """Set the process socket timeout for CLI context resolution.

    This changes process-global state and should be called once during CLI or
    worker initialization, not for each library validation.
    """
    if socket.getdefaulttimeout() is None:
        socket.setdefaulttimeout(VALIDATION_RESOURCE_TIMEOUT_SECONDS)


@lru_cache(maxsize=1)
def _get_spdx_version() -> SpdxVersion:
    """Return metadata for the supported SPDX version."""
    if (version := find_version(SPDX_CONTEXT_URL)) is None:
        raise SpdxValidateError(f"Unknown SPDX version {SPDX_VERSION}")
    return version


@lru_cache(maxsize=1)
def _load_schema_validator() -> jsonschema.protocols.Validator:
    """Download and cache the SPDX JSON schema validator."""
    version = _get_spdx_version()
    with requests.get(
        version.schema_url, timeout=VALIDATION_RESOURCE_TIMEOUT_SECONDS
    ) as response:
        response.raise_for_status()
        schema = response.json()

    try:
        return schema_validator(schema)
    except jsonschema.exceptions.SchemaError as error:
        raise SpdxValidateError(
            f"Invalid schema {version.schema_url}: {error}"
        ) from error


@lru_cache(maxsize=1)
def _load_shacl_graph() -> rdflib.Graph:
    """Download, parse, and cache the SPDX SHACL graph."""
    version = _get_spdx_version()
    with requests.get(
        version.shacl_url, timeout=VALIDATION_RESOURCE_TIMEOUT_SECONDS
    ) as response:
        response.raise_for_status()
        shacl_data = response.content

    shacl_graph = rdflib.Graph()
    shacl_graph.parse(
        data=shacl_data.decode("utf-8"),
        format="turtle",
        publicID=version.shacl_url,
    )
    return shacl_graph


def load_validation_resources(
    enable_schema_validation: bool = True,
    enable_semantic_validation: bool = True,
) -> ValidationResources:
    """Load only the SPDX resources needed by the enabled validation stages."""
    return ValidationResources(
        schema_validator=(
            _load_schema_validator() if enable_schema_validation else None
        ),
        shacl_graph=_load_shacl_graph() if enable_semantic_validation else None,
        version=_get_spdx_version(),
    )
