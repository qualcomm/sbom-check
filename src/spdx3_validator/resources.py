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
    """Cached resources required to validate SPDX documents."""

    schema_validator: jsonschema.protocols.Validator
    shacl_graph: rdflib.Graph
    version: SpdxVersion


def configure_network_timeout() -> None:
    """Set the default socket timeout used by rdflib context resolution."""
    socket.setdefaulttimeout(VALIDATION_RESOURCE_TIMEOUT_SECONDS)


@lru_cache(maxsize=1)
def load_validation_resources() -> ValidationResources:
    """Load and cache SPDX schema and SHACL resources for this process."""
    if (version := find_version(SPDX_CONTEXT_URL)) is None:
        raise SpdxValidateError(f"Unknown SPDX version {SPDX_VERSION}")

    with requests.get(
        version.schema_url, timeout=VALIDATION_RESOURCE_TIMEOUT_SECONDS
    ) as response:
        response.raise_for_status()
        schema = response.json()

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

    try:
        validator = schema_validator(schema)
    except jsonschema.exceptions.SchemaError as error:
        raise SpdxValidateError(
            f"Invalid schema {version.schema_url}: {error}"
        ) from error

    return ValidationResources(validator, shacl_graph, version)
