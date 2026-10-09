# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Pytest configuration and shared fixtures."""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sbom_check.config.loader import ConfigLoader
from sbom_check.config.models import SbomCheckConfig

MINIMAL_SPDX3_DOCUMENT = (
    Path(__file__).parent / "fixtures" / "minimal-spdx3.0.1.spdx.json"
)


@pytest.fixture
def minimal_spdx3_document() -> dict[str, Any]:
    """Provide an isolated deep copy of the minimal SPDX 3 document."""
    document = json.loads(MINIMAL_SPDX3_DOCUMENT.read_text(encoding="utf-8"))
    return deepcopy(document)


@pytest.fixture
def sample_valid_spdx_document() -> dict[str, Any]:
    """Provide a valid SPDX document for testing."""
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "TestProduct-v1.0.0-SBOM",
        "documentNamespace": "https://example.com/spdx/testproduct-v1.0.0-20240824",
        "creationInfo": {
            "creators": ["Organization: Example Corp", "Tool: sbom-generator-1.0.0"],
            "created": "2024-08-24T18:30:22Z",
            "licenseListVersion": "3.26",
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-TestApp",
                "name": "TestApplication",
                "versionInfo": "1.0.0",
                "supplier": "Organization: Example Corp",
                "downloadLocation": "NONE",
                "filesAnalyzed": False,
                "homepage": "https://example.com/testapp",
                "licenseConcluded": "Apache-2.0",
                "licenseDeclared": "Apache-2.0",
                "copyrightText": "Copyright (c) 2024 Example Corp",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:generic/testapplication@1.0.0",
                    }
                ],
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-TestApp",
            }
        ],
    }


@pytest.fixture
def sample_invalid_spdx_document() -> dict[str, Any]:
    """Provide an invalid SPDX document for testing."""
    return {
        "spdxVersion": "SPDX-2.2",  # Wrong version
        "dataLicense": "MIT",  # Wrong license
        "SPDXID": "SPDXRef-DOC",  # Wrong ID
        "name": "TestProduct",
        "documentNamespace": "http://example.com/spdx/test#fragment",  # HTTP + fragment
        "creationInfo": {
            "creators": ["Organization: Example Corp"],  # Missing tool
            "created": "2024-08-24 18:30:22",  # Wrong format
        },
        "packages": [],
        "relationships": [],
    }


@pytest.fixture
def config_loader() -> ConfigLoader:
    """Provide a ConfigLoader instance."""
    return ConfigLoader()


@pytest.fixture
def basic_spdx_config(config_loader: ConfigLoader) -> SbomCheckConfig:
    """Provide basic SPDX configuration."""
    return config_loader.load_profile("basic_spdx")


@pytest.fixture
def default_config(config_loader: ConfigLoader) -> SbomCheckConfig:
    """Provide default configuration."""
    return config_loader.load_profile("default")


@pytest.fixture
def temp_spdx_file(tmp_path, sample_valid_spdx_document):
    """Create a temporary SPDX file for testing."""
    spdx_file = tmp_path / "test.spdx.json"
    with spdx_file.open("w") as f:
        json.dump(sample_valid_spdx_document, f)
    return spdx_file


@pytest.fixture
def temp_invalid_spdx_file(tmp_path, sample_invalid_spdx_document):
    """Create a temporary invalid SPDX file for testing."""
    spdx_file = tmp_path / "invalid.spdx.json"
    with spdx_file.open("w") as f:
        json.dump(sample_invalid_spdx_document, f)
    return spdx_file
