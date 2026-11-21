# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Format-neutral interfaces shared by SBOM validators."""

from sbom_validator.engine import ValidationResultProtocol, ValidatorEngine

__all__ = ["ValidationResultProtocol", "ValidatorEngine"]
