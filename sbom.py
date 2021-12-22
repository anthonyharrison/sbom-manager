# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

"""
This tool manages SBOMs (Software Bill of Materials) to allow searching for modules
and scanning for vulnerabilities.
"""

import sys

from sbom_manager.cli import main

sys.exit(main())
