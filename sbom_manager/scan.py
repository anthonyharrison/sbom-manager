# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" SBOM Vulnerability Scanner """

from sbom_manager.log import LOGGER


class SBOMScanner:
    """
    Simple SBOM Vulnerability Scanner.
    """

    def __init__(self, filename):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.filename = filename

    def scan(self, options):
        LOGGER.info(f"Scan {self.filename} for vulnerabilities")
