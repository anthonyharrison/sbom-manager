# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" SBOM Vulnerability Scanner """

from sbom_manager.log import LOGGER


class SBOMScanner:
    """
    Simple SBOM Vulnerability Scanner.
    """

    def __init__(self, filename, options):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.filename = filename
        self.options = options

    def scan(self):
        LOGGER.info(f"Scan {self.filename} for vulnerabilities")
        if len(self.options) > 0:
            LOGGER.info(
                f"{self.options['application']} {self.options['options']} {self.filename}"
            )
        else:
            LOGGER.warning("Unable to scan - vulnerability scanner not configured")
