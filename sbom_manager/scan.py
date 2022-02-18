# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" SBOM Vulnerability Scanner """

import subprocess

from sbom_manager.log import LOGGER


class SBOMScanner:
    """
    Simple SBOM Vulnerability Scanner.
    """

    def __init__(self, filename, options):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.filename = filename
        self.options = options

    def run_program(self, command_line):
        # Remove any null bytes
        command_line = command_line.replace("\x00", "")
        # print (command_line)
        # Split command line into individual elements
        params = command_line.split()
        # print(params)
        res = subprocess.run(params, capture_output=True, text=True)
        # print(res)
        return res.stdout.splitlines()

    def scan(self):
        LOGGER.info(f"Scan {self.filename} for vulnerabilities")
        if len(self.options) > 0 and 'application' in self.options:
            command_line = f"{self.options['application']} {self.options['options']} "
            command_line = command_line + f"{self.filename}"
            LOGGER.info(command_line)
            scan_output = self.run_program(command_line)
            for i in scan_output:
                print(i)
        else:
            LOGGER.warning("Unable to scan - vulnerability scanner not configured")
