# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

"""
This tool manages SBOMs (Software Bill of Materials) to allow searching for modules
and scanning for vulnerabilities.
"""

import argparse
import configparser
import logging
import sys
import textwrap
from collections import ChainMap

from sbom_manager.db import SBOMDB
from sbom_manager.input import SBOMInput
from sbom_manager.log import LOGGER
from sbom_manager.output import SBOMOutput
from sbom_manager.version import VERSION


def main(argv=None):
    """Manage a set of SBOMs"""
    argv = argv or sys.argv

    # Reset logger level to info
    LOGGER.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="sbom-manager",
        description=textwrap.dedent(
            """
            The SBOM Manager manages SBOMs (Software Bill of Materials) to allow
            searching for modules and scanning for vulnerabilities.
            """
        ),
        epilog="\n\nPlease report issues responsibly!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-a",
        "--add",
        action="store",
        default="",
        dest="add_file",
        help="SBOM file to be added",
    )
    input_group.add_argument(
        "-t",
        "--sbom-type",
        action="store",
        choices=["spdx", "cyclonedx", "csv"],
        help="SBOM file type",
    )
    input_group.add_argument(
        "-l",
        "--list",
        action="store",
        choices=["all", "sbom", "module"],
        help="list SBOMs (default all)",
    )
    input_group.add_argument(
        "-m", "--module", action="store", default="", help="Find module in SBOMs"
    )
    input_group.add_argument(
        "-d",
        "--description",
        action="store",
        default="",
        help="Description of SBOM file",
    )
    input_group.add_argument(
        "-p",
        "--project",
        action="store",
        default="",
        help="Project name",
    )
    input_group.add_argument(
        "-s", "--scan", action="store_true", help="Scan SBOMs for vulnerabilities"
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress output"
    )
    output_group.add_argument(
        "-L",
        "--log",
        help="Log level (default: info)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="Output filename (default: output to stdout)",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["csv", "console"],
        help="Output format (default: console)",
    )

    parser.add_argument(
        "-C", "--config", action="store", default="", help="Name of config file"
    )
    parser.add_argument(
        "-I", "--initialise", action="store_true", help="Initialise SBOM manager"
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "add_file": "",
        "sbom_type": "",
        "module": "",
        "list": "all",
        "description": "",
        "project": "",
        "log_level": "info",
        "format": "console",
        "quiet": False,
        "output_file": "console",
        "initialise": False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}

    configs = {}
    if args.get("config"):
        # TODO
        config = configparser.ConfigParser()
        configs = config.read(args["config"])

    args = ChainMap(args, configs, defaults)

    # Logging related settings
    if args["log_level"]:
        LOGGER.setLevel(args["log_level"].upper())

    if args["quiet"]:
        LOGGER.setLevel(logging.CRITICAL)

    # Connect to the database
    sbom_db = SBOMDB()

    # Add Input validation
    if args["add_file"] and not args["description"]:
        desc = "Not specified"
    else:
        desc = args["description"]
    if args["add_file"] and not args["sbom_type"]:
        LOGGER.info("SBOM type not specified")
        return -1
    sbom_input = SBOMInput(args["sbom_type"])
    if args["add_file"] and not args["project"]:
        LOGGER.info("Project name not specified")
        return -1

    # Add output handler
    sbom_output = SBOMOutput(args["output_file"], args["format"])

    # Do something
    if args["initialise"]:
        # Initialise everything
        LOGGER.debug("Initialise system")
        sbom_db.initialise_database()
    elif args["add_file"]:
        # Process SBOM file
        LOGGER.debug(f"Add SBOM {args['add_file']}")
        sbom_data = sbom_input.process_file(args["add_file"])
        if sbom_data is not None:
            # And add to database
            sbom_db.add_file(args["add_file"], desc, args["project"], args["sbom_type"], sbom_data)
    elif args["module"]:
        # Search for module
        LOGGER.debug(f"Search for module {args['module']}")
        sbom_output.set_headings(
            ["Filename", "Project", "Description", "Vendor", "Product", "Version"]
        )
        sbom_output.generate_output(sbom_db.find_module(args["module"], args["project"]))
    elif args["list"]:
        # List contents of database
        LOGGER.debug("List contents")
        if args["list"] == "sbom":
            sbom_output.set_headings(
                ["Filename", "Project", "Description", "SBOM Type", "Date Added"]
            )
        elif args["list"] == "module":
            sbom_output.set_headings(["Vendor", "Product", "Version"])
        else:
            sbom_output.set_headings(
                ["Filename", "Project", "Description", "Vendor", "Product", "Version"]
            )
        sbom_output.generate_output(sbom_db.list_entries(args["list"]))
    elif args["scan"]:
        # Scan for vulnerabilities
        LOGGER.info("Scan system for vulnerabilities")
    return 0
