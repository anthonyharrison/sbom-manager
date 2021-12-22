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
from sbom_manager.log import LOGGER
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
        help="add SBOM filename",
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
        "-s", "--scan", action="store_true", help="scan SBOMs for vulnerabilities"
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-q", "--quiet", action="store_true", help="suppress output"
    )
    output_group.add_argument(
        "-L",
        "--log",
        help="log level (default: info)",
        dest="log_level",
        action="store",
        choices=["debug", "info", "warning", "error", "critical"],
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        help="provide output filename (default: output to stdout)",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["csv", "console", "pdf"],
        help="update output format (default: console)",
    )

    parser.add_argument(
        "-C", "--config", action="store", default="", help="provide config file"
    )
    parser.add_argument(
        "-I", "--init", action="store_true", help="initialise SBOM manager"
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "add_file": "",
        "module": "",
        "list": "all",
        "description": "",
        "quiet": False,
        "log_level": "info",
        "format": "console",
        "quiet": False,
        "output_file": "",
        "init": False,
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

    # TODO Database validation

    # Add Input validation
    if args["add_file"] and not args["description"]:
        desc = "Not specified"
    else:
        desc = args["description"]

    # TODO Add output handlier

    # Do something
    if args["init"]:
        # Initialise everything
        LOGGER.debug("Initialise system")
        sbom_db.initialise_database()
    elif args["add_file"]:
        # Process SBOM file
        LOGGER.debug(f"Add SBOM {args['add_file']}")
        sbom_data = [
            {"vendor": "apache", "product": "log4j", "version": "2.14.2"},
            {"vendor": "oracle", "product": "mysql", "version": "5.0.45"},
        ]
        # And add to database
        sbom_db.add_file(args["add_file"], desc, sbom_data)
    elif args["module"]:
        # Search for module
        LOGGER.debug(f"Search for module {args['module']}")
        print("Filename      Description   Vendor   Product   Version")
        print("=" * 30)
        for entry in sbom_db.find_module(args["module"]):
            print(entry[0], entry[1], entry[2], entry[3], entry[4])
    elif args["list"]:
        # List contents of database
        LOGGER.debug("List contents")
        if args["list"] == "sbom":
            print("Filename      Description")
            print("=" * 30)
            for entry in sbom_db.list_entries(args["list"]):
                print(entry[1], entry[2])
        elif args["list"] == "module":
            print("Vendor   Product   Version")
            print("=" * 30)
            for entry in sbom_db.list_entries(args["list"]):
                print(entry[1], entry[2], entry[3])
        else:
            print("Filename      Description   Vendor   Product   Version")
            print("=" * 30)
            for entry in sbom_db.list_entries(args["list"]):
                print(entry[0], entry[1], entry[2], entry[3], entry[4])
    elif args["scan"]:
        # Scan for vulnerabilities
        LOGGER.info("Scan system for vulnerabilities")
    return 0
