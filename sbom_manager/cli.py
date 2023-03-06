# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: MIT

"""
This tool manages SBOMs (Software Bill of Materials) to allow searching for modules
and scanning for vulnerabilities.
"""

import argparse
import logging
import os
import sys
import textwrap
from collections import ChainMap
from pathlib import Path

from sbom_manager.config import SBOMConfig
from sbom_manager.db import SBOMDB
from sbom_manager.generate import SBOMGenerator
from sbom_manager.input import SBOMInput
from sbom_manager.log import LOGGER
from sbom_manager.output import OutputManager, SBOMOutput
from sbom_manager.scan import SBOMScanner
from sbom_manager.store import SBOMStore
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
        "-I", "--initialise", action="store_true", help="Initialise SBOM manager"
    )
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
        choices=["spdx", "cyclonedx", "csv", "dir"],
        help="SBOM file type",
    )
    input_group.add_argument(
        "-l",
        "--list",
        action="store",
        choices=["all", "sbom", "module"],
        help="list contents of SBOM",
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
    input_group.add_argument(
        "--history", action="store_true", help="Include file history"
    )

    data_group = parser.add_argument_group("Data")
    data_group.add_argument(
        "--export",
        action="store",
        help="export database filename",
        default="",
    )
    data_group.add_argument(
        "--import",
        action="store",
        help="import database filename",
        default="",
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
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "add_file": "",
        "config": "",
        "sbom_type": "",
        "module": "",
        "list": "",
        "description": "",
        "project": "",
        "log_level": "info",
        "format": "console",
        "quiet": False,
        "output_file": "console",
        "initialise": False,
        "scan": False,
        "import": "",
        "export": "",
        "history": False,
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}

    configs = {}

    args = ChainMap(args, configs, defaults)

    config_file = args["config"] if args["config"] else ""
    sbom_config = SBOMConfig(config_file)

    # Logging related settings
    if args["log_level"]:
        LOGGER.setLevel(args["log_level"].upper())

    if args["quiet"]:
        LOGGER.setLevel(logging.CRITICAL)

    # Connect to the database
    sbom_db = SBOMDB()

    # Import database if file exists
    if args["import"] and Path(args["import"]).exists():
        LOGGER.info(f'Import database from {args["import"]}')
        sbom_db.copy_db(filename=args["import"], export=False)

    # Add Input validation
    if args["add_file"] and not args["description"]:
        desc = "Not specified"
    else:
        desc = args["description"]
    if args["add_file"] and not args["sbom_type"]:
        LOGGER.info("SBOM type not specified")
        return -1
    sbom_type = args["sbom_type"]
    # Detect json files
    if args["add_file"].endswith(".json") and sbom_type in ["spdx", "cyclonedx"]:
        sbom_type = sbom_type + "_json"
    sbom_input = SBOMInput(sbom_type)
    if args["add_file"] and not args["project"]:
        LOGGER.info("Project name not specified")
        return -1

    # Ensure project name doesn't have a space (to ensure directory name is valid)
    if " " in args["project"]:
        args["project"] = args["project"].replace(" ", "_")
        LOGGER.info(f"Renaming project name to {args['project']}")

    # Add output handler
    sbom_output = SBOMOutput(args["output_file"], args["format"])

    # Setup store manager
    sbom_store = SBOMStore(sbom_config.get_section("data"))

    # Do something
    if args["initialise"]:
        # Initialise everything
        LOGGER.debug("Initialise system")
        sbom_db.initialise_database()
        sbom_store.initialise_store()
    elif args["export"] and sbom_db.check_db_exists():
        LOGGER.info(f'Export database to {args["export"]}')
        sbom_db.copy_db(filename=args["export"], export=True)
    elif not sbom_db.check_db_exists():
        LOGGER.error("Database not setup. Please enter sbom-manager --init before proceeding")
    elif args["add_file"]:
        # Process SBOM file
        LOGGER.debug(f"Add SBOM {args['add_file']}")
        sbom_data = sbom_input.process_file(args["add_file"])
        if sbom_data is not None:
            # Add entry to database
            version = sbom_db.add_file(
                args["add_file"], desc, args["project"], args["sbom_type"], sbom_data
            )
            # And store file
            LOGGER.debug(f"Store {args['add_file']}")
            sbom_store.store(args["add_file"], args["project"], version=version)
    elif args["module"]:
        # Search for module
        LOGGER.debug(f"Search for module {args['module']}")
        if args["history"]:
            sbom_output.set_headings(
                ["SBOM", "SBOM Version", "Project", "Description", "Product", "Version", "License"]
            )
        else:
            sbom_output.set_headings(
            ["SBOM", "Project", "Description", "Product", "Version", "License"]
        )
        sbom_output.generate_output(
            sbom_db.find_module(args["module"], args["project"], args["history"])
        )
    elif args["list"]:
        # List contents of database
        LOGGER.debug("List contents")
        if args["list"] == "sbom":
            if args["history"]:
                sbom_output.set_headings(
                    [
                        "SBOM",
                        "SBOM Version",
                        "Project",
                        "Description",
                        "SBOM Type",
                        "Record Count",
                        "Date Added",
                    ]
                )
            else:
                sbom_output.set_headings(
                    [
                        "SBOM",
                        "Project",
                        "Description",
                        "SBOM Type",
                        "Record Count",
                        "Last Updated",
                    ]
                )
        elif args["list"] == "module":
            if args["history"]:
                sbom_output.set_headings(["Project", "file Version", "Product", "Version", "License"])
            else:
                sbom_output.set_headings(["Project", "Product", "Version", "License"])
        else:
            if args["history"]:
                sbom_output.set_headings(
                    ["SBOM", "SBOM Version", "Project", "Description", "Product", "Version", "License"]
                )
            else:
                sbom_output.set_headings(
                    ["SBOM", "Project", "Description", "Product", "Version", "License"]
                )
        sbom_output.generate_output(sbom_db.list_entries(args["list"], args["project"], args["history"]))
    elif args["scan"]:
        # Scan for vulnerabilities
        LOGGER.info("Scan system for vulnerabilities")
        project_files = sbom_store.get_project(args["project"])
        # Check that files exist for project
        for project_file in project_files:
            # Ensure that file used is in SPDX format
            filename_to_scan = sbom_store.get_file(project_file, args["project"])
            if not filename_to_scan.endswith(".spdx"):
                # Use spdx file
                filename_to_scan = os.path.splitext(filename_to_scan)[0] + ".spdx"
            sbom_scan = SBOMScanner(filename_to_scan, sbom_config.get_section("scan"))
            sbom_scan.scan()
    else:
        LOGGER.debug("Nothing to do")
    return 0


if __name__ == "__main__":
    sys.exit(main())
