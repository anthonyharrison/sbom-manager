# Copyright (C) 2021 Anthony Harrison
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

    # Ensure project name doesn't have a space (to ensure directory name is valid)
    if ' ' in args["project"]:
        args["project"] = args["project"].replace(' ','_')
        LOGGER.info(f"Renaming project name to {args['project']}")

    # Add output handler
    sbom_output = SBOMOutput(args["output_file"], args["format"])

    # Setup store manager
    sbom_store = SBOMStore()

    # Do something
    if args["initialise"]:
        # Initialise everything
        LOGGER.debug("Initialise system")
        sbom_db.initialise_database()
        sbom_store.initialise_store()
    elif args["add_file"]:
        # Process SBOM file
        LOGGER.debug(f"Add SBOM {args['add_file']}")
        sbom_data = sbom_input.process_file(args["add_file"])
        if sbom_data is not None:
            # Add entry to database
            sbom_db.add_file(
                args["add_file"], desc, args["project"], args["sbom_type"], sbom_data
            )
            # And store file
            LOGGER.debug(f"Store {args['add_file']}")
            sbom_store.store(args["add_file"], args["project"])
            if args["sbom_type"] != "spdx":
                # Generate SPDX format file
                sbom_gen = SBOMGenerator()
                sbom_gen.generate_spdx(args["project"], sbom_data)
                spdx_filename = (
                    os.path.splitext(os.path.basename(args["add_file"]))[0] + ".spdx"
                )
                spdx_filegen = OutputManager("file", spdx_filename)
                for line in sbom_gen.get_spdx():
                    spdx_filegen.file_out(line)
                spdx_filegen.close()
                sbom_store.store(spdx_filename, args["project"], delete = True)
    elif args["module"]:
        # Search for module
        LOGGER.debug(f"Search for module {args['module']}")
        sbom_output.set_headings(
            ["Filename", "Project", "Description", "Vendor", "Product", "Version"]
        )
        sbom_output.generate_output(
            sbom_db.find_module(args["module"], args["project"])
        )
    elif args["list"]:
        # List contents of database
        LOGGER.debug("List contents")
        if args["list"] == "sbom":
            sbom_output.set_headings(
                ["Filename", "Project", "Description", "SBOM Type", "Record Count", "Date Added"]
            )
        elif args["list"] == "module":
            sbom_output.set_headings(["Product", "Version"])
        else:
            sbom_output.set_headings(
                ["Filename", "Project", "Description", "Product", "Version"]
            )
        sbom_output.generate_output(sbom_db.list_entries(args["list"], args["project"]))
    elif args["scan"]:
        # Scan for vulnerabilities
        LOGGER.info("Scan system for vulnerabilities")
        project_files = sbom_store.get_project(args["project"])
        # Check that files exist for project
        if len(project_files) > 0:
            # Only scan latest file. Ensure that file used is in SPDX format
            filename_to_scan = sbom_store.get_file(project_files[-1], args["project"])
            if not filename_to_scan.endswith(".spdx"):
                # Use spdx file
                filename_to_scan = os.path.splitext(filename_to_scan)[0] + ".spdx"
            LOGGER.info(f"Scan {filename_to_scan}")
            sbom_scan = SBOMScanner(filename_to_scan, sbom_config.get_section("scan"))
            sbom_scan.scan()
    return 0
