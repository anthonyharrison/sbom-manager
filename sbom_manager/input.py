# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up SBOM Input processing """

import json
import os.path
import re

import defusedxml.ElementTree as ET

from sbom_manager.log import LOGGER


class SBOMInput:
    """
    Input manager for SBOM data.
    """

    def __init__(self, sbom_type):
        self.sbom_type = sbom_type
        self.sbom_process = {
            "spdx": self.process_spdx_file,
            "spdx_json": self.process_spdx_json_file,
            "cyclonedx": self.process_cyclonedx_file,
            "cyclonedx_json": self.process_cyclonedx_json_file,
            "csv": self.process_csv_file,
            "dir": self.process_directory_file,
        }
        self.logger = LOGGER.getChild(self.__class__.__name__)

    def process_file(self, filename):
        sbom_data = None
        # Only process if file exists
        if os.path.exists(filename):
            LOGGER.debug(f"Processing {filename} - type {self.sbom_type}")
            sbom_data = self.sbom_process[self.sbom_type](filename)
        return sbom_data

    def process_spdx_file(self, filename):
        # Process SPDX Tag file
        modules = []
        with open(filename) as spdx_file:
            lines = spdx_file.readlines()
        product = ""
        vendor = ""
        for line in lines:
            line_elements = line.split(":")
            if line_elements[0] == "PackageName":
                product = line_elements[1].strip().rstrip("\n")
                version = None
            if line_elements[0] == "PackageVersion":
                version = line_elements[1].strip().rstrip("\n")
                version = version.split("-")[0]
                version = version.split("+")[0]
                if product != "" and version != "":
                    modules.append(
                        {"vendor": vendor, "product": product, "version": version}
                    )
                    LOGGER.debug(f"Add {product} {version}")
                    product = ""  # Reset
        return modules

    def process_spdx_json_file(self, filename):
        # Process SPDX JSON file
        modules = []
        data = json.load(open(filename))
        for d in data["packages"]:
            product = d["name"]
            version = d["versionInfo"]
            modules.append({"vendor": "", "product": product, "version": version})
            LOGGER.debug(f"Add {product} {version}")
        return modules

    def process_cyclonedx_file(self, filename):
        # Process CycloneDX XML BOM file
        modules = []
        tree = ET.parse(filename)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        vendor = ""
        for components in root.findall(schema + "components"):
            for component in components.findall(schema + "component"):
                # Only if application or library....
                if component.attrib["type"] in ["library", "application"]:
                    component_name = component.find(schema + "name")
                    product = component_name.text
                    component_version = component.find(schema + "version")
                    version = component_version.text
                    if product is not None and version is not None:
                        modules.append(
                            {
                                "vendor": vendor,
                                "product": product,
                                "version": version,
                            }
                        )
                        LOGGER.debug(f"Add {product} {version}")
        return modules

    def process_cyclonedx_json_file(self, filename):
        # Process CycloneDX JSON file
        modules = []
        data = json.load(open(filename))
        for d in data["components"]:
            if d["type"] in ["application", "library"]:
                product = d["name"]
                version = d["version"]
                modules.append({"vendor": "", "product": product, "version": version})
                LOGGER.debug(f"Add {product} {version}")
        return modules

    def process_csv_file(self, filename):
        # Process CSV file
        modules = []
        with open(filename) as csv_file:
            lines = csv_file.readlines()
        for line in lines:
            # Ignore comment line indicated by #
            if line[0] != "#":
                line_elements = line.strip().rstrip("\n").split(",")
                # Ignore blank lines
                if len(line_elements) == 3:
                    modules.append(
                        {
                            "vendor": line_elements[0].strip(),
                            "product": line_elements[1].strip(),
                            "version": line_elements[2].strip(),
                        }
                    )
                    LOGGER.debug(
                        f"Add {line_elements[1].strip()} {line_elements[2].strip()}"
                    )
        return modules

    def process_directory_file(self, filename):
        # Process directory file
        modules = []
        with open(filename) as dir_file:
            lines = dir_file.readlines()
        for line in lines:
            # Ignore comment line indicated by #
            if line[0] != "#":
                line_element = line.strip().rstrip("\n")
                # Extract the filename (without extension) - make lowercase
                item = os.path.splitext(os.path.basename(line_element))[0].lower()
                # Parse line PRODUCT-VERSION[-Other]?. If pattern not followed ignore...
                # Version assumed to start with digit. Therefore find first digit
                product_version = re.search(r"-\d[.\d]*[a-z0-9]*", item)
                if product_version is not None:
                    # Extract version from item (don't store initial '-' separator)
                    version = product_version.group(0)[1:]
                    # Extract product from item
                    product = item[: product_version.start()]
                    if product != "" and version != "":
                        new_module = {
                            "vendor": "",
                            "product": product.strip(),
                            "version": version.strip(),
                        }
                        # Ensure that entry not duplicated
                        if new_module not in modules:
                            modules.append(new_module)
                            LOGGER.debug(f"Add {product} {version}")
        return modules
