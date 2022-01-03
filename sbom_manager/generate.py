# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" SBOM Generator """

import uuid
from datetime import datetime

from sbom_manager.version import VERSION


class SPDXGenerator:
    """
    Generate SPDX Tag/Value SBOM.
    """

    SPDX_VERSION = "SPDX-2.2"
    DATA_LICENCE = "CC0-1.0"
    SPDX_NAMESPACE = "http://spdx.org/spdxdocs/"
    SPDX_LICENCE_VERSION = "3.9"
    SPDX_PROJECT_ID = "SPDXRef-DOCUMENT"
    NAME = "SPDX_Generator"

    def __init__(self):
        self.doc = []
        self.package_id = 0

    def show(self, message):
        self.doc.append(message)

    def getBOM(self):
        return self.doc

    def generateTag(self, tag, value):
        self.show(tag + ": " + value)

    def generateTime(self):
        # Generate data/time label in format YYYY-MM-DDThh:mm:ssZ
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    def generateDocumentHeader(self, project_name):
        # SPDX Document Header
        self.generateTag("SPDXVersion", self.SPDX_VERSION)
        self.generateTag("DataLicense", self.DATA_LICENCE)
        self.generateTag("SPDXID", self.SPDX_PROJECT_ID)
        # Project name mustn't have spaces in. Covert spaces to '-'
        self.generateTag("DocumentName", project_name.replace(" ", "-"))
        self.generateTag(
            "DocumentNamespace",
            self.SPDX_NAMESPACE
            + project_name.replace(" ", "-")
            + "-"
            + str(uuid.uuid4()),
        )
        self.generateTag("LicenseListVersion", self.SPDX_LICENCE_VERSION)
        self.generateTag("Creator: Tool", self.NAME + "-" + VERSION)
        self.generateTag("Created", self.generateTime())
        self.generateTag(
            "CreatorComment",
            "<text>This document has been automatically generated.</text>",
        )
        return self.SPDX_PROJECT_ID

    def generatePackageDetails(self, package, id, version, parent_id):
        self.generateTag("\nPackageName", package)
        package_id = "SPDXRef-Package-" + str(id)
        self.generateTag("SPDXID", package_id)
        self.generateTag("PackageVersion", version)
        self.generateTag("PackageDownloadLocation", "NONE")
        self.generateTag("FilesAnalyzed", "false")
        self.generateTag("PackageLicenseConcluded", "NOASSERTION")
        self.generateTag("PackageLicenseDeclared", "NOASSERTION")
        self.generateTag("PackageCopyrightText", "NOASSERTION")
        self.generateRelationship(parent_id, package_id, " CONTAINS ")

    def generateRelationship(self, from_id, to_id, relationship_type):
        self.generateTag("\nRelationship", from_id + relationship_type + to_id)


class SBOMGenerator:
    """
    Simple SBOM File Generator.
    """

    def __init__(self):
        self.bom = SPDXGenerator()

    def generate_spdx(self, project_name, packages):
        project_id = self.bom.generateDocumentHeader(project_name)
        self.bom.show("\n\n##### Package")
        # Get list of packages
        id = 1
        for package in packages:
            self.bom.generatePackageDetails(
                package["product"], id, package["version"], project_id
            )
            id = id + 1

    def show_spdx(self):
        for line in self.bom.getBOM():
            print(line)

    def get_spdx(self):
        return self.bom.getBOM()
