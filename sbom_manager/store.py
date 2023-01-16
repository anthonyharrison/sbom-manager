# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up File Storage """

import os
import os.path
import shutil

from sbom_manager.log import LOGGER

# File store defaults
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "sbom_manager")


class SBOMStore:
    """
    File storage management for SBOM data.
    """

    def __init__(self, disk_location):
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.location = DISK_LOCATION_DEFAULT
        if len(disk_location) > 0:
            # User specified storage location
            self.location = disk_location["location"]
        LOGGER.debug(f"Storage location: {self.location}")

    def store(self, filename, project, delete=False, version=1):
        # Check project store exists. If not create it
        project_location = os.path.join(self.location, project)
        if not os.path.isdir(project_location):
            LOGGER.debug(f"Creating file store for {project}")
            os.mkdir(project_location)
        LOGGER.debug(f"Copying {filename} to store")
        dest_file = f"{version}_{os.path.basename(filename)}"
        destination = os.path.join(project_location, dest_file)
        shutil.copy(filename, destination)
        if delete:
            LOGGER.debug(f"Deleting {filename}")
            os.remove(filename)

    def get_file(self, filename, project):
        project_location = os.path.join(self.location, project)
        file_location = os.path.join(project_location, filename)
        if not os.path.exists(file_location):
            LOGGER.debug(f"File {filename} not found for {project}")
            return None
        return file_location

    def get_project(self, project):
        # Check project store exists
        project_location = os.path.join(self.location, project)
        if not os.path.isdir(project_location):
            LOGGER.debug(f"No files for {project}")
            return []
        project_list = []
        # Get list of files (most recent first). Must be in directory for sort to work.
        os.chdir(project_location)
        for file_path in sorted(os.listdir("."), key=os.path.getmtime, reverse=True):
            LOGGER.debug(f"Processing file {file_path}")
            # Ignore . files
            if not file_path.startswith("."):
                project_list.append(file_path)
        # Return list of files
        return project_list

    def initialise_store(self):
        for file_path in os.listdir(self.location):
            full_path = os.path.join(self.location, file_path)
            LOGGER.debug(f"Processing file {file_path} - {os.path.isdir(full_path)}")
            # Ignore . files
            if not file_path.startswith(".") and os.path.isdir(full_path):
                LOGGER.debug(f"Deleting project directory {file_path}")
                shutil.rmtree(full_path)
