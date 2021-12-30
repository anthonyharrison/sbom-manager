# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

"""
Management of access to database
"""

import datetime
import logging
import os
import sqlite3

from sbom_manager.log import LOGGER

logging.basicConfig(level=logging.DEBUG)

# database defaults
DISK_LOCATION_DEFAULT = os.path.join(os.path.expanduser("~"), ".cache", "sbom_manager")
DBNAME = "sbom.db"


class SBOMDB:
    """
    Manages SBOM data in a database.
    """

    def __init__(self):

        # set up the db path
        self.dbpath = os.path.join(DISK_LOCATION_DEFAULT, DBNAME)
        self.logger = LOGGER.getChild(self.__class__.__name__)
        LOGGER.debug(f"Database location {self.dbpath}")
        self.connection = None

    def initialise_database(self):
        """Initialize db tables used for storing sbom data"""
        self.db_open()
        cursor = self.connection.cursor()
        # CREATE TABLE IF NOT EXISTS sbom_file (
        file_data_create = """
        CREATE TABLE sbom_file (
            file_id INTEGER PRIMARY KEY,
            filename TEXT NOT NULL,
            file_version TEXT,
            project TEXT,
            description TEXT,
            sbom_type TEXT,
            add_date TIMESTAMP
        )
        """
        sbom_data_create = """
        CREATE TABLE IF NOT EXISTS sbom_data (
            file_id INTEGER,
            vendor TEXT,
            product TEXT,
            version TEXT,
            FOREIGN KEY(file_id) REFERENCES sbom_file(file_id)
        )
        """
        sbom_audit = """
        CREATE TABLE IF NOT EXISTS sbom_audit (
            record_id INTEGER PRIMARY KEY,
            audit_date TIMESTAMP,
            command TEXT
        )
        """

        cursor.execute("DROP TABLE IF EXISTS sbom_file")
        cursor.execute("DROP TABLE IF EXISTS sbom_data")
        cursor.execute("DROP TABLE IF EXISTS sbom_audit")
        cursor.execute(file_data_create)
        cursor.execute(sbom_data_create)
        cursor.execute(sbom_audit)
        LOGGER.debug("Database initialised")
        self.connection.commit()
        self.db_close()
        self.audit_record("initialise")

    def audit_record(self, command_line):
        """Function that adds record to audit log"""
        self.db_open()
        cursor = self.connection.cursor()
        insert_audit_record = """
        INSERT or REPLACE INTO sbom_audit(
            audit_date,
            command
        )
        VALUES (?, ?)
        """
        # Insert audit entry
        cursor.execute(
            insert_audit_record,
            [
                datetime.datetime.now().strftime("%H:%M:%S %d-%b-%Y"), 
                command_line
            ],
        )
        self.connection.commit()
        self.db_close()

    def add_file(self, filename, description, project, sbom_type, sbom_data):
        """Function that populates the database with SBOM file"""
        self.db_open()
        cursor = self.connection.cursor()

        insert_file = """
        INSERT or REPLACE INTO sbom_file(
            filename,
            project,
            description,
            sbom_type,
            add_date
        )
        VALUES (?, ?, ?, ?, ?)
        """
        insert_sbom = """
        INSERT or REPLACE INTO sbom_data(
            file_id,
            vendor,
            product,
            version
        )
        VALUES (?, ?, ?, ?)
        """
        # Insert file entry
        cursor.execute(
            insert_file,
            [
                os.path.basename(filename),
                project,
                description,
                sbom_type,
                datetime.datetime.now().strftime("%H:%M:%S %d-%b-%Y"),
            ],
        )
        # Find id of last entry to reference with SBOM data
        file_id = cursor.lastrowid
        # Insert SBOM data records
        for data in sbom_data:
            cursor.execute(
                insert_sbom, [file_id, data["vendor"], data["product"], data["version"]]
            )
        self.connection.commit()
        self.db_close()
        self.audit_record("add")

    def find_module(self, module, project):
        """Function that searches for module in database"""
        self.db_open()
        cursor = self.connection.cursor()
        find_module_query = """
        SELECT filename, project, description, vendor, product, version
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id AND product = ?
        """
        query_params = [module]
        # Handle optional project parameter
        if project != "":
            query_params.append(project)
            find_module_query = find_module_query + " AND project = ?"
        cursor.execute(find_module_query, query_params)
        results = cursor.fetchall()
        self.db_close()
        self.audit_record("find")
        return results

    def list_entries(self, contents):
        """Function that extracts entries from database"""
        self.db_open()
        cursor = self.connection.cursor()
        list_sbom = """
        SELECT filename, project, description, sbom_type, add_date FROM sbom_file
        """
        list_module = """
        SELECT vendor, product, version FROM sbom_data
        """
        list_all = """
        SELECT filename, project, description, vendor, product, version
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        """
        if contents == "sbom":
            cursor.execute(list_sbom)
        elif contents == "module":
            cursor.execute(list_module)
        else:
            cursor.execute(list_all)
        results = cursor.fetchall()
        self.db_close()
        self.audit_record("list")
        return results

    def db_open(self):
        """Opens connection to sqlite database."""
        if not os.path.exists(DISK_LOCATION_DEFAULT):
            os.makedirs(DISK_LOCATION_DEFAULT)

        if not self.connection:
            self.connection = sqlite3.connect(self.dbpath)
            LOGGER.debug("Database opened")

    def db_close(self):
        """Closes connection to sqlite database."""
        if self.connection:
            self.connection.close()
            self.connection = None
            LOGGER.debug("Database closed")
