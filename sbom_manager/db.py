# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: MIT

"""
Management of access to database
"""

import datetime
import logging
import os
import shutil
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
            file_version INTEGER,
            project TEXT,
            description TEXT,
            sbom_type TEXT,
            record_count TEXT,
            add_date TIMESTAMP
        )
        """
        sbom_data_create = """
        CREATE TABLE IF NOT EXISTS sbom_data (
            file_id INTEGER,
            vendor TEXT,
            product TEXT,
            version TEXT,
            license TEXT,
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
            [datetime.datetime.now().strftime("%H:%M:%S %d-%b-%Y"), command_line],
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
            file_version,
            project,
            description,
            sbom_type,
            add_date
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """
        update_file_entry = """
        UPDATE sbom_file
        SET record_count = ?
        WHERE file_id = ?
        """
        insert_sbom = """
        INSERT or REPLACE INTO sbom_data(
            file_id,
            vendor,
            product,
            version,
            license
        )
        VALUES (?, ?, ?, ?, ?)
        """
        find_project = """
        SELECT count(project) FROM sbom_file
        WHERE project = ?
        """
        # Find project
        cursor.execute(
            find_project,
            [
                project
            ]
        )
        file_version = cursor.fetchone()
        # Insert file entry
        cursor.execute(
            insert_file,
            [
                os.path.basename(filename),
                file_version[0]+1,
                project,
                description,
                sbom_type,
                datetime.datetime.now().strftime("%H:%M:%S %d-%b-%Y"),
            ],
        )
        # Find id of last entry to reference with SBOM data
        file_id = cursor.lastrowid
        # Insert SBOM data records. Maintain count of records inserted
        record_count = 0
        for data in sbom_data:
            license = data["license"]
            if license == "":
                license = "NOASSERTION"
            # Make sure all entries are lowercase
            cursor.execute(
                insert_sbom,
                [
                    file_id,
                    data["vendor"].lower(),
                    data["product"].lower(),
                    data["version"].lower(),
                    license,
                ],
            )
            record_count = record_count + 1
        update_params = [record_count, file_id]
        cursor.execute(update_file_entry, update_params)
        self.connection.commit()
        self.db_close()
        self.audit_record("add")
        return file_version[0]+1

    def find_module(self, module, project, history = False):
        """Function that searches for module in database"""
        self.db_open()
        cursor = self.connection.cursor()
        find_module = """
        SELECT filename, project as P, description, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        AND file_version = (select max(file_version) from sbom_file where project = P)
        AND product LIKE ?
        """
        find_module_history = """
        SELECT filename, file_version, project, description, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id AND product LIKE ?
        """
        find_module_query = find_module_history if history else find_module
        order_query = " ORDER BY product ASC, project ASC, file_version DESC"
        query_params = ["%" + module + "%"]
        # Handle optional project parameter
        if project != "":
            query_params.append(project)
            find_module_query = find_module_query + " AND project = ?"
        LOGGER.debug(f"Query: {find_module_query}{order_query} {query_params}")
        cursor.execute(find_module_query + order_query, query_params)
        results = cursor.fetchall()
        self.db_close()
        self.audit_record("find")
        return results

    def list_entries(self, contents, project, history = False, version = None):
        """Function that extracts entries from database"""
        self.db_open()
        cursor = self.connection.cursor()
        list_sbom = """
        SELECT filename, project as P, description, sbom_type,
        record_count, add_date FROM sbom_file
        """
        list_sbom_history = """
        SELECT filename, file_version, project as P, description, sbom_type,
        record_count, add_date FROM sbom_file
        """
        list_project_module = """
        SELECT project as P, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        """
        list_project_module_history = """
        SELECT project as P, file_version, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        """
        list_all = """
        SELECT filename, project as P, description, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        """
        list_all_history = """
        SELECT filename, file_version, project as P, description, product, version, license
        FROM sbom_file, sbom_data
        WHERE sbom_file.file_id = sbom_data.file_id
        """
        latest_all = """
        file_version = (select max(file_version) from sbom_file where project = P)
        """
        # latest_query = latest_project if project else latest_all
        latest_query = latest_all
        if contents == "sbom":
            list_query = list_sbom_history if history else list_sbom
            list_query_prefix = " WHERE"
            order_query = " ORDER BY project ASC, file_version DESC"
        elif contents == "module":
            list_query = list_project_module_history if history else list_project_module
            list_query_prefix = " AND "
            order_query = " ORDER BY product ASC, project ASC, file_version DESC"
        else:
            list_query = list_all_history if history else list_all
            list_query_prefix = " AND"
            order_query = " ORDER BY project ASC, file_version DESC"
        query_params = []
        # Handle history parameter
        if not history and version is None:
            list_query= list_query + list_query_prefix + latest_all
            list_query_prefix = " AND"
        # Handle optional project parameter
        if project != "":
            query_params.append(project)
            list_query = list_query + list_query_prefix + " project = ?"
        if version is not None:
            query_params.append(version)
            list_query = list_query + list_query_prefix + " file_version = ?"
        LOGGER.debug(f"Query: {list_query}{order_query} {query_params}")
        cursor.execute(list_query + order_query, query_params)
        results = cursor.fetchall()
        self.db_close()
        self.audit_record("list")
        return results

    def check_db_exists(self):
        return os.path.isfile(self.dbpath) and (os.path.getsize(self.dbpath) > 100)

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

    def copy_db(self, filename, export=True):
        self.db_close()
        if export:
            self.audit_record("Export database")
            LOGGER.debug(f"Database export to {filename}")
            shutil.copy(self.dbpath, filename)
        else:
            self.audit_record("Import database")
            LOGGER.debug(f"Database import from {filename}")
            shutil.copy(filename, self.dbpath)