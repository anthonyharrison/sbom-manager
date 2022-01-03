# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up Config file processing """
import configparser

from sbom_manager.log import LOGGER


class SBOMConfig:
    """
    Config handler for SBOM manager.
    """

    def __init__(self, filename):
        self.config = configparser.ConfigParser()
        self.configs = filename
        if filename is not "":
            self.configs = self.config.read(filename)
        self.logger = LOGGER.getChild(self.__class__.__name__)

    def get_sections(self):
        if self.configs != "":
            return self.config.sections()
        return []
        
    def get_section(self, name):
        if self.configs != "":
            return self._ConfigSectionMap(name)
        return {}

    # Helper function from https://wiki.python.org/moin/ConfigParserExamples
    def _ConfigSectionMap(self, section):
        dict1 = {}
        options = self.config.options(section)
        for option in options:
            try:
                dict1[option] = self.config.get(section, option)
                if dict1[option] == -1:
                    print("skip: %s" % option)
            except:
                print("exception on %s!" % option)
                dict1[option] = None
        return dict1
