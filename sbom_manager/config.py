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
        if filename != "":
            self.configs = self.config.read(filename)
        self.logger = LOGGER.getChild(self.__class__.__name__)

    def get_sections(self):
        if self.configs != "":
            return self.config.sections()
        return []

    def get_section(self, name):
        if self.configs != "":
            return self._config_section_map(name)
        return {}

    # Helper function from https://wiki.python.org/moin/ConfigParserExamples
    def _config_section_map(self, section):
        section_dict = {}
        options = self.config.options(section)
        for option in options:
            section_dict[option] = self.config.get(section, option)
        return section_dict
