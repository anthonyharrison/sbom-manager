# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up Logging"""
import logging


# A log filter to filter out logs based on filter level
# Any log above and equal the specified level will not be logged
class LevelFilter(logging.Filter):
    def __init__(self, level):
        super().__init__()
        self.level = level

    def filter(self, record):
        return record.levelno < self.level

logging.basicConfig(
    level="INFO",
    format="%(asctime)s %(levelname)-8s %(name)s - %(message)s",
    datefmt="[%X]",
)

# Add the handlers to the root logger
root_logger = logging.getLogger()

LOGGER = logging.getLogger(__package__)
LOGGER.setLevel(logging.INFO)
