# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up Output Formatting """

from sbom_manager.log import LOGGER


class OutputManager:
    """Helper class for managing output to file and console."""

    def __init__(self, out_type="file", filename=None):
        self.out_type = out_type
        self.filename = filename
        if self.out_type == "file":
            self.file_handle = open(filename, "w")
        else:
            self.file_handle = None

    def close(self):
        if self.out_type == "file":
            self.file_handle.close()

    def file_out(self, message):
        self.file_handle.write(message + "\n")

    def console_out(self, message):
        print(message)

    def show(self, message):
        if self.out_type == "file":
            self.file_out(message)
        else:
            self.console_out(message)


class SBOMOutput:
    """Output manager for SBOM data."""

    WIDTH = 20
    PADDING = " "

    def __init__(self, filename="console", output_format="console"):
        self.filename = filename
        self.headings = None
        self.logger = LOGGER.getChild(self.__class__.__name__)
        self.output_format = output_format
        self.format_process = {
            "console": self.format_data,
            "csv": self.format_csv_data,
        }
        self.type = "console"
        if self.filename != "console":
            self.type = "file"
        self.output_manager = OutputManager(self.type, self.filename)

    def set_headings(self, headings):
        # Headings to be used in output. Headings are a list of fields
        self.headings = headings

    def format_element(self, element):
        # If element larger than maximum width, curtail element and add '...'
        if len(str(element)) > self.WIDTH:
            return str(element)[: self.WIDTH - 3] + "..."
        return element

    def format_data(self, data):
        # Return formatted line
        formatted_data = ""
        for entry in data:
            formatted_data = (
                formatted_data
                + f"{self.format_element(entry) :{self.PADDING}<{self.WIDTH}}"
                + " "
            )
        return formatted_data

    def format_csv_data(self, data):
        # Return csv formatted line
        formatted_data = ""
        for entry in data:
            formatted_data = formatted_data + entry + ","
        # Don't return last character (extra ,)
        return formatted_data[:-1]

    def send_output(self, data):
        self.output_manager.show(data)

    def generate_output(self, dataset):
        if len(dataset) > 0:
            if self.headings is not None:
                hdr = self.format_process[self.output_format](self.headings)
                self.send_output(hdr)
                if self.output_format == "console":
                    self.send_output("=" * len(hdr))
            for data_item in dataset:
                self.send_output(self.format_process[self.output_format](data_item))
        else:
            self.send_output("No data found")
        self.output_manager.close()
