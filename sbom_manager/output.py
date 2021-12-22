# Copyright (C) 2021 Anthony Harrison
# SPDX-License-Identifier: MIT

""" Set up Output Formatting """


class SBOMOutput:
    """
    Output manager for SBOM data.
    """

    WIDTH = 15
    PADDING = " "

    def __init__(self, destination=None):
        self.destination = destination
        self.headings = None

    def set_headings(self, headings):
        # Headings to be used in output
        # Headings is a list of fields
        self.headings = headings

    def format_element(self, element):
        # if element larger than maximum width
        if len(element) > self.WIDTH:
            return element[: self.WIDTH - 3] + "..."
        else:
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

    def console_output(self, data):
        # Send output to console
        print(data)

    def csv_output(self, data):
        # Send output to csv file
        pass

    def generate_output(self, dataset):
        if self.headings is not None:
            hdr = self.format_data(self.headings)
            self.console_output(hdr)
            self.console_output("=" * len(hdr))
        for d in dataset:
            self.console_output(self.format_data(d))
