# Copyright 2019 Splunk Inc. All rights reserved.

"""
Helper module for documentation links generation
"""
from splunk_appinspect.splunk_defined_conf_file_list import LATEST_CONFS


class DocumentationLinks:
    """Represents links to Splunk Docs sites."""

    @staticmethod
    def get_splunk_docs_link(conf_file: str) -> str:
        """Returns the Splunk Doc link for a conf file."""
        if conf_file in LATEST_CONFS:
            uri_path = conf_file.replace(".", "")
            return "https://docs.splunk.com/Documentation/Splunk/latest/Admin/{}".format(uri_path)

        return f"Unable to find doc link for {conf_file}"
