# Copyright 2019 Splunk Inc. All rights reserved.

"""
### JSON file standards
"""
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import splunk_appinspect
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


logger = logging.getLogger(__name__)
report_display_order = 13


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.1.0")
def check_validate_json_data_is_well_formed(app: "App", reporter: "Reporter") -> None:
    """Check that all JSON files are well formed."""

    for directory, file_name, _ in app.iterate_files(types=[".json"]):
        current_file_relative_path = Path(directory, file_name)
        current_file_full_path = app.get_filename(directory, file_name)

        with open(current_file_full_path, "r", encoding="utf-8") as f:
            current_file_contents = f.read()

        try:
            json.loads(current_file_contents)
        except (TypeError, ValueError) as error:
            reporter_output = f"Malformed JSON file found. File: {current_file_relative_path}  Error: {str(error)}"
            reporter.fail(reporter_output, current_file_relative_path)
