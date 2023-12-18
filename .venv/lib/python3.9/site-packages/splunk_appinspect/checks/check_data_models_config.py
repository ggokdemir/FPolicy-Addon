# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Data model files and configurations

Data models are defined in a **datamodels.conf** file in the **/default** directory of the app. For more, see [About data models](http://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutdatamodels) and [datamodels.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Datamodelsconf).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect
from splunk_appinspect.check_messages import CheckMessage, FailMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk import normalizeBoolean

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.reporter import Reporter


report_display_order = 25
logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT)
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=1)
def check_validate_data_models_conf_file_in_correct_locations(app: "App", reporter: "Reporter") -> None:
    """Check that when using data models, the `datamodels.conf` file only exists
    in the default directory.
    """
    # Gathers all datamodels.conf files
    datamodels_file_path = Path("default", "datamodels.conf")

    for relative_file_path, _ in app.get_filepaths_of_files(filenames=["datamodels"], types=[".conf"]):
        if relative_file_path != datamodels_file_path:
            reporter_output = (
                "A datamodels.conf file was found outside of the default directory." f" File: {relative_file_path}"
            )
            reporter.fail(reporter_output, relative_file_path)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT)
@splunk_appinspect.cert_version(min="1.1.0")
def check_validate_no_missing_json_data(app: "App", reporter: "Reporter") -> None:
    """Check that each stanza in
    [datamodels.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Datamodelsconf)
    has a matching JSON file in `default/data/models/`.
    """
    data_model_location = "default/data/models"
    for relative_file_path, _ in app.get_filepaths_of_files(filenames=["datamodels"], types=[".conf"]):
        config = app.get_config(name=relative_file_path, dir=".")

        for section in config.sections():
            json_filename = f"{section.name}.json"
            does_matching_json_file_exist = app.file_exists(data_model_location, json_filename)
            if not does_matching_json_file_exist:
                reporter_output = (
                    "There is no corresponding JSON file for "
                    f"[{section.name}] in {relative_file_path}."
                    f"File: {relative_file_path}, Line: {section.lineno}."
                )
                reporter.fail(reporter_output, relative_file_path, section.lineno)


class CheckForDatamodelAcceleration(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_datamodel_acceleration",
                description="""Check that the use of accelerated data models do not occur. If data model 
                        acceleration is required, developers should provide directions in documentation
                        for how to accelerate data models from within the Splunk Web GUI.
                        
                        [data model acceleration](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Acceleratedatamodels)""",
                cert_min_version="1.5.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
                depends_on_config=("datamodels",),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        datamodels_config = config["datamodels"]

        # check if acceleration=true is set in default stanza
        is_default_stanza_accelerated = False
        if datamodels_config.has_section("default") and datamodels_config.has_option("default", "acceleration"):
            accelerated = datamodels_config.get("default", "acceleration")
            is_default_stanza_accelerated = normalizeBoolean(accelerated)

        for section in config["datamodels"].sections():
            is_accelerated = False
            lineno = None
            if section.name != "default":
                if section.has_option("acceleration"):
                    if normalizeBoolean(section.get_option("acceleration").value):
                        is_accelerated = True
                        lineno = section.get_option("acceleration").lineno

                elif is_default_stanza_accelerated:
                    is_accelerated = True
                    lineno = datamodels_config.get_section("default").get_option("acceleration").lineno

                if is_accelerated:
                    yield FailMessage(
                        "Data model acceleration was detected in `default/datamodels.conf` for stanza ",
                        file_name=datamodels_config.get_relative_path(),
                        line_number=lineno,
                        remediation=f"Set `acceleration = false` for [{section.name}]."
                        "If data model acceleration is required, please provide users with "
                        "guidance on how to enable data model acceleration from within the "
                        "Splunk Web GUI. ",
                    )
                else:
                    yield WarningMessage(
                        f"Data model [{section.name}] was detected in this app and can eat disk space. ",
                        file_name=datamodels_config.get_relative_path(),
                        line_number=lineno,
                    )
