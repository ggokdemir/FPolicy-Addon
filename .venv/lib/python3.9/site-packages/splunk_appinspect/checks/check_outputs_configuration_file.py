# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Outputs.conf file standards

Ensure that the **outputs.conf** file located in the **/default** folder of the app is well formed and valid. For more, see [outputs.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Outputsconf).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk import normalizeBoolean

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


class CheckIfOutputsConfExists(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_if_outputs_conf_exists",
                description="Check that forwarding enabled in 'outputs.conf' is failed in cloud",
                cert_min_version="1.5.4",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
                depends_on_config=(("outputs",)),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        option_name = "disabled"
        outputs_conf = config["outputs"]
        file_path = config["outputs"].get_relative_path()
        section_names = outputs_conf.section_names()
        if section_names:
            # for this situation, not section_names
            # an outputs.conf has only global settings outside of any stanza is covered by check_no_default_stanzas
            for section in section_names:
                if not outputs_conf.has_option(section, option_name):
                    yield FailMessage(
                        f"From {file_path}, output is enabled by default." f" This is prohibited in Splunk Cloud. ",
                        file_name=file_path,
                    )
                else:
                    is_disabled = normalizeBoolean(outputs_conf.get(section, option_name))
                    if not is_disabled:
                        lineno = outputs_conf.get_section(section).get_option(option_name).lineno
                        yield FailMessage(
                            f"From {file_path}, output is enabled with 'disabled = False'."
                            " This is prohibited in Splunk Cloud. "
                            f" Stanza: [{section}]. ",
                            file_name=file_path,
                            line_number=lineno,
                        )
