# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Victoria-specific config replication checks

This group includes checks for configs which may not be replicated to indexers as expected in Splunk Cloud Victoria.
"""
from __future__ import annotations

import os
import re
from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage, NotApplicableMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


class CheckForIndexerSyncedConfigs(Check):
    INDEXER_SYNCED_LOCALS = (
        "app",
        "indexes",
        "props",
        "transforms",
        "limits",
        "inputs",
        "outputs",
    )
    SELF_SERVICE_CONFIGS = ("inputs", "outputs", "limits")

    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_indexer_synced_configs",
                description="Check that the app does not contain configs which might be intended "
                "for indexers, but won't be synced there on Victoria.",
                depends_on_config=self.INDEXER_SYNCED_LOCALS + self.SELF_SERVICE_CONFIGS,
                cert_min_version="2.34.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_default_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for conf_file in self.SELF_SERVICE_CONFIGS:
            if conf_file in config:
                path_in_app = config[conf_file].get_relative_path()
                yield WarningMessage(
                    f"{path_in_app} will not be synced to indexers in Victoria.",
                    file_name=config[conf_file].get_relative_path(),
                    remediation="If this file is necessary on indexers, configure the settings "
                    "in the Splunk UI or via Admin Config Service.",
                )

    def check_local_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for conf_file in self.INDEXER_SYNCED_LOCALS:
            if conf_file in config:
                path_in_app = config[conf_file].get_relative_path()
                yield WarningMessage(
                    f"{path_in_app} will not be synced to indexers in Victoria.",
                    file_name=config[conf_file].get_relative_path(),
                    remediation="If this file is necessary on indexers, configure the settings "
                    "in the Splunk UI or via Admin Config Service.",
                )

    def check_user_local_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        yield from self.check_local_config(app, config)


class CheckForIndexerSyncedDatetimeXml(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_indexer_synced_datetime_xml",
                description="Check that the specified location of datetime.xml is not from the local folder.",
                depends_on_config=("props",),
                cert_min_version="2.34.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        sections = [sect for sect in config["props"].sections() if sect.has_option("DATETIME_CONFIG")]
        if not sections:
            yield NotApplicableMessage("DATETIME_CONFIG not present in props.conf")
            return

        sections = [sect for sect in sections if sect["DATETIME_CONFIG"].value not in ("CURRENT", "NONE")]
        if not sections:
            yield NotApplicableMessage("DATETIME_CONFIG does not point to custom datetime.xml")
            return

        for section in sections:
            option = section.get_option("DATETIME_CONFIG")
            dirname = os.path.dirname(option.value)
            filename = os.path.basename(option.value)
            if re.match(r"^/?etc/apps/.+?/local", dirname):
                yield FailMessage(
                    f"{section.name} specifies a DATETIME_CONFIG which points to a file in local, which is unsupported.",
                    file_name=option.get_relative_path(),
                    line_number=option.get_line_number(),
                    remediation=f"Move {filename} from local to default.",
                )
            if not re.match(r"^.*datetime.*\.xml$", filename):
                yield FailMessage(
                    f"{section.name} specifies a DATETIME_CONFIG which points to a file named `{filename}`, which is unsupported.",
                    file_name=option.get_relative_path(),
                    line_number=option.get_line_number(),
                    remediation=f"Rename {filename} to datetime.xml.",
                )
