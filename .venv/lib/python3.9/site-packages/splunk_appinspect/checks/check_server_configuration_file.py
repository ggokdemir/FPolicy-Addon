# Copyright 2016 - 2019 Splunk Inc. All rights reserved.

"""
### Server configuration file standards

Ensure that server.conf is well formed and valid.
For detailed information about the server configuration file, see [server.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Serverconf).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy, ConfigurationSection


report_display_order = 2
logger = logging.getLogger(__name__)


def _get_setting_names_with_key_pattern(section: "ConfigurationSection", pattern: str) -> list[str]:
    return [s.name for s in section.settings_with_key_pattern(pattern)]


def _get_disallowed_settings(setting_names: list[str], allowed_settings: list[str]) -> set[str]:
    return set(setting_names).difference(set(allowed_settings))


def _check_disallow_settings(
    file_path: Path, section: "ConfigurationSection", allowed_settings_pattern: str
) -> Generator[CheckMessage, Any, None]:
    all_setting_names = [s.name for s in section.settings()]
    allowed_setting_names = _get_setting_names_with_key_pattern(section, allowed_settings_pattern)
    disallowed_settings = _get_disallowed_settings(all_setting_names, allowed_setting_names)
    if disallowed_settings:
        yield FailMessage(
            f"Only {allowed_settings_pattern} properties are allowed "
            f"for `[{section.name}]` stanza. The properties "
            f"{disallowed_settings} are not allowed in this stanza. ",
            file_name=file_path,
            line_number=section.get_line_number(),
            remediation="Please remove these properties or all of server.conf.",
        )

    return


class CheckServerConfOnlyContainsCustomConfSyncStanzasOrDiagStanza(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_server_conf_only_contains_custom_conf_sync_stanzas_or_diag_stanza",
                description="Check that server.conf in an app is only allowed to contain: "
                "1. conf_replication_include.\<custom_conf_files\> in \[shclustering\] stanza "
                "2. or EXCLUDE-\<class\> property in \[diag\] stanza,",
                depends_on_config=("server",),
                cert_min_version="1.6.1",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_0,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for server in config["server"].sections():
            file_name = config["server"].get_relative_path()
            if server.name == "shclustering":
                yield from _check_disallow_settings(file_name, server, r"conf_replication_include\..*")
            elif server.name == "diag":
                yield from _check_disallow_settings(file_name, server, "EXCLUDE-.*")
            else:
                yield FailMessage(
                    f"Stanza `[{server.name}]` configures Splunk server settings and is not "
                    "permitted in Splunk Cloud.",
                    file_name=file_name,
                    line_number=config["server"][server.name].get_line_number(),
                    remediation="Please remove this stanza or all of server.conf.",
                )
