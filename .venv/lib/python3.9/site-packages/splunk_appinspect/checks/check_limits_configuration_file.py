# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Limits.conf file standards

Ensure that **/default/limits.conf** or **local/limits.conf** file is omitted.

When included in the app, the **limits.conf** file changes the limits that are placed on the system for hardware use and memory consumption, which is a task that should be handled by Splunk administrators and not by Splunk app developers. For more, see [limits.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Limitsconf).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


class CheckLimitsConf(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_limits_conf",
                description="Check that `default/limits.conf` or `local/limits.conf` or "
                "`users/<username>/local/limits/conf` has not been included.",
                depends_on_config=("limits",),
                cert_min_version="1.0.0",
                report_display_order=6,
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        if "limits" in config:
            yield FailMessage(
                "Changes to 'limits.conf' are not allowed.Memory limits should be left to Splunk Administrators.",
                file_name=config["limits"].get_relative_path(),
                remediation="Please remove this file.",
            )
