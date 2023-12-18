# Copyright 2020 Splunk Inc. All rights reserved.
"""Splunk telemetry.conf abstraction module"""
from typing import TYPE_CHECKING

from . import configuration_file, splunk

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.splunk.telemetry.core import TelemetryAllowList


class TelemetryConfigurationFile(configuration_file.ConfigurationFile):
    """Represents a [telemetry.conf](https://docs.splunk.com/Documentation/Splunk/8.0.3/Admin/Telemetryconf) file."""

    def __init__(self) -> None:
        configuration_file.ConfigurationFile.__init__(self)
        self._allow_list: "TelemetryAllowList" = splunk.telemetry_allow_list

    def check_allow_list(self, app: "App") -> bool:
        return app.name in self._allow_list
