# Copyright 2019 Splunk Inc. All rights reserved.

"""This is a helper module to encapsulate the functionality that represents
Splunk's savedsearch feature.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional, Union

from . import configuration_file, saved_searches_configuration_file
from .splunk import normalizeBoolean

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.configuration_file import ConfigurationSection, ConfigurationSetting
    from splunk_appinspect.custom_types import ConfigurationProxyType


class SavedSearch:
    """Represents a saved search."""

    def __init__(self, section: "ConfigurationSection"):
        self.name: str = section.name
        self.lineno: Optional[int] = section.lineno

        self.args: dict[str, "ConfigurationSetting"] = {}
        self.enable_scheduled: "ConfigurationSetting" = configuration_file.ConfigurationSetting(
            "enable_scheduled", str(0)
        )
        self._cron_schedule: Optional[str] = None
        self.disabled: "ConfigurationSetting" = configuration_file.ConfigurationSetting("disabled", str(0))
        self._dispatch_earliest_time: Optional[str] = None
        self._dispatch_latest_time: Optional[str] = None
        self.searchcmd: "ConfigurationSetting" = configuration_file.ConfigurationSetting("searchcmd", "")

    @property
    def enable_sched(self) -> bool | str:
        return normalizeBoolean(self.enable_scheduled.value)

    @property
    def cron_schedule(self) -> Optional[str]:
        return self._cron_schedule

    @cron_schedule.setter
    def cron_schedule(self, cron_schedule: "ConfigurationSetting") -> None:
        self._cron_schedule = cron_schedule.value

    @property
    def dispatch_earliest_time(self) -> Optional[str]:
        return self._dispatch_earliest_time

    @dispatch_earliest_time.setter
    def dispatch_earliest_time(self, dispatch_earliest_time: "ConfigurationSetting") -> None:
        self._dispatch_earliest_time = dispatch_earliest_time.value

    @property
    def dispatch_latest_time(self) -> Optional[str]:
        return self._dispatch_latest_time

    @dispatch_latest_time.setter
    def dispatch_latest_time(self, dispatch_latest_time: "ConfigurationSetting") -> None:
        self._dispatch_latest_time = dispatch_latest_time.value

    @property
    def is_disabled(self) -> bool | str:
        return normalizeBoolean(self.disabled.value)

    def is_real_time_search(self) -> Union[re.Match, bool, None]:
        real_time_regex_string = "^rt"
        dispatch_earliest_time_is_real_time_search = (
            re.search(real_time_regex_string, self.dispatch_earliest_time) if self.dispatch_earliest_time else False
        )
        dispatch_latest_time_is_real_time_search = (
            re.search(real_time_regex_string, self.dispatch_latest_time) if self.dispatch_latest_time else False
        )
        return dispatch_earliest_time_is_real_time_search or dispatch_latest_time_is_real_time_search


class SavedSearches:
    """Represents a savedsearches.conf file from default/savedsearches.conf."""

    def __init__(self, app: "App", config: "ConfigurationProxyType") -> None:
        self.app: "App" = app
        self.config: "ConfigurationProxyType" = config

    def configuration_file_exists(self) -> bool:
        return self.app.file_exists("default", "savedsearches.conf")

    def get_configuration_file(self) -> saved_searches_configuration_file.SavedSearchesConfigurationFile:
        return self.app.get_config(
            "savedsearches.conf",
            config_file=saved_searches_configuration_file.SavedSearchesConfigurationFile(),
        )

    def searches(self) -> list[SavedSearch]:
        if "savedsearches" not in self.config:
            return []

        search_list = []
        for section in self.config["savedsearches"].sections():
            search = SavedSearch(section)

            for (
                key,
                value,
            ) in section.options.items():
                search.args[key.lower()] = value

                if key.lower() == "enablesched":
                    search.enable_scheduled = value

                if key.lower() == "cron_schedule":
                    search.cron_schedule = value

                if key.lower() == "disabled":
                    search.disabled = value

                if key.lower() == "dispatch.earliest_time":
                    search.dispatch_earliest_time = value

                if key.lower() == "dispatch.latest_time":
                    search.dispatch_latest_time = value

                if key.lower() == "search":
                    search.searchcmd = value
            search_list.append(search)

        return search_list
