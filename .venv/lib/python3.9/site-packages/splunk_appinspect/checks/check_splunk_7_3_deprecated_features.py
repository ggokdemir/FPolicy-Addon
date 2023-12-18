# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 7.3

The following features should not be supported in Splunk 7.3 or later. For more, see [Deprecated features](http://docs.splunk.com/Documentation/Splunk/7.3.0/ReleaseNotes/Deprecatedfeatures) and [Changes for Splunk App developers](http://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.check_routine import SPL_COMMAND_CHECKED_CONFS, find_spl_command_usage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.custom_types import FileViewType


class CheckForTscollectCommandUsage(Check):
    MESSAGE = (
        "`tscollect` command has been deprecated in Splunk 7.3, and might be removed in "
        "future version. The use of legacy TSIDX namespaces, which reside only on the "
        "individual search head and are therefore incompatible with search head "
        "clustering, has been discouraged for several releases. This feature has been "
        "superseded by datamodel, which reside on the indexer and has better performance "
        "and is accessible from any search head."
    )

    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_tscollect_command_usage",
                description="Check for use of `tscollect` SPL command in .conf files and SimpleXML.",
                cert_min_version="1.7.1",
                depends_on_config=SPL_COMMAND_CHECKED_CONFS,
                depends_on_data=("ui",),
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_7_3,
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
        for file_name, line_number in find_spl_command_usage(app, "tscollect", config=config):
            yield FailMessage(
                self.MESSAGE,
                file_name=file_name,
                line_number=line_number,
                remediation="Remove `tscollect` from searches and configs",
            )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        for file_name, _ in find_spl_command_usage(app, "tscollect", file_view=file_view):
            yield FailMessage(
                self.MESSAGE,
                file_name=file_name,
                remediation="Remove `tscollect` from dashboards",
            )
