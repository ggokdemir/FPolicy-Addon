# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 7.2

The following features should not be supported in Splunk 7.2 or later. For more, see [Deprecated features](http://docs.splunk.com/Documentation/Splunk/7.2.0/ReleaseNotes/Deprecatedfeatures) and [Changes for Splunk App developers](http://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers).
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


class CheckForDeprecatedLiteralsConf(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_deprecated_literals_conf",
                description="Check deprecated literals.conf existence.",
                depends_on_config=("literals",),
                cert_min_version="1.7.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_7_2,
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
        if config["literals"]:
            yield FailMessage(
                "literals.conf has been deprecated in Splunk 7.2.",
                file_name=config["literals"].get_relative_path(),
                remediation="Please use messages.conf instead",
            )
