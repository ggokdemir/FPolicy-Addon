# Copyright 2019 Splunk Inc. All rights reserved.

"""
### ITSI module verification
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from splunk_appinspect import App

from typing import Any, Generator

from splunk_appinspect.check_messages import CheckMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags


class CheckForItsiModules(Check):
    ITSI_MODULE_PREFIX = "DA-ITSI"

    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_itsi_modules",
                description="Check that the app does not contain an ITSI module.",
                cert_min_version="3.0.2",
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

    def check(self, app: "App") -> Generator[CheckMessage, Any, None]:
        """Check that app has no ITSI modules."""
        if self._is_itsi_module(app):
            yield WarningMessage(
                "ITSI modules are not allowed.",
                remediation="ITSI modules are in the process of being deprecated and replaced by the Splunk App for Content Packs. "
                "For more information, see [Overview of the Splunk App for Content Packs](https://docs.splunk.com/Documentation/ContentPackApp/latest/Overview/Overview) in the Splunk App for Content Packs Manual.",
            )

    def _is_itsi_module(self, app: "App") -> bool:
        """Check if valid itsi module"""
        return app.name.upper().startswith(self.ITSI_MODULE_PREFIX)
