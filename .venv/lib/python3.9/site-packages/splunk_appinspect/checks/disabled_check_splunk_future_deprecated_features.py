# Copyright 2019 Splunk Inc. All rights reserved.

"""
### These possible future deprecated features for Splunk.
However, these have not been officially deprecated. As such, they'll live here
until the time is right to make a respective check group for them.
"""
import logging
from typing import TYPE_CHECKING

import splunk_appinspect
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


report_display_order = 1001

logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.DEPRECATED_FEATURE)
@splunk_appinspect.cert_version(min="1.1.11")
def disabled_check_for_setup_xml(app: "App", reporter: "Reporter") -> None:
    """Checks that the setup.xml file does not exist."""
    if app.file_exists("default", "setup.xml"):
        reporter_output = (
            "Setup.xml is a deprecated feature as of Splunk"
            " version <FILL_ME_IN>. Please remove this file from the"
            " application. If you would like to use a setup"
            " page please add the 'setup_view' option to the"
            " [ui] stanza, in your app.conf."
        )
        reporter.warn(reporter_output)
    else:
        pass  # do nothing everything is fine
