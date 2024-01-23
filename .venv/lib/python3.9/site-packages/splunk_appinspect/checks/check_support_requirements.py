# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Support requirements
"""
import logging
from typing import TYPE_CHECKING

import splunk_appinspect
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect.reporter import Reporter


report_display_order = 60
logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL, Tags.MARKDOWN)
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=10)
def check_link_includes_contact_info(reporter: "Reporter") -> None:
    """Check that the app's documentation lists contact information and level
    of support for the app.  Any level of support is acceptable for developer
    supported apps, as long as it is clearly declared in documentation.
    Community supported apps must be open source with a public repository.
    For example:
    * Email support during weekday business hours (US, West Coast).
    * Phone support 24x7 @ +1 (555) 123-4567.
    * This is an open source project, no support provided, public repository
    available.
    """
    reporter.manual_check("Documentation will be read during code review.")
