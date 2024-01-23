# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 9.0.1

The following features should not be supported in Splunk 9.0.1 or later. For more, see [Deprecated features](https://docs.splunk.com/Documentation/Splunk/9.0.1/ReleaseNotes/Deprecatedfeatures) and [Changes for Splunk App developers](http://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers).
"""

import logging

import splunk_appinspect
from splunk_appinspect import check_routine
from splunk_appinspect.app import App
from splunk_appinspect.constants import Tags
from splunk_appinspect.reporter import Reporter

logger = logging.getLogger(__name__)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SPLUNK_9_0,
    Tags.DEPRECATED_FEATURE,
    Tags.AST,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="2.38.0")
def check_for_search_v1_endpoint(app: App, reporter: Reporter) -> None:
    """Check search v1 deprecated API usages"""
    reporter_output = (
        "Some 'search/*' endpoints has been deprecated in Splunk 9.0.1 and replaced by new v2 APIs."
        "They might be removed entirely in a future release. An alternative could be found at "
        "https://docs.splunk.com/Documentation/Splunk/9.0.1/RESTREF/RESTsearch#Semantic_API_versioning"
    )

    kws = [
        "search/jobs/oneshot",
        "search/jobs/export",
        "search/jobs/.*/events",
        "search/jobs/.*/results",
        "search/jobs/.*/events/export",
        "search/jobs/.*/results/export",
        "search/jobs/.*/results_preview",
        "search/parser",
    ]
    regex_file_types = [".js", ".html", ".xml", ".conf", ".py", ".java"]

    for matched_file, matched_lineno in check_routine.find_endpoint_usage(
        app=app, kws=kws, regex_file_types=regex_file_types
    ):
        reporter.fail(reporter_output, matched_file, matched_lineno)
