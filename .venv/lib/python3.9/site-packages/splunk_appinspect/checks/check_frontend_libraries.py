# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Checking for Front-end Libraries

This check looks for various front-end libraries inside of apps. 
As of 03/23/2022, we are looking at Splunk UI and it's predecessor, SplunkJS. 
This is currently an INFORMATIONAL Check. 


Updated on 04/17/2023

This check now is expanded to look for several other critical front-end libraries. 
1. We have expanded the regex matching to be more inline with all of the UDF Packages https://splunkui.splunk.com/Packages/dashboard-docs/?path=%2FFAQ
2. We have added a few other critical packages (@splunk/react-search, @splunk/react-time-range, @splunk/search-job, @splunk/ui-utils, @splunk/splunk-utils, @splunk/moment)
3. We have expanded the regex matching to be more inline with more of the Visualizations packages. 

"""

import logging
import re
from typing import TYPE_CHECKING

import splunk_appinspect
from splunk_appinspect.constants import Tags
from splunk_appinspect.regex_matcher import (
    JSSplunkDashboardCoreMatcher,
    JSSplunkJSMatcher,
    JSSplunkSplunkFrontendUtils,
    JSSplunkSUIMatcher,
    JSSplunkVisualizationsMatcher,
)

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


logger = logging.getLogger(__name__)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_splunk_js(app: "App", reporter: "Reporter") -> None:
    """Check that SplunkJS is being used."""
    matcher = JSSplunkJSMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir,
        app.iterate_files(types=[".js", ".html", ".map"]),
        regex_option=re.IGNORECASE,
        exclude_comments=False,
    ):
        reporter_output = (
            "Splunk has begun gathering telemetry on apps submitted to appinspect, that utilize SplunkJS. Please ignore this warning as it has no impact to your Splunk app."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.warn(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "SplunkJS has not been detected inside of this app. Please ignore this message as it has no impact to your Splunk App."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_splunk_sui(app: "App", reporter: "Reporter") -> None:
    """Check that SUI is being used."""
    matcher = JSSplunkSUIMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir,
        app.iterate_files(types=[".js", ".jsx", ".html", ".json", ".map"]),
        regex_option=re.IGNORECASE,
        exclude_comments=False,
    ):
        reporter_output = (
            "Splunk has begun gathering telemetry on apps submitted to appinspect, that utilize Splunk UI. Please ignore this warning as it has no impact to your Splunk app."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.warn(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "Usage of Splunk UI has not been detected inside of this app. Please ignore this message as it has no impact to your Splunk App."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_splunk_frontend_utility_components(app: "App", reporter: "Reporter") -> None:
    """Check for usage of utility components."""
    matcher = JSSplunkSplunkFrontendUtils()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir,
        app.iterate_files(types=[".js", ".jsx", ".html", ".json", ".map"]),
        regex_option=re.IGNORECASE,
        exclude_comments=False,
    ):
        reporter_output = (
            "Splunk has begun gathering telemetry on apps submitted to appinspect, that utilize Splunk UI utility components. Please ignore this warning as it has no impact to your Splunk app."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.warn(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "Splunk UI Utility components have not been detected inside of this app. Please ignore this message as it has no impact to your Splunk App."
        reporter.not_applicable(reporter_output)


# Check for Visualizations Libraries
@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_splunk_visualizations(app: "App", reporter: "Reporter") -> None:
    """Check that @splunk/visualizations is being used."""
    matcher = JSSplunkVisualizationsMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir,
        app.iterate_files(types=[".js", ".jsx", ".html", ".json", ".map"]),
        regex_option=re.IGNORECASE,
        exclude_comments=False,
    ):
        reporter_output = (
            "Splunk has begun gathering telemetry on apps submitted to appinspect, that utilize Splunk Visualizations libraries for React. Please ignore this warning as it has no impact to your Splunk app."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.warn(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "Splunk Visualizations libraries for React have not been detected inside of this app. Please ignore this message as it has no impact to your Splunk App."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_splunk_dashboard_core(app: "App", reporter: "Reporter") -> None:
    """Check that @splunk/dashboard-core is being used."""
    matcher = JSSplunkDashboardCoreMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir,
        app.iterate_files(types=[".js", ".jsx", ".html", ".json", ".map"]),
        regex_option=re.IGNORECASE,
        exclude_comments=False,
    ):
        reporter_output = (
            "Splunk has begun gathering telemetry on apps submitted to appinspect, that utilize the Unified Dashboard Framework (UDF). Please ignore this warning as it has no impact to your Splunk app."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )

        reporter.warn(reporter_output, file_path, lineno)

    if not matcher.has_valid_files:
        reporter_output = "Unified Dashboard Framework (UDF) has not been detected inside of this app. Please ignore this message as it has no impact to your Splunk App."
        reporter.not_applicable(reporter_output)
