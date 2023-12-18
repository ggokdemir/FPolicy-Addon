# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 6.2

The following features should not be supported in Splunk 6.2 or later.
https://docs.splunk.com/Documentation/Splunk/6.2.0/ReleaseNotes/Deprecatedfeatures
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect.check_routine.util as util
from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.check_routine import find_xml_nodes_all, report_on_xml_findings_all, xml_node
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.custom_types import FileViewType


class CheckForDashboardXmlListElement(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_dashboard_xml_list_element",
                description="Check Dashboard XML files for `<list>` element. `<list>`"
                "was deprecated in Splunk 6.2 and removed in Splunk 6.5.",
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.2.1",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_2,
                    Tags.SPLUNK_6_5,
                    Tags.DEPRECATED_FEATURE,
                    Tags.REMOVED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        dashboard_xml_files = []
        xml_node_list = defaultdict(set)
        reporter_output = "<list> element is detected. <list> was removed since Splunk 6.5. Please do not use it."
        for node, dashboard_relative_path in util.get_dashboard_nodes_all(app, file_view):
            for directory, filename, ext in file_view.iterate_files(basedir="ui/views"):
                relative_filepath = Path(directory, filename)
                full_filepath = app.get_filename(directory, filename)
                if dashboard_relative_path == relative_filepath:
                    dashboard_xml_files.append((relative_filepath, full_filepath))
        found_xml_node_list = util.find_xml_nodes_usages(dashboard_xml_files, [xml_node("list")])

        if found_xml_node_list:
            for node, relative_filepath in found_xml_node_list:
                xml_node_list[node.name].add(relative_filepath)
        yield from report_on_xml_findings_all(xml_node_list, reporter_output, FailMessage)


class CheckForSimpleXmlRowGrouping(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_simple_xml_row_grouping",
                description="Check for the deprecated grouping attribute of `row` node in Simple XML files."
                "Use the `<panel>` node instead.",
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.7.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_2,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        grouping_re_obj = re.compile(r"""[0-9,"'\s]+""")
        node = xml_node("row")
        node.attrs = {"grouping": grouping_re_obj}
        reporter_output = (
            "Detect grouping attribute of <row>, which is deprecated in Splunk 6.2. Please use "
            "the <panel> node instead."
        )
        yield from report_on_xml_findings_all(
            find_xml_nodes_all(app, [node], file_view),
            reporter_output,
            FailMessage,
        )


class CheckForPopulatingSearchElementInDashboardXml(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_populating_search_element_in_dashboard_xml",
                description="Check for the deprecated `<populatingSearch>` and `<populatingSavedSearch>` elements in dashboard XML files."
                "Use the `<search>` element instead.",
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.7.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_2,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        nodes = [xml_node("populatingSearch"), xml_node("populatingSavedSearch")]
        reporter_output = (
            "<{}> element was deprecated in Splunk 6.2 and supposed to be removed in future releases, "
            "please use the <search> element instead."
        )
        yield from report_on_xml_findings_all(
            find_xml_nodes_all(app, nodes, file_view),
            reporter_output,
            FailMessage,
        )


class CheckForEarliestTimeAndLatestTimeElementsInDashboardXml(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_earliest_time_and_latest_time_elements_in_dashboard_xml",
                description="Check for the deprecated `<earliestTime>` and `<latestTime>` elements in dashboard XML files."
                "As of version 6.2 these elements are replaced by `<earliest>` and `<latest>` elements.",
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.7.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_2,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        nodes = [xml_node("earliestTime"), xml_node("latestTime")]
        reporter_output = (
            "<{}> element was deprecated in Splunk 6.2. please use the <earliest>/<latest> element instead."
        )
        yield from report_on_xml_findings_all(
            find_xml_nodes_all(app, nodes, file_view),
            reporter_output,
            FailMessage,
        )
