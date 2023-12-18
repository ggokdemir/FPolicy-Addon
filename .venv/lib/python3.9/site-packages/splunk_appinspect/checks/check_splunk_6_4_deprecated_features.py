# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Deprecated features from Splunk Enterprise 6.4

The following features should not be supported in Splunk 6.4 or later. For more, see [Deprecated features](http://docs.splunk.com/Documentation/Splunk/latest/ReleaseNotes/Deprecatedfeatures#Previously_deprecated_features_that_still_work) and [Changes for Splunk App developers](http://docs.splunk.com/Documentation/Splunk/latest/Installation/ChangesforSplunkappdevelopers).
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import bs4

import splunk_appinspect
from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.custom_types import FileViewType
    from splunk_appinspect.reporter import Reporter


logger = logging.getLogger(__name__)


class CheckForSimpleXmlSingleElementWithDeprecatedOptionNames(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_simple_xml_single_element_with_deprecated_option_names",
                description="Check Simple XML files for `<single>` panels with deprecated options"
                "'additionalClass', 'afterLabel', 'beforeLabel', 'classField', 'linkFields',"
                "'linkSearch', 'linkView'",
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.1.11",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_4,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        attributes = [
            "additionalClass",
            "afterLabel",
            "beforeLabel",
            "classField",
            "linkFields",
            "linkSearch",
            "linkView",
        ]
        attribute_regex_string = "|".join(attributes)
        attribute_regex = re.compile(attribute_regex_string)
        for directory, filename, ext in file_view.iterate_files(basedir="ui/views"):
            if ext != ".xml":
                continue
            file_path = Path(directory, filename)
            full_filepath = app.get_filename(directory, filename)
            soup = bs4.BeautifulSoup(open(full_filepath, "rb"), "html.parser")
            # Get all single elements
            attributes_found = []
            single_elements = list(soup.find_all("single"))
            for single_element in single_elements:
                # Gets all child option elements of said single, and filters out to
                # only the ones that have a name attribute with the deprecated values
                option_elements = single_element.find_all("option", {"name": attribute_regex})
                if option_elements:
                    for option_element in option_elements:
                        option_attribute = {
                            "filepath": file_path,
                            "name": option_element,
                            "lineno": option_element.sourceline,
                        }
                        if option_attribute not in attributes_found:
                            attributes_found.append(option_attribute)

            if attributes_found:
                for option in attributes_found:
                    filepath = option["filepath"]
                    name = option["name"]
                    lineno = option["lineno"]
                    reporter_output = (
                        f"File `{filepath}` <single> panel contains option `{name}` "
                        f"that has been deprecated in Splunk 6.4."
                    )

                    yield FailMessage(reporter_output, file_name=file_path, line_number=lineno)


class CheckWebConfForSimpleXmlModuleRender(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_web_conf_for_simple_xml_module_render",
                description="Check that `web.conf` does not use the simple_xml_module_renderproperty.",
                depends_on_config=("web",),
                cert_min_version="1.1.11",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_4,
                    Tags.DEPRECATED_FEATURE,
                    Tags.WEB_CONF,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        web_config_file_path = config["web"].get_relative_path()
        for section in config["web"].sections():
            for _, _, lineno in [(p, v, lineno) for p, v, lineno in section.items() if p == "simple_xml_module_render"]:
                yield FailMessage(
                    f"{web_config_file_path} use the simple_xml_module_render property"
                    f"in Stanza {section.name}, which has been deprecated in Splunk 6.4.",
                    file_name=web_config_file_path,
                    line_number=lineno,
                )


class CheckWebConfForSimpleXmlForceFlashCharting(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_web_conf_for_simple_xml_force_flash_charting",
                description="Check that `web.conf` does not use the simple_xml_force_flash_chartingproperty.",
                depends_on_config=("web",),
                cert_min_version="1.1.11",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_4,
                    Tags.DEPRECATED_FEATURE,
                    Tags.WEB_CONF,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        web_config_file_path = config["web"].get_relative_path()
        for section in config["web"].sections():
            for _, _, lineno in [
                (p, v, lineno) for p, v, lineno in section.items() if p == "simple_xml_force_flash_charting"
            ]:
                yield FailMessage(
                    f"{web_config_file_path} use the simple_xml_force_flash_charting property"
                    f"in Stanza {section.name}, which has been deprecated in Splunk 6.4.",
                    file_name=web_config_file_path,
                    line_number=lineno,
                )


class CheckForNonIntegerHeightOption(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_noninteger_height_option",
                description='Check that `<option name="height">` uses an integer for the value.'
                'Do not use `<option name="height">[value]px</option>.`',
                depends_on_data=(Path("ui", "views"),),
                cert_min_version="1.1.11",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.SPLUNK_6_4,
                    Tags.DEPRECATED_FEATURE,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        def is_number(string: str) -> bool:
            try:
                float(string)
                return True
            except ValueError:
                return False

        def is_token(string: str) -> bool:
            return string.startswith("$") and string.endswith("$")

        for directory, filename, ext in file_view.iterate_files(basedir="ui/views"):
            if ext != ".xml":
                continue
            file_path = Path(directory, filename)
            full_filepath = app.get_filename(directory, filename)
            soup = bs4.BeautifulSoup(open(full_filepath, "rb"), "lxml-xml")
            option_elements = soup.find_all("option", {"name": "height"})
            for option_element in option_elements:
                option_content = option_element.string
                if not is_number(option_content) and not is_token(option_content):
                    yield FailMessage(
                        "'<option name="
                        "height"
                        "> use an "
                        "[integer]px"
                        " for the value, "
                        "which is deprecated in Splunk 6.4. Only use an integer",
                        file_name=file_path,
                    )


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SPLUNK_6_4,
    Tags.DEPRECATED_FEATURE,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_splunk_js_d3chartview(app: "App", reporter: "Reporter") -> None:
    """Checks that views are not importing d3chartview."""
    library_import_pattern = "splunkjs/mvc/d3chart/d3chartview"
    relevant_file_types = [".js"]

    # This is a little lazy, but search for pattern doesn't return a list of
    # the files being searched, so in order to know the count I get the list of
    # iterated files and then completely ignore it if > 0
    files = list(app.get_filepaths_of_files(types=relevant_file_types))

    if not files:
        reporter_output = ("No {} files exist.").format(",".join(relevant_file_types))
        reporter.not_applicable(reporter_output)

    # Check starts here
    matches_found = app.search_for_pattern(library_import_pattern, types=relevant_file_types)
    for match_file_and_line, _ in matches_found:
        match_split = match_file_and_line.rsplit(":", 1)
        match_file = match_split[0]
        match_line = match_split[1]
        reporter_output = "Views are importing d3chartview, which has been deprecated in Splunk 6.4."
        reporter.fail(reporter_output, match_file, match_line)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SPLUNK_6_4,
    Tags.DEPRECATED_FEATURE,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.1.11")
def check_for_splunk_js_googlemapsview(app: "App", reporter: "Reporter") -> None:
    """Checks that views are not importing googlemapsview."""
    library_import_pattern = "splunkjs/mvc/d3chart/googlemapsview"
    relevant_file_types = [".js"]

    # This is a little lazy, but search for pattern doesn't return a list of
    # the files being searched, so in order to know the count I get the list of
    # iterated files and then completely ignore it if > 0
    files = list(app.get_filepaths_of_files(types=relevant_file_types))

    if not files:
        file_types = ",".join(relevant_file_types)
        reporter_output = f"No {file_types} files exist."
        reporter.not_applicable(reporter_output)

    # Check starts here
    matches_found = app.search_for_pattern(library_import_pattern, types=relevant_file_types)
    for match_file_and_line, _ in matches_found:
        match_split = match_file_and_line.rsplit(":", 1)
        match_file = match_split[0]
        match_line = match_split[1]
        reporter_output = "Views are importing googlemapsview, which has been deprecated in Splunk 6.4."
        reporter.fail(reporter_output, match_file, match_line)
