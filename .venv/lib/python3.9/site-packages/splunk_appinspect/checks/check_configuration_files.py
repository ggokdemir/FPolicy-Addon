# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Configuration file standards

Ensure that all configuration files located in the **/default** folder are well formed and valid.
"""
from __future__ import annotations

import collections
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect
from splunk_appinspect import App, app_util
from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS

if TYPE_CHECKING:
    from splunk_appinspect.configuration_file import ConfigurationProxy, ConfigurationSection
    from splunk_appinspect.reporter import Reporter


report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.cert_version(min="1.6.1")
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT)
def check_validate_no_duplicate_stanzas_in_conf_files(app: "App", reporter: "Reporter") -> None:
    """Check that no duplicate
    [stanzas](https://docs.splunk.com/Splexicon:Stanza) exist in .conf files.
    """
    stanzas_regex = r"^\[([^|]+)\]"
    stanzas = app.search_for_pattern(stanzas_regex, types=[".conf"], basedir=["default", "local"])
    stanzas_found = collections.defaultdict(list)

    for fileref_output, match in stanzas:
        filepath, line_number = fileref_output.rsplit(":", 1)
        file_stanza = (filepath, match.group())
        stanzas_found[file_stanza].append(line_number)

    for key, linenos in iter(stanzas_found.items()):
        if len(linenos) > 1:
            for lineno in linenos:
                reporter_output = f"Duplicate {key[1]} stanzas were found. " f"File: {key[0]}, Line: {lineno}."
                reporter.fail(reporter_output, key[0], lineno)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.1.12")
def check_config_file_parsing(app: "App", reporter: "Reporter") -> None:
    """Check that all config files parse cleanly- no trailing whitespace after
    continuations, no duplicated stanzas or options.
    """
    basedir = ["default", "local", *app.get_user_paths("local")]
    for directory, filename, _ in app.iterate_files(types=[".conf"], basedir=basedir):
        try:
            file_path = Path(directory, filename)
            conf = app.get_config(filename, dir=directory)
            for err, lineno, section in conf.errors:
                reporter_output = (
                    f"{err} at line {lineno} in [{section}] of {filename}. " f"File: {file_path}, Line: {lineno}."
                )
                reporter.fail(reporter_output, file_path, lineno)
        except Exception as error:
            logger.error("unexpected error occurred: %s", str(error))
            raise


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
)
@splunk_appinspect.cert_version(min="2.37.0")
def check_config_file_parsing_public(app: "App", reporter: "Reporter", included_tags: list[Tags]) -> None:
    """Check that all config files parse cleanly- no trailing whitespace after
    continuations, no duplicated stanzas or options.
    """
    for directory, filename, _ in app.iterate_files(types=[".conf"], basedir=["default", "local"]):
        try:
            file_path = Path(directory, filename)
            conf = app.get_config(filename, dir=directory)
            for err, lineno, section in conf.errors:
                reporter_output = (
                    f"{err} at line {lineno} in [{section}] of {filename}. " f"File: {file_path}, Line: {lineno}."
                )
                if err.startswith(("Duplicate stanza", "Repeat item")):
                    reporter.warn(reporter_output, file_path, lineno)
                    continue
                reporter.fail(reporter_output, file_path, lineno)
        except Exception as error:
            logger.error("unexpected error occurred: %s", str(error))
            raise


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.5.0")
def check_no_default_stanzas(app: "App", reporter: "Reporter") -> None:
    """Check that app does not contain any .conf files that create global
    definitions using the `[default]` stanza.
    """
    # Added allow list support because people are making poor life choices and
    # building splunk features that require the use of the `default` stanza
    # The white list conf files using the default stanza will be supported, but
    # not condoned
    conf_file_allow_list = ["savedsearches.conf"]

    basedir = ["default", "local", *app.get_user_paths("local")]
    for directory, filename, _ in app.iterate_files(types=[".conf"], basedir=basedir):
        if filename not in conf_file_allow_list:
            file_path = Path(directory, filename)
            try:
                conf = app.get_config(filename, dir=directory)
                for section_name in ["default", "general", "global", "stash"]:
                    if conf.has_section(section_name) and _is_not_empty_section(conf.get_section(section_name)):
                        if _is_splunk_defined_conf(filename):
                            lineno = conf.get_section(section_name).lineno
                            reporter_output = (
                                f"{section_name} stanza was found in {file_path}. "
                                "Please remove any [default], [general], [global], [stash] stanzas or properties "
                                "outside of a stanza (treated as default/global) "
                                "from conf files defined by Splunk."
                                "These stanzas/properties are not permitted "
                                "because they modify global settings outside the context of the app."
                                f"File: {file_path}, Line: {lineno}."
                            )
                            reporter.fail(reporter_output, file_path, lineno)
            except Exception as error:
                logger.error("unexpected error occurred: %s", str(error))
                raise


def _is_not_empty_section(section: "ConfigurationSection") -> bool:
    return len(section.items()) > 0


def _is_splunk_defined_conf(file_name: str) -> bool:
    return file_name in SPLUNK_DEFINED_CONFS


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_manipulation_outside_of_app_container(app: "App", reporter: "Reporter") -> None:
    """Check that app conf files do not point to files outside the app container.
    Because hard-coded paths won't work in Splunk Cloud, we don't consider to
    check absolute paths.
    """
    reporter_template = (
        "Manipulation outside of the app container was found in "
        "file {}; See stanza `{}`, "
        "key `{}` value `{}`. File: {}, Line: {}."
    )
    app_name = app.package.working_artifact_name

    conf_parameter_arg_regex = re.compile(r""""[^"]+"|'[^']+'|[^"'\s]+""")
    conf_check_list = {
        "app.conf": ["verify_script"],
        "distsearch.conf": ["genKeyScript"],
        "restmap.conf": ["pythonHandlerPath"],
        "authentication.conf": ["scriptPath"],
        "server.conf": ["certCreateScript"],
        "limits.conf": ["search_process_mode"],
    }
    basedir = ["default", "local", *app.get_user_paths("local")]
    for directory, filename, _ in app.iterate_files(types=[".conf"], basedir=basedir):
        if filename not in conf_check_list:
            continue
        conf = app.get_config(filename, dir=directory)
        for section in conf.sections():
            full_filepath = Path(directory, filename)
            for option in section.settings():
                key = option.name
                value = option.value
                lineno = option.lineno
                if key not in conf_check_list[filename]:
                    continue
                for path in conf_parameter_arg_regex.findall(value):
                    if app_util.is_manipulation_outside_of_app_container(path, app_name):
                        reporter_output = reporter_template.format(
                            full_filepath,
                            section.name,
                            key,
                            value,
                            full_filepath,
                            lineno,
                        )
                        reporter.fail(reporter_output, full_filepath, lineno)


class CheckCollectionsConfForSpecifiedNameFieldType(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_collections_conf_for_specified_name_field_type",
                description="Check that the `field.<name>` type in collections.conf does not include `boolean`."
                "Use `bool` instead.",
                depends_on_config=("collections",),
                cert_min_version="2.2.0",
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

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for section in config["collections"].sections():
            for key, value in iter(section.options.items()):
                if key.startswith("field.") and value.value == "boolean":
                    yield FailMessage(
                        "The field type for filed.<name> in collections.conf includes "
                        "`number|bool|string|time`, use bool to instead of boolean",
                        file_name=config["collections"].get_relative_path(),
                        line_number=config["collections"][section.name][key].get_line_number(),
                    )
