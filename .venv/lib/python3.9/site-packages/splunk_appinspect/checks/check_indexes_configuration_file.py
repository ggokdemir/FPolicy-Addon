# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Indexes.conf file standards

Ensure that the index configuration file located in the **/default** and **/local** folder is well formed and valid. For more, see [indexes.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Indexesconf).
"""
from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


report_display_order = 2
logger = logging.getLogger(__name__)

RE_INDEX_NAME = re.compile(r"\$SPLUNK_DB\/(?P<index_name>[$\w]+)\/(db|colddb|thaweddb)$")


CheckIndexesConfDoesNotExist = Check.disallowed_config_file(
    conf_file="indexes",
    tags=(Tags.SPLUNK_APPINSPECT,),
    cert_min_version="1.1.23",
    message="Apps and add-ons should not create indexes.conf. indexes.conf"
    "should only be defined by Splunk System Administrators to meet "
    "the data storage and retention needs of the installation. Consider"
    " using Tags or Source Types to identify data",
)

CheckValidateDefaultIndexesNotModified = Check.disallowed_config_stanzas(
    conf_file="indexes",
    stanzas=[
        "_audit",
        "_internal",
        "_introspection",
        "_thefishbucket",
        "history",
        "main",
        "provider-family:hadoop",
        "splunklogger",
        "summary",
        "volume:_splunk_summaries",
    ],
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_CLASSIC,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
    ),
    check_name="check_validate_default_indexes_not_modified",
    check_description="Check that no default Splunk indexes are modified by the app.",
    message="The default Splunk index [{stanza}] was modified in {file_name}, "
    "which is not allowed in the Splunk Cloud. Please remove this stanza. ",
    cert_min_version="1.1.7",
)


class CheckIndexDefinitionHasRequiredOptions(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_index_definition_has_required_options",
                description="Check that all index definitions exist all required options including:"
                " homePath, coldPath, and thawedPath.",
                depends_on_config=("indexes",),
                cert_min_version="1.5.0",
                tags=(Tags.SPLUNK_APPINSPECT,),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        required_options = ["homePath", "coldPath", "thawedPath"]
        filter_section_prefix = ("provider-family:", "provider:", "volume:")
        virtual_index_required_option = "vix.provider"
        for section in config["indexes"].sections():
            # not check default stanza
            if section.name == "default":
                continue
            # not check provider-family, provider and volume
            if section.name.startswith(filter_section_prefix):
                continue
            # not check virtual index
            if section.has_option(virtual_index_required_option):
                continue
            for required_option in required_options:
                if not section.has_option(required_option):
                    yield FailMessage(
                        f"The {section.name} index definition does not "
                        f"have the required option: {required_option}. ",
                        file_name=config["indexes"].get_relative_path(),
                        line_number=config["indexes"][section.name].get_line_number(),
                    )


class CheckIndexesConfProperties(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_indexes_conf_properties",
                description="Check that indexes.conf only contains the required 'homePath' , 'coldPath', and"
                " 'thawedPath' properties or the optional 'frozenTimePeriodInSecs', 'disabled', "
                "'datatype' and 'repFactor' properties. All other properties are prohibited. Also, if repFactor"
                " property exists, it's value should be 'auto'. This check"
                " is cloud only because indexes are not allowed via check_indexes_conf_does_not_exist.",
                depends_on_config=("indexes",),
                cert_min_version="1.5.3",
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
        property_allow_list = ["homePath", "coldPath", "thawedPath"]
        property_optional_allow_list = [
            "frozenTimePeriodInSecs",
            "disabled",
            "datatype",
            "repFactor",
        ]
        for section in config["indexes"].sections():
            # check for all properties
            for option_name, option_value, option_lineno in section.items():
                # in allow list
                if option_name in property_allow_list:
                    pattern_dict = {
                        "homePath": "db",
                        "coldPath": "colddb",
                        "thawedPath": "thaweddb",
                    }
                    legal_path = f"$SPLUNK_DB/{section.name}/{pattern_dict[option_name]}"
                    actual_path = option_value
                    if legal_path != actual_path:
                        m = RE_INDEX_NAME.match(actual_path)
                        if m and m.group("index_name") == "$_index_name":
                            continue
                        yield FailMessage(
                            f"In stanza {section.name}, property {option_name}",
                            file_name=config["indexes"].get_relative_path(),
                            line_number=option_lineno,
                            remediation=f"should be {legal_path}, but is {actual_path}  ",
                        )
                # not in option_allow_list
                elif option_name not in property_optional_allow_list:
                    allowed_properties = ", ".join(property_allow_list + property_optional_allow_list)
                    yield FailMessage(
                        f"Illegal property {option_name} found in stanza {section.name}."
                        f" Only properties [{allowed_properties}] are allowed in",
                        file_name=config["indexes"].get_relative_path(),
                        line_number=option_lineno,
                    )

                # if repFactor exists and value is not auto
                elif option_name == "repFactor" and option_value != "auto":
                    yield FailMessage(
                        "repFactor is an optional property. If specified it should be set to 'auto' only.",
                        file_name=config["indexes"].get_relative_path(),
                        line_number=option_lineno,
                    )


class CheckColdToFrozenScriptHasValidPythonVersionProperty(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_coldToFrozenScript_has_valid_python_version_property",
                description="Check that all the coldToFrozenScript in `indexes.conf` are explicitly set"
                " the python.version to python3.",
                depends_on_config=("indexes",),
                cert_min_version="2.1.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PYTHON3_VERSION,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for section in config["indexes"].sections():
            if section.has_option("coldToFrozenScript"):
                if not section.has_option("python.version") or section.get_option("python.version").value != "python3":
                    yield FailMessage(
                        f"The python.version of coldToFrozenScript should be explicitly set to python3. ",
                        file_name=config["indexes"].get_relative_path(),
                        line_number=config["indexes"][section.name].get_line_number(),
                    )


class CheckLowerCasedIndexNames(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_lower_cased_index_names",
                description="Check that all index names consist only of lowercase characters,"
                " numbers, underscores and hyphens. They cannot begin with an underscore "
                " or hyphen, or contain the word 'kvstore'. If index names have any"
                " uppercase characters any attempts to edit the index in the UI"
                " will cause a duplicate index stanza creation which will cause many errors in Splunk.",
                depends_on_config=("indexes",),
                cert_min_version="2.23.0",
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
        for section in config["indexes"].sections():
            if not re.match(r"^(?![_-]|.*kvstore)[a-z0-9_-]+$", section.name):
                yield FailMessage(
                    f"The index [{section.name}] contains either uppercase characters, starts"
                    " with an underscore or a hyphen, contains the word 'kvstore' or contains some"
                    " special characters which is not allowed. Please ensure index names contain only "
                    " lowercase characters, numbers, underscores and hyphens and do not start with an "
                    " underscore or hyphen, or contain the word 'kvstore'.",
                    file_name=config["indexes"].get_relative_path(),
                    line_number=config["indexes"][section.name].get_line_number(),
                )
