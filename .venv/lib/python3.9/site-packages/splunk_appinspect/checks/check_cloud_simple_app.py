# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Cloud operations simple application check

This group serves to help validate simple applications in an effort to try and automate the validation process for cloud operations.
"""
from __future__ import annotations

import ast
import codecs
import logging
import os
import platform
import re
import zipfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

import bs4
import magic
import semver

import splunk_appinspect
from splunk_appinspect.app_util import find_readmes
from splunk_appinspect.check_messages import CheckMessage, FailMessage, ManualCheckMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags
from splunk_appinspect.lookup import LookupHelper
from splunk_appinspect.splunk.splunk_default_source_type_list import SPLUNK_DEFAULT_SOURCE_TYPE
from splunk_appinspect.telemetry_configuration_file import TelemetryConfigurationFile

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.custom_types import FileViewType
    from splunk_appinspect.reporter import Reporter

logger = logging.getLogger(__name__)


class CheckDefaultDataUiFileAllowList(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_default_data_ui_file_allow_list",
                description="Check that directories under `data/ui` contain only allowed files. "
                "Ensure unnecessary, unwanted files are not bundled in the app inappropriately.",
                cert_min_version="1.1.19",
                depends_on_data=(("ui",)),
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        ignored_file_names = ["readme"]
        ignored_file_types = [".md", ".txt", ".old", ".bak", ".back", ".template"]
        allowed_file_types = {
            Path("ui", "views"): [".html", ".xml"],
            Path("ui", "panels"): [".html", ".xml"],
            Path("ui", "nav"): [".html", ".xml"],
            Path("ui", "alerts"): [".html", ".xml"],
            Path("ui", "quickstart"): [".html", ".xml"],
        }

        for basedir in allowed_file_types:
            combined_allowed_types = allowed_file_types[basedir] + ignored_file_types
            for directory, filename, ext in file_view.iterate_files(
                basedir=basedir,
                excluded_types=combined_allowed_types,
                excluded_bases=ignored_file_names,
            ):
                file_path = Path(directory, filename)
                yield FailMessage(
                    f"File {file_path} is not allowed in {basedir}.",
                    file_name=file_path,
                    remediation="Remove the file or, if it is a backup or template file, rename it with `.bak` or `.template` suffix.",
                )


class CheckDefaultDataUiManagerForPlainTextCredentials(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_default_data_ui_manager_for_plain_text_credentials",
                description="Check that directories under `data/ui` contain only allowed files. "
                "Identify for manual review items that might cause passwords to be stored in plaintext.",
                cert_min_version="1.5.4",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.MANUAL,
                ),
                depends_on_data=(Path("ui", "manager"),),
            )
        )

    def check_data(self, app: "App", file_view: "FileViewType") -> Generator[CheckMessage, Any, None]:
        compiled_regex = re.compile(
            r"(pass|passwd|password|token|auth|priv|access|secret|login|community|key|privpass)\s*",
            re.IGNORECASE,
        )
        for directory, filename, ext in file_view.iterate_files(basedir="ui/manager"):
            file_path = Path(directory, filename)
            if ext != ".xml":
                yield ManualCheckMessage(
                    f"File {filename} in {directory} is not a .xml file. It will be inspected manually.",
                    file_name=file_path,
                    remediation=f"If {filename} is in {directory} by mistake, remove it.",
                )
                continue

            full_filepath = app.get_filename(directory, filename)
            soup = bs4.BeautifulSoup(open(full_filepath, "rb"), "lxml-xml")
            # element has 3 attributes: name, type, label
            # text should be the text string in element
            type_list = soup.find_all("element", {"type": re.compile("^password$")})
            attr_list = soup.find_all("element", {"name": compiled_regex}) + soup.find_all(
                "element", {"label": compiled_regex}
            )
            if type_list:
                yield ManualCheckMessage(
                    f"This app uses 'type=password'. Please check "
                    "whether the app encrypts this password in "
                    "scripts.",
                    file_name=file_path,
                )
            elif attr_list or self._is_text_with_password(soup, compiled_regex):
                yield ManualCheckMessage(
                    "This app uses password/key/secret or other "
                    "keywords. Please check whether they are "
                    "secret credentials. If yes, please make "
                    "sure the app uses 'type=password' "
                    "attribute and the 'storage/passwords' "
                    "endpoint to encrypt it. ",
                    file_name=file_path,
                )

    @staticmethod
    def _is_text_with_password(soup: bs4.BeautifulSoup, compiled_regex: re.Pattern) -> bool:
        for element in soup.find_all("element"):
            if element.find(text=compiled_regex):
                return True
        return False


class CheckLookupsAllowList(Check):
    ALLOWED_FILE_TYPES = [".csv", ".csv.default", ".csv.gz", ".csv.tgz", ".kmz"]

    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_lookups_allow_list",
                description="Check that `lookups/` contains only approved file types (.csv, .csv.default, .csv.gz, .csv.tgz, .kmz) or files formatted as valid csv. "
                "Ensure malicious files are not passed off as lookup files.",
                cert_min_version="1.5.4",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_lookup_file(self, app: "App", lookup_file: Path) -> Generator[CheckMessage, Any, None]:
        # if ext not in allowed_file_types:
        # Pretty messy way to determine if the allowed extension is a dotted
        # file, on account that iterate files will only return the last
        # level of the extension I.E. .csv.gz returns .gz instead of
        # .csv.gz
        does_file_name_end_with_extension = [
            allowed_file_type
            for allowed_file_type in self.ALLOWED_FILE_TYPES
            if str(lookup_file).endswith(allowed_file_type)
        ]

        if not does_file_name_end_with_extension:
            # Validate using LookupHelper.is_valid_csv(), if not valid csv
            # then fail this lookup
            full_filepath = app.get_filename(lookup_file)
            try:
                is_valid, rationale = LookupHelper.is_valid_csv(full_filepath)
                if not is_valid:
                    yield FailMessage(
                        "This file is not an approved file type "
                        "and is not formatted as valid csv. "
                        f"Details: {rationale}",
                        file_name=lookup_file,
                        remediation="Determine where this file is meant to be located. If it's not needed, remove it.",
                    )
            except Exception as err:
                # FIXME: tests needed
                logger.warning(
                    "Error validating lookup. File: %s Error: %s.",
                    full_filepath,
                    err,
                )
                yield FailMessage(
                    "Error opening and validating lookup. Please investigate/remove this lookup.",
                    file_name=lookup_file,
                )


class CheckMetadataAllowList(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_metadata_allow_list",
                description="Check that the `metadata/` and `users/<username>/metadata` directories "
                "do not contain any subdirectories and only contain .meta files. "
                "Ensure malicious files are not passed off as metadata files.",
                cert_min_version="1.5.4",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_metadata_file(self, app: "App", path_in_app: Path) -> Generator[CheckMessage, Any, None]:
        """Check that the `metadata/` or `users/<username>/metadata/` directory only contains .meta files
        and does not contain any subdirectories
        """
        parts = path_in_app.parts
        is_user = len(parts) == 4 and parts[0] == "users"
        is_local = len(path_in_app.parts) == 2
        if not (is_user or is_local) or path_in_app.parts[-2] != "metadata":
            yield WarningMessage(
                "A Subdirectory found under metadata directory",
                file_name=path_in_app.parent,
                remediation="Please remove this directory from the metadata directory.",
            )
        elif not str(path_in_app).endswith(".meta"):
            yield FailMessage(
                "A file within the `metadata` directory was found"
                " with an extension other than `.meta`."
                f" Please remove this file: {path_in_app}",
                file_name=path_in_app,
            )


class CheckStaticDirectoryFileAllowList(Check):
    ALLOWED_FILE_TYPES = [
        ".md",
        ".png",
        ".txt",
    ]

    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_static_directory_file_allow_list",
                description="Check that the `static/` directory does not contains any subdirectories "
                "and contains only known file types. "
                "Ensure malicious files are not passed off as metadata files.",
                cert_min_version="1.1.19",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                ),
            )
        )

    def check_static_file(self, app: "App", path_in_app: Path) -> Generator[CheckMessage, Any, None]:
        if os.path.dirname(path_in_app) != "static":
            yield FailMessage(
                "A subdirectory found under static directory",
                file_name=path_in_app.parent,
                remediation="Please remove this directory from the static directory.",
            )
        elif path_in_app.suffix.lower() not in self.ALLOWED_FILE_TYPES:
            yield FailMessage(
                "This file does not appear to be a png image or txt file.",
                file_name=path_in_app,
                remediation="Please remove this file from the static directory.",
            )


# ------------------------------------------------------------------------------
# Grey List Checks Go Here
# ------------------------------------------------------------------------------
# -------------------
# authorize.conf
# -------------------
class CheckAuthorizeConfAdminAllObjectsPrivileges(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_authorize_conf_admin_all_objects_privileges",
                description="Check that authorize.conf does not grant excessive administrative permissions to the user. "
                "Prevent roles from gaining unauthorized permissions.",
                cert_min_version="1.1.20",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
                depends_on_config=("authorize",),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        properties_to_validate = [
            "admin_all_objects",
            "change_authentication",
            "importRoles",
        ]
        import_roles_to_prevent = {"admin", "sc_admin", "splunk-system-role"}
        for section in config["authorize"].sections():
            # Ignore capability stanzas
            if section.name.startswith("capability::"):
                continue
            for property_to_validate in properties_to_validate:
                if not section.has_option(property_to_validate):
                    continue
                option = section.get_option(property_to_validate)
                if property_to_validate == "importRoles":
                    # Check importRoles for inheriting of deny listed roles
                    # using set intersection of importRoles & deny listed roles
                    bad_roles = set(option.value.split(";")) & import_roles_to_prevent
                    for bad_role in bad_roles:
                        yield FailMessage(
                            f"[{section.name}] attempts to inherit from the `{bad_role}` role.",
                            file_name=option.get_relative_path(),
                            line_number=option.get_line_number(),
                            remediation=f"Do not inherit from these roles: {','.join(import_roles_to_prevent)}",
                        )
                elif option.value == "enabled":
                    yield FailMessage(
                        f"[{section.name}] contains {property_to_validate} = enabled.",
                        file_name=option.get_relative_path(),
                        line_number=option.get_line_number(),
                        remediation=f"Remove {property_to_validate} from {section.name}",
                    )


check_authorize_conf_for_tokens_auth = Check.disallowed_config_stanza(
    conf_file="authorize",
    stanza="tokens_auth",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    # 27-Feb-2023 (mcm): We inadvertantly changed the name of this check during the transition to class-based checks.
    #                    Leaving this here in case that causes issues in the future, but not reverting it since we
    #                    probably already updated the tests, and it's already been released with the new name.
    check_name="check_authorize_conf_for_tokens_auth",
    cert_min_version="2.0.2",
)


class CheckAlertActionsConfForAlertExecuteCmdProperties(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_alert_actions_conf_for_alert_execute_cmd_properties",
                description="Check that commands referenced in the `alert.execute.cmd` property of all alert actions are checked for compliance with Splunk Cloud security policy. "
                "Prevent alert_actions.conf from being used to execute malicious commands.",
                cert_min_version="1.1.20",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.MANUAL,
                ),
                depends_on_config=("alert_actions",),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        for alert_action in config["alert_actions"].sections():
            if not alert_action.has_option("alert.execute.cmd"):
                continue
            alert_execute_cmd = alert_action.get_option("alert.execute.cmd")
            if alert_execute_cmd.value.endswith(".path"):
                yield FailMessage(
                    f"Alert action {alert_action.name} has an alert.execute.cmd "
                    f"specified with command `{alert_execute_cmd.value}`. "
                    "Path pointer files are prohibited in Splunk Cloud because they can "
                    "be used to target executables outside of the app.",
                    file_name=alert_execute_cmd.get_relative_path(),
                    line_number=alert_execute_cmd.get_line_number(),
                    remediation="Point directly to an executable within the app",
                )
            else:
                yield ManualCheckMessage(
                    f"Alert action {alert_action.name} has an alert.execute.cmd "
                    f"specified. Please check this command: `{alert_execute_cmd.value}`.",
                    file_name=alert_execute_cmd.get_relative_path(),
                    line_number=alert_execute_cmd.get_line_number(),
                )


# -------------------
# commands.conf
# -------------------
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.6.1")
def check_command_scripts_exist_for_cloud(app: "App", reporter: "Reporter") -> None:
    """Check that custom search commands have an executable or script per
    stanza.
    """
    custom_commands = app.get_custom_commands()
    if custom_commands.configuration_file_exists():
        file_path = Path("default", "commands.conf")
        for command in custom_commands.get_commands():
            lineno = command.lineno

            with_path_suffix_pattern = r".*\.path$"
            is_filename_with_path_suffix = re.match(with_path_suffix_pattern, str(command.file_name))

            # can't find scripts in `bin/` or `<PLATFORM>/bin`
            if not is_filename_with_path_suffix and not command.file_name_exe:
                reporter_message = (
                    f"The script of command [{command.name}] was not found "
                    "or the script type is not supported. "
                    f"File: {file_path}, Line: {lineno}."
                )
                reporter.warn(reporter_message, file_path, lineno)

            # v2 command
            elif command.is_v2():
                _check_v2_command(command, app, reporter, is_filename_with_path_suffix)

            # v1 command
            else:
                _check_v1_command(command, reporter)
    else:
        reporter.not_applicable("No `commands.conf` file exists.")


def _check_v1_command(command: "Command", reporter: "Reporter") -> None:
    file_path = Path("default", "commands.conf")
    lineno = command.lineno
    count_v1_exes = command.count_v1_exes()

    # file extension is not in v1 extension list
    if count_v1_exes == 0 and _is_python_script(command.file_name_exe.file_path):
        reporter_message = (
            "Custom Search Command Protocol v1 only support .py or .pl script, but the "
            f"stanza [{command.name}] in commands.conf doesn't use a .py or .pl script. "
            f"Please correct script extension: `{command.file_name_exe.file_name}`. "
            f"File: {file_path}, Line: {lineno}."
        )
        reporter.warn(reporter_message, file_path, lineno)


def _check_v2_command(
    command: "Command", app: "App", reporter: "Reporter", is_filename_with_path_suffix: Optional[re.Match]
) -> None:
    file_path = Path("default", "commands.conf")
    lineno = command.lineno
    filename_is_specified = command.file_name_specified()
    count_v2_exes = (
        command.count_win_exes()
        + command.count_linux_exes()
        + command.count_linux_arch_exes()
        + command.count_win_arch_exes()
        + command.count_darwin_arch_exes()
    )

    # For the v2 command, the Splunk software attempts to run no extension
    # or unrecognized executable directly, without an interpreter. On UNIX-based
    # platforms, this means that the executable must have the executable bit set.
    # https://docs.splunk.com/Documentation/Splunk/7.0.0/Search/Customcommandlocation
    excluded_extensions = [".py", ".pl", ".js"]
    directly_executing_scripts = [
        script
        for script in command.executable_files
        if script.ext not in excluded_extensions
        and (platform.system() == "Windows" or app.is_executable(script.file_path, is_full_path=True))
    ]
    # `filename = *.path`
    if filename_is_specified and is_filename_with_path_suffix:
        lineno = command.args["filename"][1]
        reporter_message = (
            "The custom command is chunked and "
            f"the stanza [{command.name}] in commands.conf has "
            "field of `filename` with value ends with `.path`. "
            "Please manual check whether this path pointer files "
            "are inside of app container and use relative path. "
            f"File: {file_path}, Line: {lineno}."
        )
        reporter.manual_check(reporter_message, file_path, lineno)

    elif directly_executing_scripts:
        reporter_message = (
            f"The custom command [{command.name}] doesn't use a .py, .pl, .js "
            "script, which can be executed by Splunk directly "
            "without an interpreter. Please manual check the "
            f"script `{command.file_name_exe.file_name}`. "
            f"File: {file_path}, Line: {lineno}."
        )
        reporter.manual_check(reporter_message, file_path, lineno)

    # file extension is not in v2 extension list
    elif count_v2_exes == 0:
        reporter_message = (
            "Because the custom command is chunked, the "
            f"stanza [{command.name}] in commands.conf must "
            "use a .py, .pl, .cmd, .bat, .exe, .js, .sh or no "
            f"extension script. File: {file_path}, Line: {lineno}."
        )
        reporter.warn(reporter_message, file_path, lineno)


def _is_python_script(file_path: str | Path) -> bool:
    with open(file_path, "rb") as f:
        code = f.read()

    try:
        ast.parse(code)
    except Exception:
        return False

    return len(code) != 0


# -------------------
# distsearch.conf
# -------------------
class CheckDistsearchConfForConcerningReplicatedFileSize(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_distsearch_conf_for_concerning_replicated_file_size",
                description="Check if concerningReplicatedFileSize in distsearch.conf is larger than 50 MB.",
                cert_min_version="1.6.1",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
                depends_on_config=("distsearch",),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        if not config["distsearch"].has_option("replicationSettings", "concerningReplicatedFileSize"):
            return
        concerningReplicatedFileSize = config["distsearch"]["replicationSettings"]["concerningReplicatedFileSize"]
        if int(concerningReplicatedFileSize.value) > 50:
            yield WarningMessage(
                "The app contains default/distsearch.conf and "
                "the value of concerningReplicatedFileSize, "
                f"{concerningReplicatedFileSize.value} MB, is larger than "
                "50 MB. The best practice is files which are >50MB should not "
                "be pushed to search peers via bundle replication.",
                file_name=concerningReplicatedFileSize.get_relative_path(),
                line_number=concerningReplicatedFileSize.get_line_number(),
                remediation="Limit the value of concerningReplicatedFileSize to 50MB",
            )


# -------------------
# indexes.conf
# -------------------
class CheckIndexesConfOnlyUsesSplunkDbVariable(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_indexes_conf_only_uses_splunk_db_variable",
                description="Check that indexes defined in `indexes.conf` use relative paths starting "
                "with $SPLUNK_DB",
                depends_on_config=("indexes",),
                cert_min_version="1.1.20",
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
        properties_to_validate = [
            "bloomHomePath",
            "coldPath",
            "homePath",
            "summaryHomePath",
            "thawedPath",
            "tstatsHomePath",
        ]
        path_pattern_string = re.compile(r"^\$SPLUNK_DB")

        for section in config["indexes"].sections():
            for property_key in properties_to_validate:
                if not section.has_option(property_key):
                    continue

                setting = section.get_option(property_key)

                if path_pattern_string.search(setting.value) is not None:
                    continue

                yield FailMessage(
                    f"The stanza [{section.name}] has the property {property_key} and is "
                    "using a path that does not contain $SPLUNK_DB.",
                    file_name=setting.get_relative_path(),
                    line_number=setting.get_line_number(),
                    remediation="Please use a path that contains $SPLUNK_DB.",
                )


check_for_index_volume_usage = Check.disallowed_config_stanza_pattern(
    conf_file="indexes.conf",
    pattern=re.compile(r"^volume:"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_for_index_volume_usage",
    check_description="Check that `indexes.conf` does not declare volumes.",
    message="{stanza} defines a volume, which is prohibited in Splunk Cloud.",
    cert_min_version="1.1.20",
)


# -------------------
# inputs.conf
# -------------------
check_for_inputs_fifo_usage = Check.disallowed_config_stanza_pattern(
    conf_file="inputs.conf",
    pattern=re.compile(r"^fifo://"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_for_inputs_fifo_usage",
    check_description="Check that `default/inputs.conf` or `local/inputs.conf` or `users/<username>/local/inputs.conf` "
    "does not contain any `fifo://` stanzas.",
    message="{stanza} defines a fifo input, which is prohibited in Splunk Cloud.",
    cert_min_version="1.6.1",
)


check_inputs_conf_for_tcp = Check.disallowed_config_stanza_pattern(
    conf_file="inputs.conf",
    pattern=re.compile(r"^tcp://"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_tcp",
    check_description="Check that `default/inputs.conf` or `local/inputs.conf` or `users/<username>/local/inputs.conf` "
    "does not contain any `tcp://` stanzas.",
    message="{stanza} defines a tcp input, which is prohibited in Splunk Cloud.",
    remediation="Use `tcp-ssl` as an alternative to `tcp`.",
    cert_min_version="1.2.1",
)


check_inputs_conf_for_splunk_tcp = Check.disallowed_config_stanza_pattern(
    conf_file="inputs.conf",
    pattern=re.compile(r"^splunktcp://"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_splunk_tcp",
    check_description="Check that `default/inputs.conf` or `local/inputs.conf` or `users/<username>/local/inputs.conf` "
    "does not contain any `splunktcp://` stanzas.",
    message="{stanza} defines a splunktcp input, which is prohibited in Splunk Cloud.",
    remediation="Use `splunktcp-ssl` as an alternative to `splunktcp`.",
    cert_min_version="1.2.1",
)


check_inputs_conf_for_fschange = Check.disallowed_config_stanza_pattern(
    conf_file="inputs.conf",
    pattern=re.compile(r"^fschange:"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_fschange",
    check_description="Check that `default/inputs.conf` or `local/inputs.conf` or `users/<username>/local/inputs.conf` "
    "does not contain any `fschange://` stanzas.",
    message="{stanza} defines a fschange input, which is prohibited in Splunk Cloud.",
    cert_min_version="1.2.1",
)


check_inputs_conf_for_http_global_usage = Check.disallowed_config_stanza(
    conf_file="inputs",
    stanza="http",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_http_global_usage",
    remediation="Apps cannot ship a configured HEC token in inputs.conf. "
    "HEC tokens must be created by stack admins via ACS. "
    "Refer: https://docs.splunk.com/Documentation/Splunk/9.1.0/Data/UsetheHTTPEventCollector"
    "Remove [http] stanza from inputs.conf.",
    cert_min_version="1.2.1",
)


check_inputs_conf_for_http_inputs = Check.disallowed_config_stanza_pattern(
    conf_file="inputs",
    pattern=re.compile("^http://"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_http_inputs",
    check_description="Apps cannot ship a configured HEC token in inputs.conf. "
    "HEC tokens must be created by stack admins via ACS. "
    "Refer: https://docs.splunk.com/Documentation/Splunk/9.1.0/Data/UsetheHTTPEventCollector"
    "Remove [http://] stanza from inputs.conf.",
    cert_min_version="2.37.0",
)


check_inputs_conf_for_splunktcptoken = Check.disallowed_config_stanza_pattern(
    conf_file="inputs",
    pattern=re.compile("^splunktcptoken"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_splunktcptoken",
    check_description="Check that `inputs.conf` does not contain a `splunktcptoken` stanza.",
    cert_min_version="1.2.1",
)


class CheckInputsConfForBatch(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_inputs_conf_for_batch",
                description="""Check that batch input accesses files in a permitted way.

                        To be permissible, the batch input must meet the following criteria:
                            1) The file path needs to match a file in the directory "$SPLUNK_HOME/var/spool/splunk/"
                            2) The file name needs to be application specific "$SPLUNK_HOME/etc/apps/<my_app>"
                            3) The file name should not end with "stash" or "stash_new"
                        """,
                depends_on_config=("inputs",),
                cert_min_version="1.5.1",
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
        inputs_conf = config["inputs"]
        file_path = config["inputs"].get_relative_path()
        batch_input_regex_string = (
            r"^batch[:][\/][\/][$]SPLUNK_HOME[/\\]var[/\\]spool[/\\]splunk[/\\][.][.][.]stash(?!_new).+$"
        )
        batch_input_regex_string_for_app_dir = (
            r"^batch[:][\/][\/][$]SPLUNK_HOME[/\\]etc[/\\]apps[/\\]" + re.escape(app.name) + r"[/\\].*$"
        )
        batch_input_regex = re.compile(batch_input_regex_string)
        batch_input_regex_for_app_dir = re.compile(batch_input_regex_string_for_app_dir)
        for section in inputs_conf.sections():
            if section.name.startswith("batch://"):
                match = batch_input_regex.match(section.name)
                match_for_app_dir = batch_input_regex_for_app_dir.match(section.name)
                if not match and not match_for_app_dir:
                    yield FailMessage(
                        "The batch input is prohibited in Splunk Cloud"
                        " because it is destructive unless used for"
                        " event spooling using application-specific"
                        ' stash files (e.g.,"batch://$SPLUNK_HOME/'
                        'var/spool/splunk/...stash_APP_SPECIFIC_WORD" or'
                        " batch://$SPLUNK_HOME/etc/apps/<my_app>)."
                        f" Stanza: [{section.name}]. ",
                        file_name=file_path,
                        line_number=section.lineno,
                    )


class CheckInputsConfBatchHasRequiredAttributes(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_inputs_conf_batch_has_required_attributes",
                description="""Check that batch input has required attributes.
                        The following key/value pairs are required for batch inputs:
                        move_policy = sinkhole""",
                depends_on_config=("inputs",),
                cert_min_version="2.2.0",
                tags=(
                    Tags.CLOUD,
                    Tags.SPLUNK_APPINSPECT,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        inputs_conf = config["inputs"]
        file_path = inputs_conf.get_relative_path()
        for section in inputs_conf.sections():
            if section.name.startswith("batch") and (
                not section.has_option("move_policy") or section.get_option("move_policy").value != "sinkhole"
            ):
                yield FailMessage(
                    "The `move_policy = sinkhole` key value pair is missing in"
                    f" stanza: [{section.name}]. "
                    " You must include this pair when you define batch inputs.",
                    file_name=file_path,
                    line_number=section.lineno,
                )


check_inputs_conf_for_udp = Check.disallowed_config_stanza_pattern(
    conf_file="inputs",
    pattern=re.compile("^udp"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_udp",
    check_description="Check that inputs.conf does not have any UDP inputs.",
    cert_min_version="1.2.1",
)


check_inputs_conf_for_ssl = Check.disallowed_config_stanza(
    conf_file="inputs",
    stanza="SSL",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_ssl",
    check_description="Check that inputs.conf does not have any SSL inputs.",
    cert_min_version="1.6.1",
)


check_inputs_conf_for_remote_queue_monitor = Check.disallowed_config_stanza_pattern(
    conf_file="inputs",
    pattern=re.compile("^remote_queue:"),
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_inputs_conf_for_remote_queue_monitor",
    check_description="Check that inputs.conf does not have any remote_queue inputs.",
    cert_min_version="2.0.2",
)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.6.1")
def check_scripted_inputs_cmd_path_pattern(app: "App", reporter: "Reporter") -> None:
    """Check the cmd path pattern of scripted input defined in inputs.conf."""
    scripted_inputs_cmd_path_pattern = "script://(.*)$"
    absolute_path = [r"\$SPLUNK_HOME", "etc", "apps", app.name, "bin", ""]
    absolute_path_1 = "/".join(absolute_path)
    absolute_path_2 = "(\\\\|\\\\\\\\)".join(absolute_path)
    absolute_path_pattern = f"^({absolute_path_1}|{absolute_path_2})"
    relative_path_pattern = r"^\.(/bin/|(\\|\\\\)bin(\\|\\\\))"
    with_path_suffix_pattern = r".*\.path$"

    config_file_paths = app.get_config_file_paths("inputs.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = Path(directory, filename)
            inputs_conf = app.inputs_conf(directory)
            for section in inputs_conf.sections():
                # find cmd path of [script://xxx] stanzas in inputs.conf
                path = re.findall(scripted_inputs_cmd_path_pattern, section.name)
                manual_check_report = (
                    f"The `{directory}/inputs.conf` specifies a `script` input stanza."
                    " The cmd path of scripted input ends with `.path`."
                    " Please manual check whether this path pointer files"
                    " are inside of app container and use relative path."
                    f" Stanza: [{section.name}]. File: {file_path}, Line: {section.lineno}."
                )
                warn_report_output = (
                    f"The `{directory}/inputs.conf` specifies a `script` input stanza."
                    " The best pattern of cmd path of scripted input is"
                    " $SPLUNK_HOME/etc/apps/AppName/bin/."
                    f" Stanza: [{section.name}]. File: {file_path}, Line: {section.lineno}."
                )
                fail_report_output = (
                    f"The `{directory}/inputs.conf` specifies a `script` input stanza."
                    " This cmd path of scripted input is prohibited in Splunk Cloud."
                    f" Stanza: [{section.name}]. File: {file_path}, Line: {section.lineno}."
                )
                if path:
                    path = path[0]
                    if re.match(absolute_path_pattern, path):
                        if re.match(with_path_suffix_pattern, path):
                            reporter.manual_check(manual_check_report, file_path, section.lineno)
                    elif re.match(relative_path_pattern, path):
                        if re.match(with_path_suffix_pattern, path):
                            reporter.manual_check(manual_check_report, file_path, section.lineno)
                        else:
                            reporter.warn(warn_report_output, file_path, section.lineno)
                    else:
                        reporter.fail(fail_report_output, file_path, section.lineno)
                else:
                    reporter_output = "The scripted input does not exist in inputs.conf."
                    reporter.not_applicable(reporter_output)
    else:
        reporter_output = "`inputs.conf` does not exist."
        reporter.not_applicable(reporter_output)


class CheckScriptedInputsPythonVersion(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_scripted_inputs_python_version",
                description="Check that python version is python3 for scripted inputs defined in inputs.conf.",
                depends_on_config=("inputs",),
                cert_min_version="2.1.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PYTHON3_VERSION,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        if "inputs" in config:
            scripted_inputs_cmd_path_pattern = "script://(.*)$"
            inputs_conf = config["inputs"]
            for section in inputs_conf.sections():
                # find cmd path of [script://xxx] stanzas in inputs.conf
                path = re.findall(scripted_inputs_cmd_path_pattern, section.name)
                if path:
                    path = path[0]
                    if path.endswith(".py"):
                        if (
                            not section.options.get("python.version")
                            or section.options.get("python.version").value != "python3"
                        ):
                            yield FailMessage(
                                "The input stanza needs python.version flag set to python3 "
                                f"Stanza: [{section.name}].",
                                line_number=section.lineno,
                                file_name=inputs_conf.get_relative_path(),
                                remediation="Ensure that python.version is set to python3",
                            )


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.6.1")
def check_modular_inputs_scripts_exist_for_cloud(app: "App", reporter: "Reporter") -> None:
    """Check that there is a script file in `bin/` for each modular input
    defined in `README/inputs.conf.spec`.
    """
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        if modular_inputs.has_modular_inputs():
            file_path = Path("README", "inputs.conf.spec")
            for mi in modular_inputs.get_modular_inputs():
                # a) is there a cross plat file (.py) in default/bin?
                if mi.count_cross_plat_exes() > 0:
                    continue

                win_exes = mi.count_win_exes()
                linux_exes = mi.count_linux_exes()
                win_arch_exes = mi.count_win_arch_exes()
                linux_arch_exes = mi.count_linux_arch_exes()
                darwin_arch_exes = mi.count_darwin_arch_exes()

                # b) is there a file per plat in default/bin?
                if win_exes > 0 or linux_exes > 0:
                    continue

                # c) is there a file per arch?
                if win_arch_exes > 0 or linux_arch_exes > 0 or darwin_arch_exes > 0:
                    continue

                reporter_output = (
                    "No executable exists for the modular input " f"'{mi.name}'. File: {file_path}, Line: {mi.lineno}."
                )
                reporter.warn(reporter_output, file_path, mi.lineno)
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` was detected."
        reporter.not_applicable(reporter_output)


# -------------------
# setup.xml
# -------------------
class CheckSetupXml(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_setup_xml",
                description="Check that `setup.xml` does not exist in the app default or local folders.",
                cert_min_version="2.1.0",
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

    @Check.depends_on_files(
        basedir=["default", "local"],
        names=["setup.xml"],
        recurse_depth=0,
    )
    def check_setup_xml(self, app: "App", path_in_app: Path) -> Generator[CheckMessage, Any, None]:
        yield self._fail(path_in_app)

    @Check.depends_on_files(
        basedir=["users"],
        names=["setup.xml"],
        recurse_depth=2,
    )
    def check_user_setup_xml(self, app: "App", path_in_app: Path) -> Generator[CheckMessage, Any, None]:
        path_parts = path_in_app.parts
        # only fail users/<username>/local/setup.xml
        if len(path_parts) != 4 or path_parts[0] != "users" or path_parts[2] != "local":
            return
        yield self._fail(path_in_app)

    @staticmethod
    def _fail(path_in_app: Path) -> FailMessage:
        return FailMessage(
            "`setup.xml` is not permitted in Splunk Cloud as it behaves incorrectly with search head clustering",
            file_name=path_in_app,
            remediation="Consider leveraging HTML and JS and using setup view instead. See: "
            "https://dev.splunk.com/enterprise/docs/developapps/manageknowledge/setuppage/ "
            "for more info.",
        )


# -------------------
# transforms.conf
# -------------------
@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PYTHON3_VERSION,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.1.20")
def check_transforms_conf_for_external_cmd(app: "App", reporter: "Reporter", target_splunk_version: semver.VersionInfo):
    """Check that `transforms.conf` does not contain any transforms with malicious
    command scripts specified by `external_cmd=<string>` attribute.
    """
    basedir = ["local", "default"] + app.get_user_paths("local")
    config_file_paths = app.get_config_file_paths("transforms.conf", basedir=basedir)
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = Path(directory, filename)
            transforms_conf = app.get_config("transforms.conf", directory)
            external_command_stanzas = [
                section for section in transforms_conf.sections() if section.has_option("external_cmd")
            ]
            application_files = []
            if external_command_stanzas:
                application_files = list(app.iterate_files(types=[".py"]))
            for external_command_stanza in external_command_stanzas:
                # find `external_cmd` in the sections of transforms.conf
                external_command = external_command_stanza.get_option("external_cmd").value
                external_command_lineno = external_command_stanza.get_option("external_cmd").lineno
                external_command_regex_string = r"^[^\s]+\.py(?=\s)"
                external_command_regex = re.compile(external_command_regex_string)
                script_filename_matches = external_command_regex.search(external_command)
                if script_filename_matches:
                    # if the script type is python
                    script_filename = script_filename_matches.group(0)
                    # find the python file based on the script name
                    if target_splunk_version >= Tags.SPLUNK_8_0 and (
                        not external_command_stanza.has_option("python.version")
                        or external_command_stanza.get_option("python.version").value.lower() != "python3"
                    ):
                        reporter_output = (
                            f" The `transforms.conf` stanza [{external_command_stanza.name}]"
                            " is using python script as external command."
                            " but not specifying `python.version=python3`."
                            " Please specify `python.version=python3.`"
                        )
                        reporter.fail(reporter_output, file_path)
                        continue
                    script_matches = [file for file in application_files if file[1] == script_filename]
                    if not script_matches:
                        reporter_output = (
                            f" The `transforms.conf` stanza [{external_command_stanza.name}] is using the"
                            f" `external_cmd` property, but the {script_filename} file can't be found in the app."
                            f" File: {file_path}, Line: {external_command_lineno}."
                        )
                        reporter.fail(reporter_output, file_path, external_command_lineno)
    else:
        reporter_output = "`default/transforms.conf` does not exist."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="2.37.0")
def check_transforms_conf_for_external_cmd_cloud(app: "App", reporter: "Reporter") -> None:
    """Check that `transforms.conf` does not contain any transforms with non-python malicious
    command scripts specified by `external_cmd=<string>` attribute.
    """
    config_file_paths = app.get_config_file_paths("transforms.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = Path(directory, filename)
            transforms_conf = app.get_config("transforms.conf", directory)
            external_command_stanzas = [
                section for section in transforms_conf.sections() if section.has_option("external_cmd")
            ]
            for external_command_stanza in external_command_stanzas:
                # find `external_cmd` in the sections of transforms.conf
                external_command = external_command_stanza.get_option("external_cmd").value
                external_command_lineno = external_command_stanza.get_option("external_cmd").lineno
                external_command_regex_string = r"^[^\s]+\.py(?=\s)"
                external_command_regex = re.compile(external_command_regex_string)
                script_filename_matches = external_command_regex.search(external_command)
                if not script_filename_matches:
                    # manual check other `external_type`, such as executable
                    reporter_output = (
                        f"The `transforms.conf` stanza [{external_command_stanza.name}] is"
                        " using the `external_cmd` property."
                        f" Please investigate. Command: {external_command}. "
                        f"File: {file_path}, Line: {external_command_lineno}."
                    )
                    reporter.manual_check(reporter_output, file_path, external_command_lineno)


# -------------------
# audit.conf
# -------------------

check_audit_conf_deny_list = Check.disallowed_config_file(
    conf_file="audit",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_audit_conf_deny_list",
    reason="Splunk Cloud does not permit apps to control whether to perform cryptographic signing of "
    "events in _audit nor which certificates to use to that end.",
    cert_min_version="1.5.0",
)


# -------------------
# authentication.conf
# -------------------
class CheckStanzaOfAuthenticationConf(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_stanza_of_authentication_conf",
                description="Check that only role-mapping stanza is allowed in authenticaiton.conf as long as "
                "it doesn't map users to a cloud-internal role.",
                depends_on_config=("authentication",),
                cert_min_version="2.0.0",
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
        authentication_conf = config["authentication"]
        # Maps a Splunk role (from authorize.conf) to LDAP groups, SAML groups or groups passed in headers from proxy server
        # [roleMap_<authSettings-key>], [roleMap_<saml-authSettings-key>], [roleMap_proxySSO],
        # <Splunk RoleName> = <Group String>
        # Maps a SAML user to Splunk role(from authorize.conf), Realname and Email
        # [userToRoleMap_<saml-authSettings-key>]
        # <SAML User> = <Splunk RoleName>::<Realname>::<Email>
        # Maps a ProxySSO user to Splunk role (from authorize.conf)
        # [userToRoleMap_proxySSO]
        # <ProxySSO User> = <Splunk RoleName>
        allowed_stanzas = ["roleMap_", "userToRoleMap_"]
        stanza_list = authentication_conf.sections()
        for stanza in stanza_list:
            for allowed_stanza in allowed_stanzas:
                if stanza.name.startswith(allowed_stanza):
                    reporter_output = "Splunk admin role is prohibited from configuring in role-mapping."
                    if stanza.name.startswith("roleMap_"):
                        # check if option-key equal to 'admin'
                        if stanza.has_option("admin"):
                            yield FailMessage(
                                reporter_output,
                                line_number=stanza.get_option("admin").lineno,
                                file_name=authentication_conf.get_relative_path(),
                            )
                    else:
                        # check if option-value equal to 'admin' or startswith 'admin::'
                        for _, option_value, lineno in stanza.items():
                            if option_value == "admin" or option_value.startswith("admin::"):
                                yield FailMessage(
                                    reporter_output,
                                    line_number=lineno,
                                    file_name=authentication_conf.get_relative_path(),
                                )
                    break
            else:
                reporter_output = (
                    "Only role-mapping stanza is allowed in " f"authentication.conf, but [{stanza}] is found."
                )
                yield FailMessage(
                    reporter_output,
                    line_number=stanza.lineno,
                    file_name=authentication_conf.get_relative_path(),
                )


# -------------------
# bookmarks.conf
# -------------------

check_bookmarks_conf_deny_list = Check.disallowed_config_file(
    conf_file="bookmarks",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_bookmarks_conf_deny_list",
    reason="The bookmarks feature is not available in Splunk Cloud.",
    reporter_action=WarningMessage,
    cert_min_version="2.0.2",
)


# -------------------
# crawl.conf
# -------------------
# This check is redundant with deprecated features in Splunk 6.0, however
# Cloud Ops permits deprecated features that aren't harmful, so this check
# is necessary to prevent usage in Cloud.
check_introspection_of_cloud_filesystem = Check.disallowed_config_file(
    conf_file="crawl",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_introspection_of_cloud_filesystem",
    reason="crawl.conf allows Splunk to introspect the file system. Please do not use it.",
    cert_min_version="1.5.0",
)


# -------------------
# datatypesbnf.conf
# -------------------
check_datatypesbnf_conf_deny_list = Check.disallowed_config_file(
    conf_file="datatypesbnf",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_datatypesbnf_conf_deny_list",
    reason="datatypesbnf.conf is not permitted for Splunk Cloud pending further evaluation.",
    cert_min_version="1.5.0",
)


# -------------------
# default-mode.conf
# -------------------
check_default_mode_conf_deny_list = Check.disallowed_config_file(
    conf_file="default-mode",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_default_mode_conf_deny_list",
    reason="default-mode.conf describes the alternate setups used by the Splunk Light Forwarder and "
    "Splunk Universal Forwarder, which are not run in Splunk Cloud.",
    cert_min_version="1.5.0",
)


# -------------------
# deployment.conf
# -------------------
check_deployment_conf_deny_list = Check.disallowed_config_file(
    conf_file="deployment",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.SPLUNK_5_0,
        Tags.REMOVED_FEATURE,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_deployment_conf_deny_list",
    reason="deployment.conf has been removed and replaced by 1) deploymentclient.conf - for "
    "configuring Deployment Clients and 2) serverclass.conf - for Deployment Server server "
    "class configuration. Note that both deploymentclient.conf and serverclass.conf are "
    "prohibited for Splunk Cloud and App Certification, however.",
    cert_min_version="1.5.0",
)


# -------------------
# deploymentclient.conf
# -------------------
check_deployment_client_conf_deny_list = Check.disallowed_config_file(
    conf_file="deploymentclient",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_deploymentclient_conf_deny_list",
    reason="deploymentclient.conf configures the client of the deployment server, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# health.conf
# -------------------
check_health_conf_deny_list = Check.disallowed_config_file(
    conf_file="health",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_health_conf_deny_list",
    reason="Currently sc_admin is not able to see or configure the health report in Cloud.",
    cert_min_version="2.0.2",
)


# -------------------
# instance.cfg.conf
# -------------------
check_instance_cfg_conf_deny_list = Check.disallowed_config_file(
    conf_file="instance.cfg",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_instance_cfg_conf_deny_list",
    reason="instance.cfg.conf configures server/instance specific settings to set a GUID per "
    "server. Apps leave configuration up to Splunk administrators and should not "
    "configure these settings.",
    cert_min_version="1.5.0",
)


# -------------------
# literals.conf
# -------------------
check_literals_conf_deny_list = Check.disallowed_config_file(
    conf_file="literals",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_literals_conf_deny_list",
    reason="literals.conf allows overriding of text, such as search error strings, displayed in "
    "Splunk Web. Apps should not alter these strings as Splunk users/administrators may "
    "rely on them.",
    cert_min_version="1.5.0",
)


# -------------------
# messages.conf
# -------------------
check_messages_conf_deny_list = Check.disallowed_config_file(
    conf_file="messages",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_messages_conf_deny_list",
    reason="messages.conf allows overriding of messages/externalized strings. Apps should not "
    "alter these as Splunk users/administrators may rely on them.",
    cert_min_version="1.5.0",
)


# -------------------
# passwords.conf
# -------------------
check_passwords_conf_deny_list = Check.disallowed_config_file(
    conf_file="passwords",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_passwords_conf_deny_list",
    reporter_action=WarningMessage,
    reason="Secrets in passwords.conf are either plaintext, which is not allowed, or encrypted "
    "using host-specific splunk.secret. Pre-encrypted secrets will not work in Splunk "
    "Cloud.",
    cert_min_version="1.6.1",
)


# -------------------
# props.conf
# -------------------
check_that_no_configurations_of_default_source_type_in_props_conf = Check.disallowed_config_stanzas(
    conf_file="props",
    stanzas=SPLUNK_DEFAULT_SOURCE_TYPE,
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_that_no_configurations_of_default_source_type_in_props_conf",
    check_description="Check that the app does not contain configurations of default source type "
    "in props.conf, which will overwrite the configurations in "
    "system/default/props.conf and may affect other apps.",
    reporter_action=WarningMessage,
    message="{file_name} contains a [{stanza}] stanza, which is not allowed in Splunk Cloud as it "
    "may affect other apps.",
    cert_min_version="1.6.1",
)


# -------------------
# pubsub.conf
# -------------------
check_pubsub_conf_deny_list = Check.disallowed_config_file(
    conf_file="pubsub",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_pubsub_conf_deny_list",
    reason="pubsub.conf defines a custom client for the deployment server, this is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# segmenters.conf
# -------------------
check_segmenters_conf_deny_list = Check.disallowed_config_stanzas(
    conf_file="segmenters",
    stanzas=[
        "default",
        "full",
        "indexing",
        "search",
        "standard",
        "inner",
        "outer",
        "none",
        "whitespace-only",
        "meta-tokenizer",
    ],
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_segmenters_conf_deny_list",
    check_description="Check that app does not contain segmenters.conf with Splunk-defined stanza.",
    reason="A misconfigured segmenters.conf can result in unsearchable data that can only be "
    "addressed by re-indexing.",
    cert_min_version="1.5.0",
)


# -------------------
# serverclass.conf
# -------------------
check_serverclass_conf_deny_list = Check.disallowed_config_file(
    conf_file="serverclass",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_serverclass_conf_deny_list",
    reason="serverclass.conf configures server classes for use with a deployment server and is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# serverclass.seed.xml.conf
# -------------------
check_serverclass_seed_xml_conf_deny_list = Check.disallowed_config_file(
    conf_file="serverclass.seed.xml",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_serverclass_seed_xml_conf_deny_list",
    reason="serverclass.seed.xml.conf configures deploymentClient to seed a Splunk installation "
    "with applications at startup time, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# source-classifier.conf
# -------------------
check_source_classifier_conf_deny_list = Check.disallowed_config_file(
    conf_file="source-classifier",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_source_classifier_conf_deny_list",
    reason="source-classifier.conf configures system-wide terms to ignore when generating a "
    "sourcetype model, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# sourcetypes.conf
# -------------------
check_sourcetypes_conf_deny_list = Check.disallowed_config_file(
    conf_file="sourcetypes",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_sourcetypes_conf_deny_list",
    reason="sourcetypes.conf stores source type learning rules, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# splunk-launch.conf
# -------------------
check_splunk_launch_conf_deny_list = Check.disallowed_config_file(
    conf_file="splunk-launch",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_splunk_launch_conf_deny_list",
    reason="splunk-launch.conf configures environment values used at startup time, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# telemetry.conf
# -------------------
check_telemetry_conf_deny_list = Check.disallowed_config_file(
    conf_file="telemetry",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_telemetry_conf_deny_list",
    reason="telemetry.conf configures Splunk-internal settings, which is not permitted.",
    cert_min_version="1.5.0",
    exceptions_predicate=TelemetryConfigurationFile().check_allow_list,
)


# -------------------
# user-seed.conf
# -------------------
check_user_seed_conf_deny_list = Check.disallowed_config_file(
    conf_file="user-seed",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_user_seed_conf_deny_list",
    reason="user-seed.conf configures default login and password information, which is not permitted.",
    cert_min_version="1.5.0",
)


# -------------------
# wmi.conf
# -------------------
check_wmi_conf_deny_list = Check.disallowed_config_file(
    conf_file="wmi",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_wmi_conf_deny_list",
    reason="wmi.conf configures Splunk to ingest data via Windows Management Instrumentation, "
    "which is not permitted in Splunk Cloud.",
    cert_min_version="1.5.0",
)


# -------------------
# workload_pools.conf
# -------------------
check_workload_pools_deny_list = Check.disallowed_config_file(
    conf_file="workload_pools",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_workload_pools_conf_deny_list",
    reason="workload_pools.conf configures workload categories/pools, which is not permitted in Splunk Cloud.",
    cert_min_version="2.0.2",
)


# -------------------
# workload_rules.conf
# -------------------
check_workload_rules_deny_list = Check.disallowed_config_file(
    conf_file="workload_rules",
    tags=(
        Tags.SPLUNK_APPINSPECT,
        Tags.CLOUD,
        Tags.PRIVATE_APP,
        Tags.PRIVATE_VICTORIA,
        Tags.MIGRATION_VICTORIA,
        Tags.PRIVATE_CLASSIC,
    ),
    check_name="check_workload_rules_conf_deny_list",
    reason="workload_rules.conf defines rules to trigger actions on running search processes, "
    "which is not permitted in Splunk Cloud.",
    cert_min_version="2.0.2",
)


# ------------------------------------------------------------------------------
# Manual Checks Go Here
# ------------------------------------------------------------------------------


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL, Tags.CLOUD)
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_binary_files_without_source_code(app: "App", reporter: "Reporter") -> None:
    """Check that all executable binary files have matching source code. For any binary files, there
    should be a source code provided with the same name. Or, there should be a decalaration of what the
    binary file is all about in the app's REAMDE. Details for passing this check will be returned if you fail
    it."""
    if platform.system() == "Windows":
        # FIXME: tests needed
        reporter.manual_check("Matching source check will be done manually during code review.")
    else:
        source_types = [".cpp", ".c", ".java", ".h"]
        source_name_pool = {}
        app_files_iterator = app.iterate_files(types=source_types)
        for directory, file, _ in app_files_iterator:
            current_file_relative_path = Path(directory, file)
            source_name_without_extension = current_file_relative_path.name.split(".")[0]
            source_name_pool[source_name_without_extension] = current_file_relative_path

        # excluding docx, python and egg files to reduce false positives, and covered elsewhere
        exclude_types = [".docx", ".egg", ".py"]

        readme_names = find_readmes(app)
        readmes_dict = {}
        for readme_name in readme_names:
            full_file_path = Path(app.app_dir, readme_name)
            with codecs.open(str(full_file_path), encoding="utf-8", errors="ignore") as file:
                readmes_dict[readme_name] = file.read().lower()
        app_files_iterator = app.iterate_files(excluded_types=exclude_types)
        file_output_regex = re.compile(
            "^((?!ASCII text executable)(?!Unicode text executable)(?!UTF-8 text executable)(?!Perl script text executable).)*executable(.)*"
            + "|(.)*shared object(.)*"
            + "|(.)*binary(.)*"
            + "|^((?!Zip archive data).)*archive(.)*",
            re.DOTALL | re.IGNORECASE | re.MULTILINE,
        )

        for directory, file, _ in app_files_iterator:
            current_file_relative_path = Path(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)

            try:
                # file_output = subprocess.check_output(["file", "-b", current_file_full_path])
                # using magic library to substitute the original file cmd
                if current_file_relative_path in app.info_from_file:
                    file_output = app.info_from_file[current_file_relative_path]
                else:
                    file_output = magic.from_file(str(current_file_full_path))
            except Exception as error:
                # in case of any further exception, throw a manual check instead of an internal error
                # Exception could be UnicodeException, it doesn't have returncode, cmd or output attributes
                return_code = getattr(error, "returncode", "N/A")
                cmd = getattr(error, "cmd", "N/A")
                output = getattr(error, "output", "N/A")
                reporter.manual_check(
                    (
                        f"Please manually check {current_file_relative_path} ({return_code} {cmd} {output}) "
                        'Note if you are using macOS, you might need to "brew install libmagic". '
                        f"File: {current_file_relative_path}"
                    ),
                    current_file_relative_path,
                )
            else:
                if re.match(file_output_regex, file_output):
                    binary_name = current_file_relative_path.name.split(".")[0]
                    if binary_name in source_name_pool:
                        reporter_output = (
                            "Please ensure the binary files are safe. Source file: "
                            f" Bianry file: {current_file_relative_path}"
                            f" Format: {file_output}"
                            f" Source file: {source_name_pool[binary_name]}"
                        )
                        reporter.manual_check(reporter_output, current_file_relative_path)
                    elif readme_names:
                        readme_find = False
                        for readme_name, readme_content in iter(readmes_dict.items()):
                            if binary_name in readme_content or "# binary file declaration" in readme_content:
                                reporter_output = (
                                    "Please ensure the binary files are safe. Related info might be included in App README."
                                    f" Binary file: {current_file_relative_path}  Format: {file_output}  README: {readme_name}"
                                )
                                reporter.manual_check(reporter_output, current_file_relative_path)
                                readme_find = True
                                break
                        if not readme_find:
                            reporter_output = (
                                f"File: {current_file_relative_path}"
                                f" is a binary file (Format: {file_output}) but fail to"
                                " find any source file nor reference info."
                                " Please attach source code of this binary in the package,"
                                ' OR include any information of those binaries under "# Binary File Declaration" section'
                                " (You might need create one) in your App's REAMDE."
                                " We will manually review the source code of the binary."
                            )
                            reporter.fail(reporter_output)
                    else:
                        reporter_output = (
                            f"File: {current_file_relative_path}"
                            f" is a binary file (Format: {file_output}) but fail to"
                            " find any source file nor reference info."
                            " Please attach source code of this binary in the package,"
                            " OR create an App's README under root directory"
                            ' and include any information of those binaries under "# Binary File Declaration" section'
                            " (You might need create one) in README."
                            " We will manually review the source code of the binary."
                        )
                        reporter.fail(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.6.1")
def check_that_app_contains_any_windows_specific_components(app: "App", reporter: "Reporter") -> None:
    """Check that the app contains MS Windows specific components, which will not
    function correctly in Splunk Cloud whose OS should be Linux x64.
    """
    if platform.system() == "Windows":
        # FIXME: tests needed
        reporter.manual_check("Matching source check will be done manually during code review.")
    else:
        ms_windows_info = ["DOS batch file", "MS Windows", "CRLF line terminators"]
        ms_windows_file_types_in_crlf = [".ps1", ".psm1"]
        excluded_types = [".ico"]
        # only consider default directory here because local directory will be failed
        inputs_conf_path = Path("default", "inputs.conf")
        for path, info in iter(app.info_from_file.items()):
            # check if inputs.conf exists
            ext = path.suffix
            if inputs_conf_path == path:
                inputs_configuration_file = app.inputs_conf()

                banned_stanzas = [
                    stanza
                    for stanza in inputs_configuration_file.sections()
                    if re.search(r"^monitor:\/\/([a-zA-Z]\:|\.)\\", stanza.name)
                    or re.search(r"^script:\/\/([a-zA-Z]\:|\.)\\", stanza.name)
                    or re.search(r"^perfmon:\/\/", stanza.name)
                    or re.search(r"^MonitorNoHandle:\/\/", stanza.name)
                    or re.search(r"^WinEventLog:\/\/", stanza.name)
                    or re.search(r"^admon:\/\/", stanza.name)
                    or re.search(r"^WinRegMon:\/\/", stanza.name)
                    or re.search(r"^WinHostMon:\/\/", stanza.name)
                    or re.search(r"^WinPrintMon:\/\/", stanza.name)
                    or re.search(r"^WinNetMon:\/\/", stanza.name)
                    or re.search(r"^powershell2:\/\/", stanza.name)
                    or re.search(r"^powershell:\/\/", stanza.name)
                ]

                for stanza in banned_stanzas:
                    reporter_output = (
                        "default/inputs.conf contains a stanza for Windows inputs"
                        " that will not work correctly in Splunk Cloud."
                        " (http://docs.splunk.com/Documentation/Splunk/7.1.3/Admin/Inputsconf)"
                        f" Stanza: [{stanza.name}]. File: {path}, Line: {stanza.lineno}."
                    )
                    reporter.warn(reporter_output, path, stanza.lineno)
            else:
                for sub_info in ms_windows_info:
                    if sub_info in info:
                        if ext in excluded_types or (
                            sub_info == "CRLF line terminators" and ext not in ms_windows_file_types_in_crlf
                        ):
                            continue
                        reporter_output = (
                            f"The app works for MS Windows platform because {path} exists,"
                            f" which is {info}. It is only valid at MS Windows platform."
                            f" File: {path}"
                        )
                        reporter.warn(reporter_output, path)
                        break


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_reverse_shells(reporter: "Reporter") -> None:
    """Check that the app does not contain reverse shells."""
    reporter_output = "Please check for reverse shells."
    reporter.manual_check(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_auto_update_features(app: "App", reporter: "Reporter") -> None:
    """Check that the app does not implement auto-update features."""
    bin_directories = [bin_directory for arch in app.arch_bin_dirs for bin_directory in app.arch_bin_dirs[arch]]
    app_has_auto_update_capability = False
    for bin_directory in bin_directories:
        bin_directory_iterator = app.iterate_files(basedir=bin_directory)
        for directory, _, _ in bin_directory_iterator:
            app_has_auto_update_capability = True
            reporter_output = (
                f"Please check the {directory} directory for app auto-update features, which is prohibited."
            )
            reporter.manual_check(reporter_output, directory)
            break
    # If an app has nothing in the /bin directory and nothing in any of
    # the architecture-specific directories, it does not have the capacity to
    # update itself.
    if not app_has_auto_update_capability:
        reporter_output = "No scripts found in /bin or architecture-specific directories in app."
        reporter.not_applicable(reporter_output)


# This is a Cloud check that isn't tagged cloud because it always returns
# manual_check and prevents us from auto-vetting.
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.19")
def check_for_known_vulnerabilities_in_third_party_libraries(reporter: "Reporter") -> None:
    """Check third party libraries for known vulnerabilities. Splunk Cloud
    Application Security policy defines "Included application libraries have
    multiple vulnerabilities not covered by the components in Transit" as a
    moderate security risk and may or may not be permitted based on
    cumulative risk score.
    """
    reporter_output = (
        "Please check for known vulnerabilities in third-party"
        " libraries. Use these links:"
        " https://web.nvd.nist.gov/view/vuln/search."
        " and https://nvd.nist.gov/cvss.cfm"
    )
    reporter.manual_check(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.22")
def check_for_perl(app: "App", reporter: "Reporter") -> None:
    """Check if the app contains Perl scripts. Perl scripts will be inspected
    for compliance with Splunk Cloud security policy.
    """
    application_files = list(app.iterate_files(types=[".cgi", ".pl", ".pm"]))
    if application_files:
        for directory, file, _ in application_files:
            current_file_relative_path = Path(directory, file)
            reporter_output = f"File: {current_file_relative_path}"
            reporter.manual_check(reporter_output, current_file_relative_path)

    else:
        reporter_output = "No Perl scripts found in app."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL, Tags.JAVA)
@splunk_appinspect.cert_version(min="1.1.22")
def check_for_java(app: "App", reporter: "Reporter") -> None:
    """Check whether the app contains java files. Java files will be inspected
    for compliance with Splunk Cloud security policy.
    """
    application_files = list(app.iterate_files(types=[".class", ".jar", ".java"]))
    if application_files:
        for directory, file, _ in application_files:
            current_file_relative_path = Path(directory, file)
            reporter_output = f"java file found. File: {current_file_relative_path}"
            reporter.manual_check(reporter_output, current_file_relative_path)
    else:
        reporter_output = "No java files found in app."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.MANUAL)
def check_for_shell(app: "App", reporter: "Reporter") -> None:
    """Check whether the app contains shell files. Shell files will be manually inspected
    for compliance with Splunk Cloud security policy.
    """
    if platform.system() == "Windows":
        reporter_output = "Please run AppInspect using another OS to enable this check. Or use AppInspect API."
        reporter.not_applicable(reporter_output)
        return

    shell_types = [
        ".sh",
        ".bash",
        ".csh",
        ".dash",
        ".rc",
        ".fish",
        ".ksh",
        ".zsh",
        ".tcsh",
    ]
    shell_scripts = app.iterate_files(types=shell_types)
    for directory, file, _ in shell_scripts:
        file_path = Path(directory, file)
        file_full_path = app.get_filename(file_path)
        reporter_output = f"A shell script was found and need to be verified. File: {file_path}"
        reporter.manual_check(reporter_output, file_name=file_full_path)

    for directory, file, _ in app.iterate_files(excluded_types=shell_types):
        file_path = Path(directory, file)
        file_full_path = app.get_filename(file_path)
        mimetype = magic.from_file(str(file_full_path), mime=True)
        if mimetype == "text/x-shellscript":
            reporter_output = f"A shell script was found and need to be verified. File: {file_path}"
            reporter.manual_check(reporter_output, file_name=file_full_path)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.FUTURE,
    Tags.JAVA,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="2.11.1")
def check_java_sdk_version(app: "App", reporter: "Reporter") -> None:
    """Check that Splunk SDK for Java is up-to-date."""

    min_ver = semver.VersionInfo.parse("1.7.1")
    max_ver = semver.VersionInfo.parse("1.9.1")
    splunk_sdk_java = "splunk-sdk-java/"
    jar_files = app.iterate_files(types=[".jar"])

    for directory, jar, _ in jar_files:
        file_path = Path(directory, jar)
        full_file_path = app.get_filename(file_path)
        with zipfile.ZipFile(full_file_path, "r") as jar_zip:
            # Iterate over all the files in a jar file
            for file_info in jar_zip.infolist():
                file_name = file_info.filename

                # Filter out the non HttpService class files
                if not re.search("com/splunk/HttpService.*class$", file_name):
                    continue

                # Read the content of .class file in bytes
                # Convert it into string to extract the SDK version
                content = jar_zip.read(file_name).decode("latin-1")

                # If the .class file doesn't include "splunk-java-sdk/", filter it out.
                if splunk_sdk_java not in content:
                    continue

                # Extract the version from the .class file
                match = re.search(r"" + splunk_sdk_java + "([\d.]+)", content)
                version = match.group(1)
                try:
                    parsed_version = semver.VersionInfo.parse(version)
                except:
                    parsed_version = semver.VersionInfo.parse("0.0.0")

                if parsed_version < min_ver:
                    reporter_output = (
                        f"Detected an outdated version of the Splunk SDK for Java ({version}). "
                        f"Please upgrade to version {max_ver.major}.{max_ver.minor}.{max_ver.patch} or later. "
                        f"It is recomended to use the latest version."
                        f"File: {file_path}."
                    )
                    reporter.fail(reporter_output, file_path)
                elif parsed_version < max_ver:
                    reporter_output = (
                        f"Detected an outdated version of the Splunk SDK for Java ({version}). "
                        f"Please upgrade to version {max_ver.major}.{max_ver.minor}.{max_ver.patch} or later. "
                        f"It is recomended to use the latest version."
                        f"File: {file_path}."
                    )
                    reporter.fail(reporter_output, file_path)

                # Break the iteration if SDK version found
                break
