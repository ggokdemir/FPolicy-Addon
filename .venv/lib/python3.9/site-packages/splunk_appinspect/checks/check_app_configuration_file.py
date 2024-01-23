# Copyright 2019 Splunk Inc. All rights reserved.

"""
### App.conf standards

The **app.conf** file located at **default/app.conf** provides key application information and branding. For more, see [app.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf).
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

import splunk_appinspect
from splunk_appinspect.app_util import AppVersionNumberMatcher
from splunk_appinspect.check_messages import (
    CheckMessage,
    FailMessage,
    NotApplicableMessage,
    SkipMessage,
    WarningMessage,
)
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.configuration_file import ConfigurationProxy, MergedConfigurationProxy
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk import normalizeBoolean
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.app_configuration_file import AppConfigurationFile
    from splunk_appinspect.configuration_file import ConfigurationFile, ConfigurationSetting
    from splunk_appinspect.custom_types import ConfigurationProxyType
    from splunk_appinspect.reporter import Reporter


report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD)
@splunk_appinspect.cert_version(min="1.1.20")
def check_that_setup_has_not_been_performed(app: "App", reporter: "Reporter") -> None:
    """Check that `default/app.conf` setting `is_configured` = False."""
    if app.file_exists("default", "app.conf"):
        filename = Path("default", "app.conf")
        app_conf = app.app_conf()
        if app_conf.has_section("install") and app_conf.has_option("install", "is_configured"):
            # Sets to either 1 or 0
            is_configured = normalizeBoolean(app_conf.get("install", "is_configured"))
            if is_configured:
                lineno = app_conf.get_section("install").get_option("is_configured").lineno
                reporter_output = (
                    "The app.conf [install] stanza has the"
                    " `is_configured` property set to true."
                    " This property indicates that a setup was already"
                    f" performed. File: {filename}, Line: {lineno}."
                )
                reporter.fail(reporter_output, filename, lineno)
            else:
                pass  # Pass - The property is true
        else:
            pass  # Pass - The stanza or property does not exist.
    else:
        reporter_output = "`default/app.conf` does not exist."
        reporter.not_applicable(reporter_output)


class CheckForValidPackageId(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_valid_package_id",
                description="Check that the [package] stanza in app.conf has a valid `id` value."
                "See https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf"
                " for details.",
                depends_on_config=("app",),
                cert_min_version="2.0.1",
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
        # NOTE: check_that_extracted_splunk_app_contains_default_app_conf_file already
        # exists for failing apps that do not contain a default/app.conf, this check
        # will return not_applicable for that case
        app_conf = config["app"]
        filename = app_conf.get_relative_path()
        uncompressed_directory_name = app.name
        package_id = id_name = None

        try:
            package_configuration_section = app_conf.get_section("package")
            package_id_object = package_configuration_section.get_option("id")
            package_id = package_id_object.value
            if not _is_package_id_valid(package_id_object):
                lineno = package_configuration_section.get_option("id").lineno
                yield FailMessage(
                    f"The app.conf [package] stanza's has an invalid 'id' property: {package_id}."
                    " For the `id` property, it must contain only letters, numbers, `.` (dot),"
                    " `_` (underscore) and `-`(hyphen) characters, should not start with numbers, "
                    " and cannot end with a dot character."
                    " Besides, some reserved names are prohibited."
                    " See https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf for details.",
                    remediation="Fix the app.conf [package] `id` to use a valid naming convention",
                    file_name=filename,
                    line_number=lineno,
                )

            if package_id != uncompressed_directory_name:
                # Fail, app id is present but id does not match directory name
                lineno = package_configuration_section.get_option("id").lineno
                yield FailMessage(
                    "The `app.conf` [package] stanza has an `id` property"
                    " that does not match the uncompressed directory's name."
                    f" `app.conf` [package] id: {package_id}"
                    f" uncompressed directory name: {uncompressed_directory_name}.",
                    remediation="Fix the app.conf [package] `id` to match the app directory name",
                    file_name=filename,
                    line_number=lineno,
                )

        except splunk_appinspect.configuration_file.NoOptionError:
            lineno_package = package_configuration_section.lineno
            yield WarningMessage(
                "No `id` property found in [package] stanza. `id` is required by the Splunk platform to "
                "enable updates of apps published to Splunkbase. If you intend to publish this app to Splunkbase, "
                "please add an `id` to the [package] stanza."
                "If this app will be installed as a Private app on a Splunk Cloud stack, and the target stack is "
                "running a Splunk Cloud platform version earlier than 8.2.2112, the `id` property is *required* for "
                "installation.",
                remediation="Add an `id` attribute to the [package] stanza in app.conf",
                file_name=filename,
                line_number=lineno_package,
            )

        except splunk_appinspect.configuration_file.NoSectionError:
            yield WarningMessage(
                "No `[package]` section found in app.conf file.",
                remediation="Add an [package] stanza to app.conf with `id` attribute",
                file_name=filename,
            )

        try:
            app_conf.has_option("id", "name")
            id_configuration_section = app_conf.get_section("id")
            id_name = id_configuration_section.get_option("name").value

            if package_id != id_name:
                name_lineno = id_configuration_section.get_option("name").lineno
                yield FailMessage(
                    "The `app.conf` [package] stanza has an `id` property"
                    " that does not match the `name` property of the [id] stanza."
                    f" `app.conf` [package] id: {package_id}"
                    f" [id] name: {id_name}.",
                    remediation="Fix app.conf [package] `id` to match [id] `name`",
                    file_name=filename,
                    line_number=name_lineno,
                )

        except splunk_appinspect.configuration_file.NoOptionError:
            lineno_id = id_configuration_section.lineno
            yield WarningMessage(
                "No `name` attribute specified in the [id] stanza in app.conf."
                " This attribute is required for app installation.",
                remediation="Add an [id] stanza to app.conf with `name` attribute",
                file_name=filename,
                line_number=lineno_id,
            )

        except splunk_appinspect.configuration_file.NoSectionError:
            yield WarningMessage(
                "No [id] stanza specified in app.conf. An id` attribute in the [id] "
                "stanza is required for app installation.",
                remediation="Add an [id] stanza to app.conf with `name` attribute",
                file_name=filename,
            )

        if not app.package.does_working_artifact_contain_app_manifest():
            yield SkipMessage("Splunk App packages doesn't contain `app.manifest file`. No `app.manifest` was found.")
            return

        manifest_filename = Path("app.manifest")
        try:
            filepath = open(Path(app.app_dir, "app.manifest"), "r")
            manifest_json = json.loads(filepath.read())
            manifest_name = manifest_json.get("info").get("id").get("name")

            if package_id is not None and package_id != manifest_name:
                id_lineno = package_configuration_section.get_option("id").lineno
                yield FailMessage(
                    "An `app.manifest` file isn't required, but if present it must contain an info.id.name attribute,"
                    " which must match the value of the [package] stanza's `id` attribute in `app.conf`."
                    f" `app.conf` [package] id: {package_id}"
                    f" [info][id] name: {manifest_name}."
                    f" `File`: {filename} or {manifest_filename}, `[package]id Line`: {id_lineno}.",
                    remediation="Fix app.manifest info.id.name attribute to match app.conf [package] id",
                    file_name=manifest_filename,
                )

            if id_name is not None and id_name != manifest_name:
                name_lineno = id_configuration_section.get_option("name").lineno
                yield FailMessage(
                    "The `app.manifest` file isn't required, but if present it must contain info.id.name attribute,"
                    " which must match the value  of the [id] stanza's `name` attribute in `app.conf`."
                    f" `app.conf` [id] name: {id_name}"
                    f" [info][id] name: {manifest_name}."
                    f" `File`: {filename} or {manifest_filename}, `[id]name Line`: {name_lineno}.",
                    remediation="Fix app.manifest info.id.name attribute to match app.conf [id] name",
                    file_name=manifest_filename,
                )

        except ValueError:
            yield NotApplicableMessage(
                "No `name` attribute specified under `[info][id]` " f"section of app.manifest.",
                file_name=manifest_filename,
            )
            return

        except AttributeError:
            yield NotApplicableMessage(
                "No `[info]` or `[id]` stanza found in app.manifest." f"Or app.manifest file is empty.",
                file_name=manifest_filename,
            )
            return

        except:
            yield NotApplicableMessage(
                f"The `app.manifest` file can't be loaded properly." f" Please submit the file in correct format.",
                file_name=manifest_filename,
            )
            return


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT)
@splunk_appinspect.cert_version(min="1.6.0")
def check_for_invalid_app_names(app: "App", reporter: "Reporter") -> None:
    """Check that `default/app.conf` has `author = <some words are not about Splunk>` must not
    has attributes `label` or `description` with values of `Splunk App for XXXX`.
    """
    if app.file_exists("default", "app.conf"):
        filename = Path("default", "app.conf")
        app_conf = app.app_conf()
        is_author_splunk = _is_author_splunk(app_conf)
        if app_conf.has_option("ui", "label"):
            name = app_conf.get("ui", "label")
            if _is_with_value_of_splunk_app_for(name) and not is_author_splunk:
                lineno = app_conf.get_section("ui").get_option("label").lineno
                reporter_output = (
                    "For the app.conf [ui] stanza's 'label' attribute,"
                    " names of community-built apps must not start with 'Splunk'."
                    " For example 'Splunk app for Awesome' is inappropriate,"
                    f" but 'Awesome app for Splunk' is OK. File: {filename}, Line: {lineno}."
                )
                reporter.fail(reporter_output, filename, lineno)
        if app_conf.has_option("launcher", "description"):
            name = app_conf.get("launcher", "description")
            if _is_with_value_of_splunk_app_for(name) and not is_author_splunk:
                lineno = app_conf.get_section("launcher").get_option("description").lineno
                reporter_output = (
                    "For the app.conf [launcher] stanza's 'description' attribute,"
                    " apps built by 3rd parties should not have names starting with Splunk."
                    " For example 'Splunk app for Awesome' is inappropriate,"
                    f" but 'Awesome app for Splunk' is OK. File: {filename}, Line: {lineno}."
                )
                reporter.fail(reporter_output, filename, lineno)
    else:
        reporter_output = "`default/app.conf` does not exist."
        reporter.not_applicable(reporter_output)


def _is_with_value_of_splunk_app_for(name: str) -> bool:
    # the regex expression is for searching:
    # "splunk (addon|add on|add-on|app)s for"
    return bool(re.search(r"splunk\s*(add(\s*|-*)on|app)(s*)\s*for", name, re.IGNORECASE))


def _is_author_splunk(app_conf: "AppConfigurationFile") -> bool:
    if app_conf.has_option("launcher", "author"):
        if re.search(r"splunk", app_conf.get("launcher", "author"), re.IGNORECASE):
            return True
    for name in app_conf.section_names():
        if re.search(r"author=", name):
            if re.search(r"splunk", name, re.IGNORECASE):
                return True

            if app_conf.has_option(name, "company"):
                return bool(re.search(r"splunk", app_conf.get(name, "company"), re.IGNORECASE))
    return False


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_no_install_source_checksum(app: "App", reporter: "Reporter") -> None:
    """Check in `default/app.conf`, 'local/app.conf' and each `users/<username>/local/app.conf`,
    that install_source_checksum not be set explicitly."""
    file_folder_list = ["default", "local", *app.get_user_paths("local")]
    stanza = "install_source_checksum"
    for folder in file_folder_list:
        if not app.file_exists(folder, "app.conf"):
            reporter_output = f"`{folder}/app.conf` does not exist."
            reporter.not_applicable(reporter_output)
            continue

        filename = Path(folder, "app.conf")
        app_conf = app.app_conf(folder)
        if not app_conf.has_section("install"):
            continue  # Pass - The stanza does not exist.

        if not app_conf.has_option("install", stanza):
            continue  # Pass - The property does not exist

        if not app_conf.get("install", stanza):
            continue  # Pass - The property is empty.

        lineno = app_conf.get_section("install").get_option(stanza).lineno
        reporter_output = (
            f"For the app.conf [install] stanza's `{stanza}` attribute,"
            " it records a checksum of the tarball from which a given app was installed"
            " or a given app's local configuration was installed."
            " Splunk Enterprise will automatically populate this value during installation."
            " Developers should *not* set this value explicitly within their app!"
            f" File: {filename}, Line: {lineno}."
        )
        reporter.fail(reporter_output, filename, lineno)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
    Tags.FUTURE,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_no_install_source_local_checksum(app: "App", reporter: "Reporter") -> None:
    """Check in `default/app.conf`, 'local/app.conf' and each `users/<username/local/app.conf,
    that install_source_local_checksum not be set explicitly."""
    stanza = "install_source_local_checksum"
    file_folder = ["default", "local", *app.get_user_paths("local")]
    for folder in file_folder:
        if not app.file_exists(folder, "app.conf"):
            reporter_output = f"`{folder}/app.conf` does not exist."
            reporter.not_applicable(reporter_output)
            continue

        filename = Path(folder, "app.conf")
        app_conf = app.app_conf(folder)

        if not app_conf.has_section("install"):
            continue  # Pass - The stanza does not exist.

        if not app_conf.has_option("install", stanza):
            continue  # Pass - The property does not exist

        if not app_conf.get("install", stanza):
            continue  # Pass - The property is empty.

        lineno = app_conf.get_section("install").get_option(stanza).lineno
        reporter_output = (
            f"For the app.conf [install] stanza's `{stanza}` attribute,"
            " it records a checksum of the tarball from which a given app was installed"
            " or a given app's local configuration was installed."
            " Splunk Enterprise will automatically populate this value during installation."
            " Developers should *not* set this value explicitly within their app!"
            f" File: {filename}, Line: {lineno}."
        )
        reporter.fail(reporter_output, filename, lineno)


class CheckForTriggerStanza(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_trigger_stanza",
                description="Check that `default/app.conf`, `local/app.conf` and all `users/<username>/local/app.conf` "
                "don't have a `reload.<CONF_FILE>`, where CONF_FILE is a non-custom conf. "
                "(https://docs.splunk.com/Documentation/Splunk/latest/Admin/Appconf#.5Btriggers.5D)",
                depends_on_config=("app",),
                cert_min_version="1.7.2",
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

    def check_default_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        yield from self._check_triggers(app, config, Path("metadata", "default.meta"), None)

    def check_merged_config(self, app: "App", config: "MergedConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        default_meta = app.get_meta("default.meta") if app.file_exists("metadata", "default.meta") else None
        yield from self._check_triggers(app, config, Path("metadata", "local.meta"), default_meta)

    def check_user_merged_config(
        self, app: "App", config: "MergedConfigurationProxy"
    ) -> Generator[CheckMessage, Any, None]:
        default_meta = app.get_meta("default.meta") if app.file_exists("metadata", "default.meta") else None
        local_meta = (
            app.get_meta("local.meta", meta_file=default_meta)
            if app.file_exists("metadata", "local.meta")
            else default_meta
        )
        for meta_path in app.get_user_paths("metadata", "local.meta"):
            yield from self._check_triggers(app, config, meta_path, local_meta)

    @staticmethod
    def _check_triggers(
        app: "App", config: "ConfigurationProxyType", meta_path: Path, default_meta: Optional["ConfigurationFile"]
    ) -> Generator[CheckMessage, Any, None]:
        if not config["app"].has_section("triggers"):
            return

        settings = config["app"].get_section("triggers").settings()
        if app.file_exists(meta_path):
            conf_permissions = _get_conf_permissions(
                app.get_meta(
                    meta_path.name,
                    directory=meta_path.parent,
                    meta_file=default_meta,
                )
            )
        elif default_meta is not None:
            conf_permissions = _get_conf_permissions(default_meta)
        else:
            conf_permissions = {}

        for conf_name, lineno in _get_reloaded_splunk_confs(settings):
            if _is_exported(conf_name, conf_permissions):
                yield FailMessage(
                    f"{conf_name}.conf is a Splunk defined conf, which should not "
                    "be configured in [trigger] stanza. Per the documentation, "
                    "it should be configured only for custom config file. "
                    "Please remove this line.",
                    file_name=config["app"].get_relative_path(),
                    line_number=lineno,
                )
            else:
                yield WarningMessage(
                    f"{conf_name}.conf is a Splunk defined conf, which should not "
                    "be configured in [trigger] stanza. Per the documentation, "
                    "it should be configured only for custom config file. "
                    f"However, the {conf_name}.conf is not shared with other apps. "
                    "Suggest to remove this line.",
                    file_name=config["app"].get_relative_path(),
                    line_number=lineno,
                )


class CheckForValidUiLabel(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_valid_ui_label",
                description="Check that the `default/app.conf` or `local/app.conf` or `users/<username>/local/app.conf` "
                "contains a label key value pair in the [ui] stanza and the length is between 5 and 80 "
                "characters inclusive.",
                depends_on_config=("app",),
                cert_min_version="2.3.0",
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

    MIN_LENGTH = 5
    MAX_LENGTH = 80

    def check_config(self, app: "App", config: "ConfigurationProxyType") -> Generator[CheckMessage, Any, None]:
        # return not_applicable if ui stanza does not exist
        if not config["app"].has_section("ui"):
            if isinstance(config, ConfigurationProxy):
                message = f"`{config['app'].get_relative_path()}` does not contain [ui] stanza."
            elif isinstance(config, MergedConfigurationProxy):
                filenames = [
                    f"`{proxy['app'].get_relative_path()}`" for proxy in config.proxies if proxy["app"] is not None
                ]
                message = f"{' or '.join(filenames)} does not contain [ui] stanza."
            else:
                raise ValueError(f"Unexpected type for config: {type(config)}")

            yield NotApplicableMessage(
                message,
                file_name=config["app"].get_relative_path(),
            )
            return

        # return warning if label field does not exist in ui stanza
        if not config["app"].has_option("ui", "label"):
            yield WarningMessage(
                "`label` is required in [ui] stanza.",
                file_name=config["app"].get_relative_path(),
                line_number=config["app"]["ui"].get_line_number(),
            )
            return

        label_option = config["app"]["ui"]["label"]
        if len(label_option.value) < self.MIN_LENGTH or len(label_option.value) > self.MAX_LENGTH:
            yield WarningMessage(
                "The length of `label` field under [ui] stanza should between 5 to 80 characters.",
                file_name=config["app"].get_relative_path(),
                line_number=config["app"]["ui"]["label"].get_line_number(),
            )
            return


class CheckReloadTriggerForAllCustomConfs(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_reload_trigger_for_all_custom_confs",
                description="Check that custom config files have a corresponding reload trigger in app.conf. "
                "Without a reload trigger the app will request a restart on any change to the "
                "config file, which may be a negative experience for end-users.",
                depends_on_config={"app"},
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

    def check(self, app: "App") -> None:
        # Collect all custom configs once
        if not (app.custom_conf_files or app.user_custom_conf_files):
            yield NotApplicableMessage("App does not contain any custom config files.")
            return

        self._config.depends_on_config = (
            {"app"}
            | {conf_file.stem for conf_file in app.custom_conf_files}
            | {conf_file.stem for conf_file in app.user_custom_conf_files}
        )

        yield from super().check(app) or []

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        app_conf = config["app"]

        if not (app_conf and app_conf.has_section("triggers")):
            yield FailMessage(
                "App contains one or more custom configs but does not have a `[triggers]` stanza in app.conf.",
                file_name=app_conf.get_relative_path() if app_conf else "default/app.conf",
            )
            return

        triggers_stanza = app_conf["triggers"]

        # Check that all the custom confs have a reload trigger
        # e.g. "banana.conf" -> "reload.banana" in app.conf
        for path_in_app in app.custom_conf_files | app.user_custom_conf_files:
            file_name = path_in_app.stem
            reload_option_name = f"reload.{file_name}"

            if triggers_stanza.has_option(reload_option_name):
                reload_trigger = triggers_stanza.get_option(reload_option_name)

                if reload_trigger.value == "never":
                    yield WarningMessage(
                        f"App contains custom config {path_in_app} but the `[triggers]` stanza in "
                        "app.conf specifies `never` for the reload trigger.",
                        file_name=reload_trigger.get_relative_path(),
                        line_number=reload_trigger.get_line_number(),
                    )
            else:
                yield FailMessage(
                    f"App contains custom config {path_in_app} but the `[triggers]` stanza in "
                    "app.conf does not specify a reload trigger.",
                    file_name=app_conf.get_relative_path(),
                )


def _get_conf_permissions(default_meta: "ConfigurationFile") -> dict[str, bool]:
    conf_permissions = {}
    meta_stanza_pattern = r"(?=\/).*"
    for section in default_meta.sections():
        name = re.sub(meta_stanza_pattern, "", section.name) or "default"
        is_exported = section.has_option("export") and section.get_option("export").value == "system"
        conf_permissions[name] = is_exported
    return conf_permissions


def _get_reloaded_splunk_confs(
    settings: Generator["ConfigurationSetting", Any, None]
) -> Generator[tuple[str, Optional[int]], Any, None]:
    splunk_conf_allow_list = ["passwords.conf"]
    reload_pattern = r"^reload\."
    for setting in settings:
        if re.match(reload_pattern, setting.name):
            conf_name = re.sub(reload_pattern, "", setting.name)
            conf_file_name = f"{conf_name}.conf"
            if conf_file_name in SPLUNK_DEFINED_CONFS and conf_file_name not in splunk_conf_allow_list:
                yield conf_name, setting.lineno


def _is_exported(conf_name: str, conf_permissions: dict[str, bool]) -> bool:
    if conf_name in conf_permissions:
        return conf_permissions[conf_name]

    default_stanza = "default"
    if default_stanza in conf_permissions:
        return conf_permissions[default_stanza]

    return False


def _is_package_id_with_hyphen(package_id: "ConfigurationSetting") -> bool:
    """Check that if package id contains '-'"""
    return "-" in package_id.value


def _is_package_id_valid(package_id: "ConfigurationSetting") -> bool:
    """
    Check rules for package id:
        1. must contain only letters, numbers, "." (dot), and "_" (underscore) characters.
           Besides, '-' should be add into the white list, see https://jira.splunk.com/browse/ACD-3636.
        2. must not end with a dot character
        3. must not be any of the following names: CON, PRN, AUX, NUL,
           COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
           LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, LPT9
    Best practice:
        1. do not endwith '.tar', '.tgz', '.tar.gz' and '.spl'
    """
    blcak_list = [
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "COM1",
        "COM2",
        "COM3",
        "COM4",
        "COM5",
        "COM6",
        "COM7",
        "COM8",
        "COM9",
        "LPT1",
        "LPT2",
        "LPT3",
        "LPT4",
        "LPT5",
        "LPT6",
        "LPT7",
        "LPT8",
        "LPT9",
    ]

    # check for rule 1
    pattern = re.compile(r"[a-zA-Z_.-][a-zA-Z0-9_.-]*")
    results = re.findall(pattern, package_id.value)
    if not results.__contains__(package_id.value):
        return False
    # check for rule 2 and best practice
    if package_id.value.endswith((".", ".tar", ".tar.gz", ".tgz", ".spl")):
        return False
    # check for rule 3
    if package_id.value in blcak_list:
        return False

    return True


class CheckCustomConfReplication(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_custom_conf_replication",
                description="Check that custom .conf files have a a matching "
                "`conf_replication_include.<conf_file_name>` value in server.conf, under "
                "the `[shclustering]` stanza, to ensure that configurations are "
                "synchronized across Search Head Clusters.",
                depends_on_config={"server"},
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
        # Collect all custom configs once
        if not (app.custom_conf_files or app.user_custom_conf_files):
            yield NotApplicableMessage("App does not contain any custom config files.")
            return

        self._config.depends_on_config = (
            {"server"}
            | {conf_file.stem for conf_file in app.custom_conf_files}
            | {conf_file.stem for conf_file in app.user_custom_conf_files}
        )

        yield from super().check(app) or []

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        server_conf = config["server"]

        if not (server_conf and server_conf.has_section("shclustering")):
            yield WarningMessage(
                "App contains one or more custom configs but does not have a `[shclustering]` stanza "
                "in server.conf.",
                file_name=server_conf.get_relative_path() if server_conf else "default/server.conf",
            )
            return

        shclustering_stanza = server_conf["shclustering"]

        # Check that all the custom confs have a conf_replication_include
        for custom_conf in app.custom_conf_files | app.user_custom_conf_files:
            file_name = custom_conf.stem
            replication_option_name = f"conf_replication_include.{file_name}"

            if not shclustering_stanza.has_option(replication_option_name):
                yield WarningMessage(
                    f"App contains `{custom_conf}` but {replication_option_name} setting is not set in server.conf",
                    file_name=shclustering_stanza.get_relative_path(),
                )


def _is_splunk_default_app_id(app_id: str) -> bool:
    # "python_upgrade_readiness_app" not added in the below list though it is available in splunk cloud instances
    # because the app is also available on Splunkbase.
    # Also, the following apps that are present on splunk cloud instances are not mentioned in the below list
    # beccause they fail check_that_app_name_config_is_valid` : "075-cloudworks", "100-s2-config",
    # "100-whisper", "100-whisper-common", "100-whisper-indexer", "100-cloudworks-wlm" and "100-whisper-searchhead"
    splunk_default_apps = {
        "alert_logevent",
        "alert_webhook",
        "appsbrowser",
        "cloud_administration",
        "dmc",
        "introspection_generator_addon",
        "journald_input",
        "launcher",
        "learned",
        "legacy",
        "prometheus",
        "sample_app",
        "scsaudit",
        "search",
        "search_artifacts_helper",
        "splunk-dashboard-studio",
        "splunk_gdi",
        "splunk_httpinput",
        "splunk_instrumentation",
        "splunk_internal_metrics",
        "splunk_metrics_workspace",
        "splunk_product_guidance",
        "splunk_rapid_diag",
        "splunk_secure_gateway",
        "user-prefs",
        "data_manager",
        "dynamic-data-self-storage-app",
        "splunkclouduf",
        "splunk_instance_monitoring",
        "tos",
        "missioncontrol000-self-service",
        "splunk_ta_data_manager",
        "splunk_datasets_addon",
        "framework",
        "_cluster_admin",
        "_cluster",
    }

    return app_id in splunk_default_apps


class CheckForDefaultSplunkApp(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_default_splunk_app",
                description="Check that `id` attribute under the package stanza in app.conf"
                "does not match with the Splunk Default App names",
                depends_on_config=("app",),
                cert_min_version="2.37.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        # NOTE: check_that_extracted_splunk_app_contains_default_app_conf_file already
        # exists for failing apps that do not contain a default/app.conf, this check
        # will return not_applicable for that case
        app_conf = config["app"]
        if app_conf.has_section("package"):
            filename = app_conf.get_relative_path()
            package_configuration_section = app_conf.get_section("package")
            if package_configuration_section.has_option("id"):
                package_id = package_configuration_section.get_option("id").value
                if _is_splunk_default_app_id(package_id):
                    yield FailMessage(
                        "The id attribue under package stanza in app.conf has value {package_id} which matches with one of the Splunk default apps.",
                        remediation="Change the `id` attribute under package stanza in app.conf.",
                        file_name=filename,
                    )


class CheckForUpdatesDisabled(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_for_updates_disabled",
                description="Check the [package] stanza in app.conf specifies check_for_updates as False for Private apps.",
                depends_on_config=("app",),
                cert_min_version="2.37.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        app_conf = config["app"]

        if app_conf.has_section("package"):
            package_section = app_conf.get_section("package")
            if not package_section.has_option("check_for_updates"):
                yield WarningMessage(
                    "No check_for_updates property found in [package] stanza. check_for_updates property should be set to False for private apps not uploaded to Splunkbase.",
                    file_name=app_conf.get_relative_path(),
                    line_number=package_section.get_line_number(),
                )
            elif package_section.has_option("check_for_updates"):
                val = package_section.get_option("check_for_updates").value
                if normalizeBoolean(val):
                    yield WarningMessage(
                        "check_for_updates property found in [package] stanza is set to True for private app not uploaded to Splunkbase. It should be set to False for private apps not uploaded to Splunkbase.",
                        file_name=app_conf.get_relative_path(),
                        line_number=package_section.get_option("check_for_updates").lineno,
                    )
        else:
            yield WarningMessage(
                "No [package] stanza found in app.conf. check_for_updates property under [package] stanza in app.conf should be set to False for private apps not uploaded to Splunkbase.",
                file_name=app_conf.get_relative_path(),
            )
