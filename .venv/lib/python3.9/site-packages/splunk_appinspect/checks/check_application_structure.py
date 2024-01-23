# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Directory structure standards

Ensure that the directories and files in the app adhere to hierarchy standards.
"""
from __future__ import annotations

import logging
import string
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect
from splunk_appinspect.check_messages import CheckMessage, FailMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


report_display_order = 2
logger = logging.getLogger(__name__)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.0.0")
@splunk_appinspect.display(report_display_order=1)
def check_that_local_does_not_exist(app: "App", reporter: "Reporter") -> None:
    """Check that the 'local' directory does not exist.  All configuration
    should be in the 'default' directory.
    """
    if app.directory_exists("local"):
        reporter_output = "A 'local' directory exists in the app."
        reporter.fail(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.PRIVATE_APP, Tags.PRIVATE_VICTORIA, Tags.PRIVATE_CLASSIC
)
@splunk_appinspect.cert_version(min="1.1.9")
def check_for_local_meta(app: "App", reporter: "Reporter") -> None:
    """Check that the file 'local.meta' does not exist.  All metadata
    permissions should be set in 'default.meta'.
    """
    if app.file_exists("metadata", "local.meta"):
        file_path = Path("metadata", "local.meta")
        reporter_output = "Do not supply a local.meta file- put all settings" f" in default.meta. File: {file_path}"
        reporter.fail(reporter_output, file_path)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.PRIVATE_APP, Tags.PRIVATE_VICTORIA, Tags.PRIVATE_CLASSIC
)
@splunk_appinspect.cert_version(min="1.1.16")
def check_that_local_passwords_conf_does_not_exist(app: "App", reporter: "Reporter") -> None:
    """Check that `local/passwords.conf` or `users/<username>/local/passwords.conf does not exist.
    Password files are not transferable between instances.
    """

    def check_dir(basedir: Path):
        if app.directory_exists(basedir):
            if app.file_exists(basedir, "passwords.conf"):
                file_path = basedir.joinpath("passwords.conf")
                reporter.fail(
                    f"A 'passwords.conf' file exists in the '{basedir}' directory of the app. File: {file_path}",
                    file_path,
                )
            else:
                pass  # No passwords.conf so it passes
        else:
            return False
        return True

    any_local_exists = check_dir(Path("local"))
    for user_local in app.get_user_paths("local"):
        any_local_exists = check_dir(user_local) or any_local_exists

    if not any_local_exists:
        reporter.not_applicable("The local directory does not exist.")


class CheckFilenamesForSpaces(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_filenames_for_spaces",
                description="Check that app has no .conf or dashboard filenames that contain spaces. "
                "Splunk software does not support such files.",
                cert_min_version="1.5.0",
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
        LOCATIONS = (
            ("default", [".conf"]),
            ("default/data", [".xml"]),
            ("local", [".conf"]),
            ("local/data", [".xml"]),
            *[(user_local, [".conf"]) for user_local in app.get_user_paths("local")],
            *[(user_data, [".xml"]) for user_data in app.get_user_paths("local", "data")],
        )

        for basedir, types in LOCATIONS:
            for directory, file, _ in app.iterate_files(basedir=basedir, types=types):
                if " " not in file:
                    continue

                yield FailMessage(
                    "A conf or dashboard file contains a space in the filename.",
                    file_name=Path(directory, file),
                    remediation="Ensure conf and dashboard files do not contain spaces in their names.",
                )


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.6.0")
def check_that_app_name_config_is_valid(app: "App", reporter: "Reporter") -> None:
    """Check that the app name does not start with digits"""
    if app.package.app_cloud_name.startswith(tuple(string.digits)):
        reporter_output = "The app name (%s) cannot start with digits!" % app.name
        reporter.fail(reporter_output)
    else:
        pass
