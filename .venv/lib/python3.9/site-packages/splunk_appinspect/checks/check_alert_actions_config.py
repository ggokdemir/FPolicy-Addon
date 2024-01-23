# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Alert actions structure and standards

Custom alert actions are defined in an **alert_actions.conf** file located in the **/default** directory of the app. For more, see [Custom alert actions overview](http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModAlertsIntro) and [alert_actions.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Alertactionsconf).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from semver import VersionInfo

import splunk_appinspect
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.alert_actions import AlertAction
    from splunk_appinspect.file_resource import FileResource
    from splunk_appinspect.reporter import Reporter


report_display_order = 20

logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.ALERT_ACTIONS_CONF)
@splunk_appinspect.cert_version(min="1.1.0")
def check_alert_actions_conf_exists(app: "App", reporter: "Reporter") -> None:
    """Check that a valid `alert_actions.conf` file exists at
    default/alert_actions.conf.
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        pass
    else:
        reporter_output = "An alert_actions.conf does not exist in the app bundle."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.ALERT_ACTIONS_CONF)
@splunk_appinspect.cert_version(min="1.1.1")
def check_alert_icon_exists_for_custom_alerts(app: "App", reporter: "Reporter") -> None:
    """Check that icon files defined for alert actions in `alert_actions.conf`
    exist.
    [Custom Alert Action Component Reference](http://docs.splunk.com/Documentation/Splunk/6.3.0/AdvancedDev/ModAlertsCreate)
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = Path("default", "alert_actions.conf")
        for alert_action in alert_actions.get_alert_actions():
            if alert_action.icon_path is not None:
                if alert_action.alert_icon().exists():
                    pass  # success, path is declared, file exists
                else:
                    lineno = alert_action.args["icon_path"][1]
                    reporter_output = (
                        f"The alert_actions.conf [{alert_action.name}] specified"
                        f" the icon_path value of {alert_action.relative_icon_path}, but did not"
                        f" find it. File: {filename}, Line: {lineno}."
                    )
                    reporter.fail(reporter_output, filename, lineno)

            else:
                lineno = alert_action.lineno
                reporter_output = (
                    f"No icon_path was specified for [{alert_action.name}]. File: {filename}, Line: {lineno}."
                )
                reporter.fail(reporter_output, filename, lineno)
    else:
        reporter_output = "No alert_actions.conf was found."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.ALERT_ACTIONS_CONF,
    Tags.CLOUD,
    Tags.PYTHON3_VERSION,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.PRIVATE_CLASSIC,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.1.0")
def check_alert_actions_exe_exist(app: "App", reporter: "Reporter") -> None:
    """Check that each custom alert action has a valid executable. If it does, further check
    if the executable is Python script. If it does, further check it's Python 3 compatible."""

    # a) is there an overloaded cmd in the stanza e.g. execute.cmd
    # b) is there a file in default/bin for the files in nix_exes & windows_exes (one of each for platform agnostic)
    # c) is there a file in a specific arch directory for all

    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = Path("default", "alert_actions.conf")
        for alert in alert_actions.get_alert_actions():
            if alert.alert_execute_cmd_specified():
                # Highlander: There can be only one...
                if alert.executable_files[0].exists():
                    _check_python_version_in_alert_action(alert, alert.executable_files[0], reporter, filename)
                else:
                    lineno = alert.args["alert.execute.cmd"][1]
                    mess = (
                        f"No alert action executable for {alert.alert_execute_cmd} was found in the "
                        f"bin directory. File: {filename}, Line: {lineno}."
                    )
                    reporter.fail(mess, filename, lineno)
            elif "command" in alert.args:
                continue
            else:
                # The following logic will only take effect when running interpreter
                # in Python 3
                for file_resource in alert_actions.find_exes(alert.name):
                    _check_python_version_in_alert_action(alert, file_resource, reporter, filename)

                # a) is there a cross plat file (.py, .js) in default/bin?
                if alert.count_cross_plat_exes() > 0:
                    continue

                # b) is there a file per plat in default/bin?
                if alert.count_linux_exes() > 0:
                    continue

                reporter_output = f"No executable was found for alert action {alert.name}."
                reporter.fail(reporter_output, filename, alert.lineno)

    else:
        reporter_output = "No `alert_actions.conf` was detected."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.ALERT_ACTIONS_CONF,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_payload_format(app: "App", reporter: "Reporter") -> None:
    """Check that each custom alert action's payload format has a value of `xml`
    or `json`.
    """
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = Path("default", "alert_actions.conf")
        for alert in alert_actions.get_alert_actions():
            for arg in alert.args:
                if arg == "payload_format":
                    if not alert.args["payload_format"][0] == "json" and not alert.args["payload_format"][0] == "xml":
                        lineno = alert.args["payload_format"][1]
                        reporter_output = (
                            "The alert action must specify"
                            " either 'json' or 'xml' as the"
                            f" payload. File: {filename}, Line: {lineno}."
                        )
                        reporter.fail(reporter_output, filename, lineno)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.ALERT_ACTIONS_CONF, Tags.MANUAL, Tags.CLOUD)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_explict_exe_args(app: "App", reporter: "Reporter") -> None:
    """Check whether any custom alert actions have executable arguments."""
    alert_actions = app.get_alert_actions()
    if alert_actions.has_configuration_file():
        filename = Path("default", "alert_actions.conf")
        for alert in alert_actions.get_alert_actions():
            for arg in alert.args:
                if "alert.execute.cmd.arg" in arg:
                    lineno = alert.args[arg][1]
                    reporter_output = (
                        "The alert action specifies executable arguments: "
                        f" {arg}, Manually verify these arguments"
                        " against the executable."
                        f" File: {filename}, Line: {lineno}."
                    )
                    reporter.manual_check(reporter_output, filename, lineno)


def _check_python_version_in_alert_action(
    alert: "AlertAction", file_resource: "FileResource", reporter: "Reporter", config_file_path: str
) -> None:
    if file_resource.file_path.name.endswith("py") and alert.python_version != "python3":
        reporter_output = (
            f" The `alert_actions.conf` stanza [{alert.name}] is using python script as alert script."
            " but not specifying `python.version=python3`. Please specify `python.version=python3.`"
        )
        reporter.fail(reporter_output, config_file_path)
    else:
        # Do nothing because it's not Python script
        pass
