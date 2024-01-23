# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Authentication.conf file standards

Ensure that `bindDNpassword` is not specified. For more, see [authentication.conf](http://docs.splunk.com/Documentation/Splunk/latest/Admin/Authenticationconf).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect
from splunk_appinspect.check_messages import CheckMessage, FailMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk import normalizeBoolean

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.reporter import Reporter


if TYPE_CHECKING:
    from splunk_appinspect.configuration_file import ConfigurationSection

logger = logging.getLogger(__name__)


# ACD-2339
@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT)
@splunk_appinspect.cert_version(min="1.5.0")
def check_authentication_conf_does_not_have_binddnpassword_property(app: "App", reporter: "Reporter") -> None:
    """Check that stanzas in `authentication.conf` do not use the the
    bindDNpassword property.
    """
    config_file_paths = app.get_config_file_paths("authentication.conf")
    if config_file_paths:
        for directory, filename in iter(config_file_paths.items()):
            file_path = Path(directory, filename)
            authentication_conf_file = app.authentication_conf(dir=directory)
            stanzas_with_bind_dn_password = [
                stanza_name
                for stanza_name in authentication_conf_file.section_names()
                if authentication_conf_file.has_option(stanza_name, "bindDNpassword")
            ]
            if stanzas_with_bind_dn_password:
                for stanza_name in stanzas_with_bind_dn_password:
                    lineno = authentication_conf_file.get_section(stanza_name).get_option("bindDNpassword").lineno
                    reporter_output = (
                        "authentication.conf contains the"
                        " property bindDNpassword. Plain text"
                        " credentials should not be included in an"
                        " app. Please remove the bindDNpassword= property."
                        f" Stanza: [{stanza_name}]. File: {file_path}, Line: {lineno}."
                    )
                    reporter.fail(reporter_output, file_path, lineno)
    else:
        reporter_output = "authentication.conf does not exist."
        reporter.not_applicable(reporter_output)


class CheckSamlAuthShouldNotTurnOffSignedAssertion(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_saml_auth_should_not_turn_off_signed_assertion",
                description="Check that saml-* stanzas in `authentication.conf` do not turn off signedAssertion property. ",
                depends_on_config=("authentication",),
                cert_min_version="1.6.0",
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

    def _is_signed_assertion_off(self, section: ConfigurationSection) -> bool:
        return not normalizeBoolean(section.get_option("signedAssertion").value.strip())

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        auth_conf = config["authentication"]
        if config["authentication"].has_option("authentication", "authType"):
            auth_type_value = auth_conf.get("authentication", "authType")

            if auth_type_value == "SAML":
                stanzas_with_signed_assertion = [
                    (section.name, section.lineno)
                    for section in auth_conf.sections_with_setting_key_pattern("signedAssertion")
                    if section.name.startswith("saml-") and self._is_signed_assertion_off(section)
                ]
                for stanza_name, stanza_lineno in stanzas_with_signed_assertion:
                    yield FailMessage(
                        "SAML signedAssertion property is turned off, which will introduce vulnerabilities. "
                        "Please turn the signedAssertion property on. "
                        f"Stanza: [{stanza_name}] ",
                        file_name=auth_conf.get_relative_path(),
                        line_number=stanza_lineno,
                    )


class CheckScriptedAuthenticationHasValidPythonVersionProperty(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_scripted_authentication_has_valid_python_version_property",
                description="Check that all the scripted authentications defined in `authentication.conf` "
                "are explicitly set the python.version to python3. ",
                depends_on_config=("authentication",),
                cert_min_version="2.1.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PYTHON3_VERSION,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        auth_conf = config["authentication"]

        if (
            auth_conf.has_option("authentication", "authType")
            and auth_conf.get("authentication", "authType") == "Scripted"
            and auth_conf.has_option("authentication", "authSettings")
        ):
            auth_settings_stanza_name = auth_conf.get("authentication", "authSettings")
            if auth_conf.has_section(auth_settings_stanza_name):
                python_version = None
                if auth_conf.has_option(auth_settings_stanza_name, "python.version"):
                    python_version = auth_conf.get(auth_settings_stanza_name, "python.version")
                if not auth_conf.has_option(auth_settings_stanza_name, "python.version") or python_version != "python3":
                    yield FailMessage(
                        f"Scripted authentication [{auth_settings_stanza_name}] is defined,"
                        "and python.version should be explicitly set to python3. ",
                        file_name=config["authentication"].get_relative_path(),
                        line_number=config["authentication"][auth_settings_stanza_name].get_line_number(),
                    )
                    return
            else:
                yield WarningMessage(
                    f"Script authentication configuration for [{auth_settings_stanza_name}] is missing. "
                )


class CheckRoleMapShouldNotMapSplunkSystemRole(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_role_map_should_not_map_splunk_system_role",
                description="Check that all map roles defined in `authentication.conf` "
                "do not map to `splunk-system-role`.",
                depends_on_config=("authentication",),
                cert_min_version="3.1.0",
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

    ROLE_MAP_PREFIX = "roleMap_"
    SPLUNK_SYSTEM_ROLE = "splunk-system-role"

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        auth_conf = config["authentication"]
        for section in auth_conf.sections():
            if section.name.startswith(self.ROLE_MAP_PREFIX) and section.has_option(self.SPLUNK_SYSTEM_ROLE):
                yield FailMessage(
                    f"Mapping role to splunk-system-role is not allowed. Stanza: [{section.name}].",
                    file_name=auth_conf.get_relative_path(),
                    line_number=auth_conf[section.name].get_line_number(),
                )
