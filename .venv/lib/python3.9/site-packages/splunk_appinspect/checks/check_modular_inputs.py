# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Modular inputs structure and standards

Modular inputs are configured in an **inputs.conf.spec** file located in the **/README** directory of the app. For more, see [Modular inputs overview](http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsIntro), [Modular inputs configuration](http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsSpec), and [Modular inputs basic example](http://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ModInputsBasicExample#Basic_implementation_requirements).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

import splunk_appinspect
from splunk_appinspect.check_messages import CheckMessage, FailMessage, NotApplicableMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy
    from splunk_appinspect.reporter import Reporter


report_display_order = 12

logger = logging.getLogger(__name__)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
@splunk_appinspect.display(report_display_order=1)
def check_inputs_conf(app: "App", reporter: "Reporter") -> None:
    """Check that a valid `inputs.conf.spec` file are located in the `README/`
    directory.
    """
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        pass
    else:
        reporter_output = (
            f"No `{modular_inputs.specification_filename}` file exists. Please check that "
            " a valid `inputs.conf.spec` file is located in the `README/`directory."
        )
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
@splunk_appinspect.display(report_display_order=2)
def check_inputs_conf_spec_has_stanzas(app: "App", reporter: "Reporter") -> None:
    """Check that README/inputs.conf.spec contains stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        file_path = Path(
            modular_inputs.specification_directory_path,
            modular_inputs.specification_filename,
        )

        inputs_specification_file = modular_inputs.get_specification_file()
        inputs_specification_file_stanzas_count = len(list(inputs_specification_file.sections()))
        if inputs_specification_file_stanzas_count == 0:
            reporter_output = (
                f"The inputs.conf.spec {modular_inputs.get_specification_app_filepath} "
                f"does not specify any stanzas. File: {file_path}"
            )
            reporter.fail(reporter_output, file_path)
        else:
            pass  # Success - stanzas were found
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` file exists."
        reporter.not_applicable(reporter_output)


class CheckInputsConfSpecStanzasHasPythonVersionProperty(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_inputs_conf_spec_stanzas_has_python_version_property",
                description="Check that all the modular inputs defined in inputs.conf.spec are explicitly"
                "set the python.version to python3",
                depends_on_config=("inputs",),
                cert_min_version="2.1.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.MODULAR_INPUTS,
                    Tags.PYTHON3_VERSION,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                    Tags.PRIVATE_CLASSIC,
                ),
            )
        )

    @Check.depends_on_files(
        basedir=["README"],
        names=["inputs.conf.spec"],
        recurse_depth=0,
        not_applicable_message="No `inputs.conf.spec` file exists.",
    )
    def check_inputs_conf_spec(self, app: "App", path_in_app: Path) -> Generator[CheckMessage, Any, None]:
        modular_inputs = app.get_modular_inputs()

        if not modular_inputs.has_modular_inputs():
            yield NotApplicableMessage("No modular inputs were detected.")
            return

        for config in (app.default_config, app.merged_config, *app.user_merged_config.values()):
            yield from self.check_inputs_config(app, config) or []

    def check_inputs_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        modular_inputs = app.get_modular_inputs()

        inputs_config = config["inputs"]

        global_default_python = None
        if inputs_config and inputs_config.has_option("default", "python.version"):
            global_default_python = inputs_config.get_option("default", "python.version")

        for modular_input in modular_inputs.get_modular_inputs():
            if modular_input.count_cross_plat_exes() == 0:
                continue

            input_python_version = None
            if inputs_config and inputs_config.has_option(modular_input.name, "python.version"):
                input_python_version = inputs_config.get_option(modular_input.name, "python.version")

            if input_python_version is not None:
                if input_python_version.value != "python3":
                    yield FailMessage(
                        f"Modular input `{modular_input.name}` specifies `{input_python_version.value}` "
                        "for `python.version`, which should be set to `python3`.",
                        file_name=input_python_version.get_relative_path(),
                        line_number=input_python_version.get_line_number(),
                        remediation="Set `python.version` to `python3`.",
                    )
            elif global_default_python is not None:
                if global_default_python.value != "python3":
                    yield FailMessage(
                        f"Modular input `{modular_input.name} does not specify a `python.version`, and "
                        f"the `[default]` stanza in {global_default_python.get_relative_path()} "
                        f"specifies {global_default_python.value}, which should be set to `python3`.",
                        file_name=global_default_python.get_relative_path(),
                        line_number=global_default_python.get_line_number(),
                        remediation="Set `python.version` to `python3`.",
                    )
            else:
                # inputs.conf does not exist or nothing specifies python.version
                section = None
                if inputs_config and inputs_config.has_section(modular_input.name):
                    section = inputs_config.get_section(modular_input.name)
                elif inputs_config and inputs_config.has_section("default"):
                    section = inputs_config.get_section("default")

                if section:
                    file_name = section.get_relative_path()
                    line_number = section.get_line_number()
                elif inputs_config:
                    file_name = inputs_config.get_relative_path()
                    line_number = None
                else:
                    file_name = "default/inputs.conf"
                    line_number = None

                yield FailMessage(
                    f"`python.version` is not specified for modular input `{modular_input.name}.",
                    file_name=file_name,
                    line_number=line_number,
                    remediation="Add `inputs.conf` and set `python.version` to `python3` in a "
                    f"`[default]` stanza, or explicitly in a `[{modular_input.name}]` "
                    "stanza.",
                )


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
def check_inputs_conf_spec_stanzas_have_properties(app: "App", reporter: "Reporter") -> None:
    """Check that modular inputs specify arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        if modular_inputs.has_modular_inputs():
            file_path = Path(
                modular_inputs.specification_directory_path,
                modular_inputs.specification_filename,
            )
            for modular_input in modular_inputs.get_modular_inputs():
                if not modular_input.args_exist():
                    lineno = modular_input.lineno
                    reporter_output = (
                        f"The stanza [{modular_input.name}] does not include any args. "
                        f"File: {file_path}, Line: {lineno}."
                    )
                    reporter.fail(reporter_output, file_path, lineno)
                else:
                    pass  # SUCCESS - The modular input has arguments
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` file exists."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
def check_inputs_conf_spec_has_no_duplicate_stanzas(app: "App", reporter: "Reporter") -> None:
    """Check that modular inputs do not have duplicate stanzas."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()
        file_path = Path(
            modular_inputs.specification_directory_path,
            modular_inputs.specification_filename,
        )

        for (
            error,
            line_number,
            section,
        ) in inputs_specification_file.errors:
            if error.startswith("Duplicate stanza"):
                reporter_output = f"{error}  File: {file_path}  Stanza: {section}  Line: {line_number}"
                reporter.warn(reporter_output, file_path, line_number)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` was detected."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
def check_inputs_conf_spec_has_no_duplicate_properties(app: "App", reporter: "Reporter") -> None:
    """Check that modular input stanzas do not contain duplicate arguments."""
    modular_inputs = app.get_modular_inputs()
    if modular_inputs.has_specification_file():
        inputs_specification_file = modular_inputs.get_specification_file()
        file_path = Path(
            modular_inputs.specification_directory_path,
            modular_inputs.specification_filename,
        )

        for (
            error,
            line_number,
            section,
        ) in inputs_specification_file.errors:
            if error.startswith("Repeat item name"):
                reporter_output = f"{error}  File: {file_path}  Stanza: {section}  Line: {line_number}"
                reporter.warn(reporter_output, file_path, line_number)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` was detected."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
def check_inputs_conf_spec_stanza_args_broken_correctly(app: "App", reporter: "Reporter") -> None:
    """Check lines breaks are included in configuration when using a modular
    input.
    """

    modular_inputs = app.get_modular_inputs()

    if modular_inputs.has_specification_file():
        raw_specification_file = modular_inputs.get_raw_specification_file()
        file_path = Path(
            modular_inputs.specification_directory_path,
            modular_inputs.specification_filename,
        )

        # From https://github.com/splunk/splunk-app-validator
        if len(raw_specification_file.decode().split("\n")) > 1:
            pass
        else:
            reporter_output = f"The inputs.conf.spec has incorrect line breaks. File: {file_path}"
            reporter.fail(reporter_output, file_path)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` was detected."
        reporter.not_applicable(reporter_output)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MODULAR_INPUTS)
@splunk_appinspect.cert_version(min="1.1.0")
def check_modular_inputs_scripts_exist(app: "App", reporter: "Reporter") -> None:
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
                else:
                    reporter_output = (
                        "No executable exists for the modular input"
                        f" '{mi.name}'. File: {file_path}, Line: {mi.lineno}."
                    )
                    reporter.fail(reporter_output, file_path, mi.lineno)
        else:
            reporter_output = "No modular inputs were detected."
            reporter.not_applicable(reporter_output)
    else:
        reporter_output = f"No `{modular_inputs.specification_filename}` was detected."
        reporter.not_applicable(reporter_output)
