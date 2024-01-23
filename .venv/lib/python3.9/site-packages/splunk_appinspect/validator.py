# Copyright 2019 Splunk Inc. All rights reserved.

"""
This is the core validation logic used to centralize validation run-time.

This module contains functions to accumulate and run checks under configurations
as needed.
"""
from __future__ import annotations

import concurrent.futures
import logging
from concurrent.futures import Future
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Generator, KeysView, Optional, Type

import splunk_appinspect
from splunk_appinspect.checks import Check, Group
from splunk_appinspect.constants import Tags
from splunk_appinspect.python_analyzer.trustedlibs.trusted_libs_manager import TrustedLibsManager
from splunk_appinspect.validation_report import ApplicationValidationReport, ValidationReport

from . import infra
from .reporter import Reporter

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.app_package_handler import AppPackageHandler
    from splunk_appinspect.listeners import Listener
    from splunk_appinspect.reporter import ReportRecord
    from splunk_appinspect.resource_manager import ResourceManager, ResourceManagerContext


logger = logging.getLogger(__name__)
MAX_CHECK_RETRIES = 2

try:
    import sys

    reload(sys)
    sys.setdefaultencoding("utf8")  # pylint: disable=no-member
except NameError:
    # py3 default encoding is utf-8
    pass


def _emit(eventname, listeners, *args):
    for listener in listeners:
        listener.handle_event(eventname, *args)


class Validator:
    """
    The core validation class. Meant to encapsulate the entire validation workflow.

    Attributes:
        app_package_handler: Contains the AppPackage objects to be used for validation.
        args: Key value arguments that will be used to modify check election, check run-time, and check execution.
        groups_to_validate: Groups that contain the filtered checks to perform.
        listeners: Listeners that are used to hook into events of the validation workflow.
        resource_manager: used to help facilitate dependency injection for checks.
        app_class: represents the overall Splunk App being validator. It exposes functionality for interacting
            with an app.
        appinspect_version: The version of AppInspect being used for validation.
        app_names: All the names of the apps being validated.
        validation_report: The report object containing validation results.

    """

    def __init__(
        self,
        app_package_handler: "AppPackageHandler",
        args: Optional[dict[str, Any]] = None,
        groups_to_validate: Optional[list["Group"]] = None,
        listeners: Optional[list["Listener"]] = None,
        resource_manager: Optional["ResourceManager"] = None,
        app_class: Optional[Type["App"]] = None,
        report_filter: Optional[Callable[["ReportRecord"], bool]] = None,
    ) -> None:
        """
        The core validation class. Meant to encapsulate the entire validation workflow.

        Args:
            app_package_handler: Contains the AppPackage objects to be used for validation.
            args: Key value arguments that will be used to modify check selection, check run-time, and check execution.
            groups_to_validate: Groups that contain the filtered checks to perform.
            listeners: Listeners that are used to hook into events of the validation workflow.
            resource_manager: used to help facilitate dependency injection for checks.
            app_class: represents the overall Splunk App being validator. It exposes functionality for
                interacting with an app.
            report_filter: an optional filter to apply to the report records in order to accept or discard them.
                The callable should return True if the record should be accepted, False otherwise.


        """
        self.app_package_handler: "AppPackageHandler" = app_package_handler
        self.app_names: KeysView[Path] = self.app_package_handler.apps.keys()
        self.args: dict[str, Any] = args if args else {}
        self.groups_to_validate: list["Group"] = groups_to_validate if groups_to_validate else []
        self.resource_manager: "ResourceManager" = (
            resource_manager if resource_manager else splunk_appinspect.resource_manager.ResourceManager()
        )
        self.app_class: Type["App"] = app_class if app_class else splunk_appinspect.App
        self.listeners: list["Listener"] = listeners if listeners else []
        self.__validation_groups: Optional[list["Group"]] = None
        self.validation_report: ValidationReport = ValidationReport()

        if app_class is not None:
            logger_output = f"The custom app_class '{app_class}' was provided to the validate_packages function."
            logger.info(logger_output)

        self.appinspect_version: str = splunk_appinspect.version.__version__
        self.args["appinspect_version"] = self.appinspect_version
        self.report_filter = report_filter

        logger.info(f"Executing checks using Splunk AppInspect version {self.appinspect_version}")

    def __emit_event(self, eventname: str, _, *args) -> None:
        for listener in self.listeners:
            listener.handle_event(eventname, *args)

    @property
    def packaging_groups(self) -> list[Group]:
        """
        Returns:
            the internal and custom packaging checks.

        """

        # Find packaging checks built into the CLI/library
        consolidated_groups = {}
        packaging_grps = splunk_appinspect.checks.groups(included_tags=[Tags.PACKAGING_STANDARDS])
        for grp in packaging_grps:
            consolidated_groups[grp.name] = grp

        # Find all the checks including custom packaging checks may have been provided.
        # Ignore duplicates already listed in packaging_grps
        custom_checks = []
        for grp in self.groups_to_validate:
            for check in grp.checks(included_tags=[Tags.PACKAGING_STANDARDS]):
                add_check = True
                for pkg_grp in packaging_grps:
                    if pkg_grp.has_check(check):
                        add_check = False

                if add_check:
                    custom_checks.append((grp, check))

        # Create a new group (possibly could do a clone/copy)
        for grp, check in custom_checks:
            if grp.module in consolidated_groups:
                consolidated_groups[grp.name].add_check(check)
            else:
                custom_group = Group(grp.module, [check], grp.report_display_order)
                consolidated_groups[custom_group.name] = custom_group

        return list(consolidated_groups.values())

    @property
    def validation_groups(self) -> list[Group]:
        """
        Returns:
            the internal and custom checks not marked as packaging checks.

        """

        if self.__validation_groups:
            return self.__validation_groups

        self.__validation_groups = []

        for grp in self.groups_to_validate:
            selected_chks = list(grp.checks(excluded_tags=[Tags.PACKAGING_STANDARDS]))
            custom_group = Group(grp.module, selected_chks, grp.report_display_order)
            self.__validation_groups.append(custom_group)

        return self.__validation_groups

    def validate(self) -> None:
        """Validates the package supplied by the package handler."""
        self.validation_report = ValidationReport()
        self.validation_report.validation_start()
        self.__emit_event("start_validation", self.listeners, self.app_names)

        try:
            self.__emit_event("start_package_preparation", self.listeners, self.app_package_handler)

            python_analyzer_enable = False
            for group in self.validation_groups:
                if group.has_checks(included_tags=[Tags.AST]):
                    python_analyzer_enable = True
                    self.__emit_event("enable_python_analyzer", self.listeners)
                    break
            trusted_libs_manager = TrustedLibsManager()
            apps = [
                self.app_class(
                    package=app_package,
                    python_analyzer_enable=python_analyzer_enable,
                    trusted_libs_manager=trusted_libs_manager,
                )
                for app_package in self.app_package_handler.app_packages
            ]
            splunk_args = {}

            if "splunk_version" in self.args:
                splunk_args["splunk_version"] = self.args["splunk_version"]

            if "included_tags" not in self.args:
                self.args["included_tags"] = []
            if "excluded_tags" not in self.args:
                self.args["excluded_tags"] = []

            splunk_args["apps"] = apps
            (
                splunk_args["included_tags"],
                splunk_args["excluded_tags"],
            ) = infra.refine_tag_set(self.args["included_tags"], self.args["excluded_tags"])
            splunk_args["target_splunk_version"] = splunk_appinspect.splunk.TargetSplunkVersion(
                splunk_args["included_tags"]
            )

            self.__emit_event("finish_package_preparation", self.listeners, self.app_package_handler)

            with self.resource_manager.context(splunk_args) as context:
                for app in apps:
                    application_validation_report = ApplicationValidationReport(app, self.args)
                    application_validation_report.validation_start()
                    self.__emit_event("start_app", self.listeners, app)

                    application_validation_report.results = []
                    if Tags.PACKAGING_STANDARDS not in self.args["excluded_tags"]:
                        self.__emit_event("start_package_validation", self.listeners, app)
                        packaging_results = self.__run_checks(app, context, self.packaging_groups)
                        application_validation_report.results = packaging_results
                        self.__emit_event("finish_package_validation", self.listeners, app)

                    if application_validation_report.has_invalid_package:
                        # If there are packaging issues, skip the remaining checks.
                        skipped_results = self.__skip_checks(self.validation_groups)
                        for grp, check, rpt in skipped_results:
                            application_validation_report.results.append((grp, check, rpt))
                    else:
                        if self.validation_groups:
                            self.__emit_event("start_app_validation", self.listeners, app)
                            validation_results = self.__run_checks(app, context, self.validation_groups)
                            for grp, check, rpt in validation_results:
                                application_validation_report.results.append((grp, check, rpt))
                            self.__emit_event("finish_app_validation", self.listeners, app)

                    application_validation_report.validation_completed()
                    self.__emit_event("finish_app", self.listeners, app, application_validation_report)
                    self.validation_report.add_application_validation_report(application_validation_report)

            self.validation_report.validation_completed()

        except Exception as exception:
            self.validation_report.validation_error(exception)
            raise
        finally:
            self.__emit_event(
                "finish_validation",
                self.listeners,
                self.app_names,
                self.validation_report,
            )

    def __execute_check(self, context: "ResourceManagerContext", app: "App", check: "Check") -> "Reporter":
        self.__emit_event("start_check", self.listeners, check)

        retries = 0
        reporter = check.run(app, context, self.report_filter)

        while reporter.state() == "error" and retries < MAX_CHECK_RETRIES:
            retries += 1
            logger.info(f"Retrying check because it produced an error, check_name={check.name}")
            self.__emit_event("retry_check", self.listeners, check, reporter)
            reporter = check.run(app, context)

        self.__emit_event("finish_check", self.listeners, check, reporter)
        return reporter

    def __dispatch_check(
        self,
        threadpool: concurrent.futures.ThreadPoolExecutor,
        context: "ResourceManagerContext",
        app: "App",
        check: "Check",
    ) -> Future:
        return threadpool.submit(self.__execute_check, context, app, check)

    def __skip_checks(self, groups: list[Group]) -> Generator[tuple["Group", "Check", "Reporter"], Any, None]:
        for grp in groups:
            for check in grp.checks():
                self.__emit_event("start_check", self.listeners, check)
                reporter = splunk_appinspect.reporter.Reporter()
                reporter.start()
                reporter.skip("Skipping due to package validation issues.")
                logger.debug("Skipping %s", check)
                reporter.complete()
                self.__emit_event("finish_check", self.listeners, check, reporter)
                yield grp, check, reporter

    def __run_checks(
        self, app: "App", context: "ResourceManagerContext", groups: list[Group]
    ) -> list[tuple["Group", "Check", "Reporter"]]:
        futures = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as threadpool:
            logger.debug("Beginning validation execution.")
            for group in groups:
                logger.debug(
                    ("Executing start_group event for Group: %s Group_Checks: %s Listeners: %s"),
                    group,
                    list(group.checks()),
                    self.listeners,
                )

                self.__emit_event("start_dispatching_group", self.listeners, group, group.checks())
                # This runs the initial checks
                future_checks = list(
                    map(
                        lambda check: (
                            check,
                            self.__dispatch_check(threadpool, context, app, check),
                        ),
                        group.checks(),
                    )
                )
                # This accumulates the called checks
                futures.append((group, future_checks))
                self.__emit_event("finish_dispatching_group", self.listeners, group, group.checks())

                logger.debug(
                    ("Executing finish_dispatching_group event for Group: %s Group_Checks: %s Listeners: %s"),
                    group,
                    list(group.checks()),
                    self.listeners,
                )

        # After exiting 'with', all checks are run.
        # future.result() calls a promise that returns the reporter
        return_values = []
        for group_object, checks in futures:
            for check_object, future in checks:
                return_values.append((group_object, check_object, future.result()))

        return return_values


def validate_packages(
    app_package_handler: "AppPackageHandler",
    args: Optional[dict[str, Any]] = None,
    groups_to_validate: Optional[list["Group"]] = None,
    listeners: Optional[list["Listener"]] = None,
    resource_manager: Optional["ResourceManager"] = None,
    app_class: Optional[Type["App"]] = None,
    report_filter: Optional[Callable[["ReportRecord"], bool]] = None,
) -> ValidationReport:
    """
    A legacy entry point for the validation process.

    Args:
        app_package_handler: Contains the AppPackage objects to be used for validation.
        args: Key value arguments that will be used to modify check selection, check run-time, and check execution.
        groups_to_validate: Groups that contain the filtered checks to perform.
        listeners: Listeners that are used to hook into events of the validation workflow.
        resource_manager: used to help facilitate dependency injection for checks.
        app_class: represents the overall Splunk App being validator.
            It exposes functionality for interacting with an app.
        report_filter: an optional filter to apply to the report records in order to accept or discard them.
            The callable should return True if the record should be accepted, False otherwise.

    Returns:
        The report object containing validation results.

    """
    validator = Validator(
        app_package_handler, args, groups_to_validate, listeners, resource_manager, app_class, report_filter
    )
    validator.validate()
    return validator.validation_report
