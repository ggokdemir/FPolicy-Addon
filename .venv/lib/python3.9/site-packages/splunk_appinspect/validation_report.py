# Copyright 2019 Splunk Inc. All rights reserved.
"""Splunk AppInspect Validation Report module"""
from __future__ import annotations

import collections
import copy
import logging
from datetime import datetime
from typing import TYPE_CHECKING, Any, Optional, Union

import splunk_appinspect
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.checks import Check, Group
    from splunk_appinspect.reporter import Reporter


logger = logging.getLogger(__name__)


class ValidationReport(object):
    """Validation Report for inspection. Each validation report could contain multiple application reports."""

    def __init__(self) -> None:
        self._application_validation_reports: list[ApplicationValidationReport] = []
        self._metrics: dict[str, Union[None, float, datetime]] = {
            "start_time": None,
            "end_time": None,
            "execution_time": None,
        }
        # can be `not_executed`, `in_progress`, `completed`, or `error`
        self.status: str = "not_executed"
        self.errors: list[Exception] = []

    def add_application_validation_report(self, application_validation_report: ApplicationValidationReport) -> None:
        self.application_validation_reports.append(application_validation_report)

    @property
    def application_validation_reports(self) -> list[ApplicationValidationReport]:
        return self._application_validation_reports

    @application_validation_reports.setter
    def application_validation_reports(self, value: list[ApplicationValidationReport]) -> None:
        self._application_validation_reports = value

    def get_summary(self) -> dict[str, int]:
        summary_dict: dict[str, int] = collections.defaultdict(int)

        for application_validation_report in self.application_validation_reports:
            for key, value in iter(application_validation_report.get_summary().items()):
                summary_dict[key] += value

        return summary_dict

    @property
    def metrics(self) -> dict[str, Union[None, float, datetime]]:
        return self._metrics

    @metrics.setter
    def metrics(self, value: dict[str, Union[None, float, datetime]]) -> None:
        self._metrics = value

    def validation_start(self) -> None:
        """Helper function to be called at the start of a validation."""
        self.metrics["start_time"] = datetime.now()
        if self.status != "error":
            self.status = "in_progress"

    def validation_completed(self) -> None:
        # TODO: rename to validation_complete to align with start
        """Helper function to be called at the end of a validation."""
        self.metrics["end_time"] = datetime.now()
        self.metrics["execution_time"] = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()
        if self.status != "error":
            self.status = "completed"

    def validation_error(self, exception: Exception) -> None:
        """Helper function to be called when an error is encountered during validation."""
        self.status = "error"
        self.errors.append(exception)

    @property
    def has_invalid_packages(self) -> bool:
        """Returns boolean if packaging checks failed or error."""
        return any(rpt.has_invalid_package for rpt in self.application_validation_reports)


class ApplicationValidationReport(object):
    """Splunk AppInspect inspection report for an app."""

    def __init__(self, application: "App", run_parameters: Optional[dict[str, Any]]) -> None:
        self.run_parameters: Optional[dict[str, str]] = copy.copy(run_parameters)

        self.app_author: str = application.author
        self.app_description: str = application.description
        self.app_version: str = application.version
        self.app_name: str = application.label
        self.package_id: Optional[str] = application.package_id
        self.app_hash: str = application._get_hash()  # pylint: disable=W0212

        self._results: list[tuple["Group", "Check", "Reporter"]] = []
        self._metrics: dict[str, Union[None, float, datetime]] = {
            "start_time": None,
            "end_time": None,
            "execution_time": None,
        }

        # can be `not_executed`, `in_progress`, `completed`, or `error`
        self.status: str = "not_executed"
        self.errors: list[Exception] = []

    def groups(self) -> list[list[tuple["Group", "Check", "Reporter"]]]:
        """
        Returns:
             A list of lists containing tuples of a Group object, a Check object, and a Reporter object.
            Each nested list is all the checks grouped together based on the group they belong to. This means that each
            check in a nested list should contain the same group object::

                [
                    [(group, check, reporter), (group, check, reporter), ... ]
                    [(group, check, reporter), (group, check, reporter), ... ]
                ]

        """
        grouped_results = collections.defaultdict(list)
        # Get the results, adding basic ordering
        for group, check, reporter in self.results:
            key = f"{group.report_display_order}-{group.name}"
            grouped_results[key].append((group, check, reporter))

        # Return the groups in order of key
        return [group_with_key[1] for group_with_key in sorted(grouped_results.items(), key=lambda t: t[0])]

    @property
    def results(self) -> list[tuple["Group", "Check", "Reporter"]]:
        """
        Returns:
             List of results as that is really just a list of the checks.

        """
        return self._results

    @results.setter
    def results(self, new_results: list[tuple["Group", "Check", "Reporter"]]):
        self._results = new_results

    @property
    def metrics(self) -> dict[str, Union[None, float, datetime]]:
        return self._metrics

    @metrics.setter
    def metrics(self, value: dict[str, Union[None, float, datetime]]) -> None:
        self._metrics = value

    def get_total_test_count(self) -> int:
        """
        Returns:
             Scalar value representing the total test count.

        """
        return sum(iter(self.get_summary().values()))

    def checks(self) -> Optional[list[tuple["Group", "Check", "Reporter"]]]:
        """
        Returns:
            List of results as that is really just a list of the checks.

        """
        return self._results

    def get_group_results(self, group_name: str) -> list[tuple["Group", "Check", "Reporter"]]:
        """
        Args:
            group_name: the group name to retrieve results by.

        Returns:
             Array containing tuples that match the group name specified. Should be an array with a length
             greater than 1 as groups can have multiple checks.

        """
        return [(group, check, reporter) for group, check, reporter in self.results if group.name == group_name]

    def get_check_results(self, check_name: str) -> list[tuple["Group", "Check", "Reporter"]]:
        """
        Args:
             check_name the check name to be searched for in the results.

        Returns:
            Array containing tuples that match the check name specified. Should be an array with a length of 1 as
            checks should not be duplicated.

        """
        return [(group, check, reporter) for group, check, reporter in self.results if check.name == check_name]

    def has_group(self, group_name: str) -> list[tuple["Group", "Check", "Reporter"]]:
        """
        Args:
             group_name the group name to be searched for in the results.

        Returns:
             Boolean value indicating if the group_name exists in the results. ( Not really )

        """
        return self.get_group_results(group_name)

    @property
    def has_invalid_package(self) -> bool:
        """
        Returns:
            Boolean value indicating if the report includes failed packaging checks.

        """
        if self._results is None or not self._results:
            return False

        fails = [
            (group, check, reporter)
            for group, check, reporter in self._results
            if check.matches_tags([Tags.PACKAGING_STANDARDS], [""])
            and (reporter.state() == "failure" or reporter.state() == "error")
        ]

        return len(fails) > 0

    def has_check(self, check_name: str) -> bool:
        """
        Args:
            check_name: the group name to be searched for in the results.

        Returns:
            Boolean value indicating if the check_name exists in the results.

        """
        if self.get_check_results(check_name):
            return True
        return False

    def get_summary(self) -> dict[str, int]:
        """
        Returns:
             Dictionary with the cumulative count of result states.

        """
        summary_dict = dict.fromkeys(splunk_appinspect.reporter.STATUS_TYPES, 0)

        for _, _, reporter in self.results:
            summary_dict[reporter.state()] += 1

        return summary_dict

    def validation_start(self) -> None:
        """Helper function to be called at the start of a validation."""
        self.metrics["start_time"] = datetime.now()
        if self.status != "error":
            self.status = "in_progress"

    def validation_completed(self) -> None:
        # TODO: rename to validation_complete to align with start
        """Helper function to be called at the end of a validation."""
        self.metrics["end_time"] = datetime.now()
        self.metrics["execution_time"] = (self.metrics["end_time"] - self.metrics["start_time"]).total_seconds()
        if self.status != "error":
            self.status = "completed"

    def validation_error(self, exception: Exception) -> None:
        """Helper function to be called when an error is encountered during validation."""
        self.status = "error"
        self.errors.append(exception)
