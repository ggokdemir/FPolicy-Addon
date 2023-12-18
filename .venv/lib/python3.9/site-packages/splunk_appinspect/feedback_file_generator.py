"""
This module provides method(s) to generate Splunk AppInspect report feedback file from AppInspect validation report.

Copyright 2020 Splunk Inc. All rights reserved.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from splunk_appinspect.custom_types import FormattedAppReportDict, GroupDict, MetricsDict
    from splunk_appinspect.validation_report import ApplicationValidationReport, ValidationReport

# Splunk AppInspect report feedback file name.
FEEDBACK_FILE_NAME = "inspect.yml"


def generate_feedback_file(validation_report: "ValidationReport") -> None:
    """
    Generates Splunk AppInspect report feedback file that customer can use to provided response against AppInspect
    checks reported in the feedback file.

    This generated feedback file provides opportunity to customer to provide feedback against AppInspect checks that
    returned `failure` or `manual_check` result state.

    """
    with open(FEEDBACK_FILE_NAME, "w") as f:
        yaml.safe_dump(
            {"reports": _get_formatted_validation_report(validation_report)},
            f,
            allow_unicode=True,
            width=120,
            sort_keys=False,
            default_flow_style=False,
        )


def _get_formatted_validation_report(validation_report: "ValidationReport") -> list[FormattedAppReportDict]:
    formatted_reports = []

    for app_report in validation_report.application_validation_reports:
        formatted_reports.append(_get_formatted_app_report(app_report))
    return formatted_reports


def _get_formatted_app_report(app_report: "ApplicationValidationReport") -> FormattedAppReportDict:
    app_info = _get_formatted_app_info(app_report)
    metrics = _get_formatted_metrics(app_report)
    groups = _get_formatted_groups(app_report)

    formatted_report = {}
    formatted_report.update(app_info)
    formatted_report.update(metrics)
    formatted_report.update(groups)

    return formatted_report


def _get_formatted_app_info(app_report: "ApplicationValidationReport") -> dict[str, str]:
    app_info = {
        "app_name": app_report.app_name,
        "app_version": app_report.app_version,
        "app_hash": app_report.app_hash,
        "app_author": app_report.app_author,
        "app_description": app_report.app_description,
    }
    return app_info


def _get_formatted_metrics(app_report: "ApplicationValidationReport") -> dict[str, MetricsDict]:
    return {"metrics": app_report.metrics}


def _get_formatted_groups(app_report: "ApplicationValidationReport") -> dict[str, list[GroupDict]]:
    groupings = app_report.groups()
    groups = []

    for grouping in groupings:
        group_checks = []

        for group, check, reporter in grouping:
            if reporter.state() in ["manual_check", "failure"]:
                report_records = []

                for report_record in reporter.report_records():
                    report_records.append(
                        {
                            "filename": str(report_record.filename),
                            "line": report_record.line,
                            "code": report_record.code,
                            "message_filename": str(report_record.message_filename),
                            "message_line": report_record.message_line,
                            "message": report_record.message,
                            "result": report_record.result,
                            "response": " ",
                        }
                    )

                if len(report_records) > 0:
                    group_checks.append({"name": check.name, "messages": report_records})

        if len(group_checks) > 0:
            groups.append({"name": group.name, "description": group.doc(), "checks": group_checks})

    return {"groups": groups}
