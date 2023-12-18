# Copyright 2019 Splunk Inc. All rights reserved.
"""
Splunk AppInspect certification events listeners/handlers for test mode
"""
import logging
import sys
from typing import TYPE_CHECKING, TextIO

import click

import splunk_appinspect

from . import listener

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.checks import Check
    from splunk_appinspect.reporter import Reporter
    from splunk_appinspect.validation_report import ApplicationValidationReport


logger = logging.getLogger(__name__)


class DotStatusListener(listener.Listener):
    """test mode certification status listener class."""

    def __init__(
        self,
        stream: TextIO = sys.stdout,
        column_wrap: int = 80,
        skip_manual: bool = True,
        max_report_messages: int = splunk_appinspect.main.MAX_MESSAGES_DEFAULT,
    ) -> None:
        """
        Args:
            stream: The output to write to.
            column_wrap: the column wrap length.
            skip_manual: skip manual checks.
            max_report_messages: the maximum number of messages to return for a single check.

        """
        self.idx: int = 0
        self.column_wrap: int = column_wrap
        self.stream: TextIO = stream
        self.exit_status: int = 0
        self.skip_manual: bool = skip_manual
        self.max_messages: int = max_report_messages

    @staticmethod
    def on_start_app(app: "App") -> None:
        """
        Args:
            app: The app object representing the Splunk Application.

        """
        command_line_output = f"Validating: {app.name} Version: {app.version}"
        click.echo(command_line_output)

    @staticmethod
    def on_enable_python_analyzer() -> None:
        click.echo("Enable Python analyzer.")

    def on_finish_check(self, check: "Check", reporter: "Reporter") -> None:
        """
        Args:
            check: The check object that was executed.
            reporter: The reporter object that contains the results of the check that was executed.

        """
        self.idx += 1
        result = reporter.state()
        glyph = "."
        if result == "failure":
            glyph = "F"
            self.exit_status += 1
        elif result == "error":
            glyph = "E"
            self.exit_status += 1
        elif result == "skipped":
            glyph = "S"
        elif result == "manual_check":
            if self.skip_manual:
                return
            glyph = "M"

        self.stream.write(glyph)
        if self.idx % self.column_wrap == 0:
            self.stream.write("\n")
        self.stream.flush()

    def on_finish_app(self, app: "App", application_validation_report: "ApplicationValidationReport") -> None:
        """
        Prints  out the output of failed checks with respect to their group.

        Args:
            app: The app object being validated
            application_validation_report: The application validation report that contains the
                results of the validation.

        """
        result_types = ["error", "failure"]
        message_types = ["warning", "error", "failure", "manual_check"]

        if not self.skip_manual:
            result_types.append("manual_check")

        click.echo("\n")
        splunk_appinspect.command_line_helpers.print_result_records(
            application_validation_report,
            max_messages=self.max_messages,
            result_types=result_types,
            message_types=message_types,
        )
        click.echo("\n")
        summary_header = f"{app.name} Report Summary"
        splunk_appinspect.command_line_helpers.output_summary(
            application_validation_report.get_summary(), summary_header=summary_header
        )
        click.echo("\n")
