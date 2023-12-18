"""
Base class for all Splunk AppInspect report formatter
"""
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from splunk_appinspect.validation_report import ValidationReport


# Copyright 2019 Splunk Inc. All rights reserved.


class ValidationReportFormatter:
    """Base class for all Splunk AppInspect report formatter."""

    def format(self, validation_report: "ValidationReport", max_messages=None) -> str:
        error_output = "Derived Formatter classes should override this"
        raise NotImplementedError(error_output)
