# Copyright 2019 Splunk Inc. All rights reserved.

"""Each of these add metadata to the function they wrap. This metadata is then
used by the Check object that encloses it.
"""
from typing import Callable, Optional

import semver


def cert_version(min: str = "1.0.0", max: Optional[str] = None) -> Callable:
    """
    Allows specifying which checks should be run at a given certification level.
    Both min and max define an _inclusive_ range, compared as strings.
    """

    def wrap(check: Callable) -> Callable:
        check.min_version = semver.VersionInfo.parse(min)
        check.max_version = semver.VersionInfo.parse(max) if max else None
        return check

    return wrap


def tags(*args: str) -> Callable:
    """Allows specifying of different groups of checks via tags."""

    def wrap(check: Callable) -> Callable:
        check.tags = args
        return check

    return wrap


def display(report_display_order: int = 1000) -> Callable:
    """Allows specifying an order for checks to appear within a group."""

    def wrap(check: Callable) -> Callable:
        check.report_display_order = report_display_order
        return check

    return wrap
