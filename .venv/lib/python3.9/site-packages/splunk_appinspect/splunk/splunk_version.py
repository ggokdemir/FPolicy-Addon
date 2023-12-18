"""
Splunk AppInspect Splunk version object definition module.
Represent a version like splunk_7_2_0
"""
from __future__ import annotations

import re


class TargetSplunkVersion:
    """
    An object to abstract the target Splunk version that is inspected against, meanwhile providing some useful APIs.
    """

    def __init__(self, tags: list[str]) -> None:
        """If there are multiple splunk_x_x tags. Only the last one is considered."""
        splunk_tags = list(filter(lambda e: re.match(r"splunk_\d+_\d+", e), tags))
        self._target_version_value: int | float = self._version_value(splunk_tags[-1]) if splunk_tags else float("inf")

    def __le__(self, other: str) -> bool:
        return self._target_version_value <= self._version_value(other)

    def __eq__(self, other: object | str) -> bool:
        return self._target_version_value == self._version_value(other)

    def __ge__(self, other: str) -> bool:
        return self._target_version_value >= self._version_value(other)

    def __lt__(self, other: str) -> bool:
        return self._target_version_value < self._version_value(other)

    def __gt__(self, other: str) -> bool:
        return self._target_version_value > self._version_value(other)

    def __str__(self) -> str:
        return f"<{self.__class__.__name__}: {self._target_version_value}>"

    __repr__ = __str__

    @staticmethod
    def _version_value(tag: str) -> int:
        """
        Convert version number in a splunk_tag into an integer of two digits.
        For example: splunk_7_2 -> 72
        """
        numbers = tag.split("_")[1:]
        numbers = list(map(int, numbers))
        assert len(numbers) <= 2
        value = 0
        for i in range(len(numbers)):
            value += 10 ** (1 - i) * numbers[i]
        return value
