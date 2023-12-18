from __future__ import annotations

import csv
from pathlib import Path

list_path = Path(__file__).parent / "list.csv"


class TelemetryAllowList:
    def __init__(self) -> None:
        self._data: set[str] = set()
        with open(list_path, "r") as fd:
            allow_list_reader = csv.DictReader(fd)
            for row in allow_list_reader:
                self._data.add(row["appid"])

    def __contains__(self, value: str) -> bool:
        return value in self._data


telemetry_allow_list = TelemetryAllowList()
