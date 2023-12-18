from __future__ import annotations

import csv
import logging
import os
from pathlib import Path
from typing import Any, Generator

TRUSTED_CHECK_AND_LIBS_FILE = Path(__file__).parent / "lib_files" / "trusted_file_hashes.csv"
UNTRUSTED_CHECK_AND_LIBS_FILE = Path(__file__).parent / "lib_files" / "untrusted_file_hashes.csv"


logger = logging.getLogger(__name__)


class TrustedDataCollector:
    """collects trusted data."""

    def __init__(
        self,
        trusted_check_and_lib_file: Path = TRUSTED_CHECK_AND_LIBS_FILE,
        untrusted_check_and_libs_file: Path = UNTRUSTED_CHECK_AND_LIBS_FILE,
    ):
        self._trusted_check_and_libs_file: Path = trusted_check_and_lib_file
        self._untrusted_check_and_libs_file: Path = untrusted_check_and_libs_file
        self._trusted_check_and_libs: set[tuple[str, str]] = set()
        self._untrusted_check_and_libs: set[tuple[str, str]] = set()
        self._process_trusted_data()

    def get_trusted_check_and_libs(self) -> set[tuple[str, str]]:
        return self._trusted_check_and_libs

    def get_untrusted_check_and_libs(self) -> set[tuple[str, str]]:
        return self._untrusted_check_and_libs

    def _process_trusted_data(self) -> None:
        if os.path.exists(self._trusted_check_and_libs_file):
            for check_name, file_hash in self._read_lib_file(self._trusted_check_and_libs_file):
                self._trusted_check_and_libs.add((check_name, file_hash))
        else:
            logger.warning(
                "trustedlibs source file `%s` is not found",
                self._trusted_check_and_libs_file,
            )

        if os.path.exists(self._untrusted_check_and_libs_file):
            for check_name, file_hash in self._read_lib_file(self._untrusted_check_and_libs_file):
                self._untrusted_check_and_libs.add((check_name, file_hash))
        else:
            logger.warning(
                "trustedlibs source file `%s` is not found",
                self._untrusted_check_and_libs_file,
            )

    @staticmethod
    def _read_lib_file(source_file: str) -> Generator[tuple[str, str], Any, None]:
        with open(source_file, "r") as f:
            filereader = csv.DictReader(f)
            for line in filereader:
                yield line["check_name"], line["file_hash"]
