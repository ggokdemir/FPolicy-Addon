# Copyright 2019 Splunk Inc. All rights reserved.
"""Splunk app file resource abstraction module. Parsers provided for xml, lxml-xml and lxml format."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Optional

import bs4

logger = logging.getLogger(__name__)


class FileResource(object):
    def __init__(self, file_path: Path, ext: str = "", app_file_path: Optional[Path] = None, file_name: str = ""):
        self.file_path: Path = file_path
        self.app_file_path: Optional[Path] = app_file_path
        self.ext: str = ext
        self.file_name: str = file_name
        self.tags: list[str] = []

    def exists(self) -> bool:
        return os.path.isfile(self.file_path)

    @property
    def relative_path(self) -> str:
        # remove top app folder name
        return Path(*self.app_file_path.parts[1:])

    @property
    def is_path_pointer(self) -> bool:
        if re.match(r".*\.path$", self.file_name):
            return True
        return False

    def parse(self, fmt: str) -> bs4.BeautifulSoup:
        try:
            if fmt in ["xml", "lxml-xml", "lxml"]:
                return bs4.BeautifulSoup(open(self.file_path), "lxml")
        except Exception as e:
            logging.error(str(e))
            raise
        else:
            logging.error("%s file is not supported!", fmt)
            raise Exception(f"{fmt} file is not supported!")
