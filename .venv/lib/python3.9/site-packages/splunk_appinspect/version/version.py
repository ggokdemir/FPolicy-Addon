# Copyright 2019 Splunk Inc. All rights reserved.

"""This file is used to track the version of Splunk AppInspect."""
from pathlib import Path
from typing import Optional


# https://packaging.python.org/guides/single-sourcing-package-version/
def get_version(current_dir: Optional[str] = None) -> str:
    """Helper function to get Splunk AppInspect version info."""
    if current_dir is None:
        current_dir = Path(__file__).resolve().parent
    version_file = Path(current_dir, "VERSION.txt")

    with open(version_file, "r") as version_text:
        return version_text.read().strip()
