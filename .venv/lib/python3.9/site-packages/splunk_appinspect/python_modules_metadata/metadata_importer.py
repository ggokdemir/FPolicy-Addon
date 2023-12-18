"""
Splunk AppInspect metadata importer module
"""
from __future__ import annotations

import importlib
from pathlib import Path
from typing import TYPE_CHECKING


def import_modules(directory: str | Path) -> None:
    """Import modules from a specified directory to gather metadata."""
    directories_in_dir = filter(Path.is_dir, Path(directory).iterdir())
    # /path/to/gzip => .gzip
    sub_dir_names = ["." + d.name for d in directories_in_dir]
    allow_list = [".DS_Store", ".__pycache__"]
    for subdir in sub_dir_names:
        if subdir not in allow_list:
            importlib.import_module(subdir, package="splunk_appinspect.python_modules_metadata.metadata")


def load_metadata() -> None:
    """load pre-defined modules metadata from metadata folder."""
    metadata_dir = Path(__file__).resolve().parent.joinpath("metadata")
    import_modules(metadata_dir)
