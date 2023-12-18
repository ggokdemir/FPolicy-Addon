"""
Module to provide high level common functionalities
"""
import hashlib
from io import BufferedReader
from pathlib import Path


def md5(file_path: Path) -> str:
    """Generate md5 hash hex string."""
    return hashlib.md5(_file_as_bytes(open(file_path, "rb"))).hexdigest()


def _file_as_bytes(file: BufferedReader) -> bytes:
    with file:
        return file.read()
