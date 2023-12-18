"""Module to ensure tar's are safe."""

__version__ = "0.1.0"
__license__ = "Copyright 2019 Splunk Inc. All rights reserved."

from .check_tar import TarSec  # noqa: F401

__ALL__ = ["TarSec"]
