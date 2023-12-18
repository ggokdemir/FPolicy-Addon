"""Splunk app image file abstraction resource module"""

from __future__ import annotations

from pathlib import Path

from PIL import Image

from .file_resource import FileResource


class ImageResource(FileResource):
    """store metadata of an image file in app."""

    def __init__(self, image_path: Path) -> None:
        """
        This only supports PNG/JPEG/GIF image formats, and will throw NotImplementedError for not supported formats.
        """
        FileResource.__init__(self, image_path)
        self.image_path: Path = image_path
        self.meta: Image = Image.open(self.image_path)

    def dimensions(self) -> tuple[int, int]:
        return self.meta.size

    def is_png(self) -> bool:
        return self.meta.format == "PNG"

    def content_type(self) -> str | None:
        return self.meta.format
