# Copyright 2019 Splunk Inc. All rights reserved.
"""Splunk App Custom Visualization abstraction module"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

from splunk_appinspect.visualizations_configuration_file import VisualizationsConfigurationFile

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.configuration_file import ConfigurationSection, ConfigurationSetting


class CustomVisualizations:
    def __init__(self, app: "App"):
        self.app: "App" = app
        self.CONFIGURATION_DIRECTORY_PATH = "default"
        self.CONFIGURATION_FILE_NAME = "visualizations.conf"
        self.VISUALIZATION_REQUIRED_FILES = [
            "formatter.html",
            "visualization.css",
            "visualization.js",
            "preview.png",
        ]

    def create_custom_visualization(self, stanza_section: "ConfigurationSection") -> CustomVisualization:
        # Required Properties
        description_option = stanza_section.get_option("description")
        label_option = stanza_section.get_option("label")
        search_fragment_option = stanza_section.get_option("search_fragment")

        # Optional Properties
        allow_user_selection_option = (
            stanza_section.get_option("allow_user_selection")
            if stanza_section.has_option("allow_user_selection")
            else None
        )
        default_height_option = (
            stanza_section.get_option("default_height") if stanza_section.has_option("default_height") else None
        )
        disabled_option = stanza_section.get_option("disabled") if stanza_section.has_option("disabled") else None

        custom_visualization = CustomVisualization(
            self.app,
            stanza_section.name,
            description_option,
            label_option,
            search_fragment_option,
            stanza_section.lineno,
            allow_user_selection=allow_user_selection_option,
            default_height=default_height_option,
            disabled=disabled_option,
        )
        return custom_visualization

    @staticmethod
    def visualizations_directory() -> Path:
        return Path("appserver", "static", "visualizations")

    @property
    def visualization_required_files(self) -> list[str]:
        return self.VISUALIZATION_REQUIRED_FILES

    def get_custom_visualizations(self) -> Generator[CustomVisualization, Any, None]:
        visualizations_configuration_file = self.get_configuration_file()
        # Passes in a ConfigurationSection to be used for creation
        for section in visualizations_configuration_file.sections():
            yield self.create_custom_visualization(section)

    def does_visualizations_directory_exist(self) -> bool:
        return self.app.directory_exists(CustomVisualizations.visualizations_directory())

    def has_configuration_file(self) -> bool:
        return self.app.file_exists(self.CONFIGURATION_DIRECTORY_PATH, self.CONFIGURATION_FILE_NAME)

    def get_configuration_file(
        self,
    ) -> VisualizationsConfigurationFile:
        return self.app.get_config(
            self.CONFIGURATION_FILE_NAME,
            dir=self.CONFIGURATION_DIRECTORY_PATH,
            config_file=VisualizationsConfigurationFile(),
        )

    def get_raw_configuration_file(self) -> bytes:
        return self.app.get_raw_conf(self.CONFIGURATION_FILE_NAME, dir=self.CONFIGURATION_DIRECTORY_PATH)

    def get_configuration_file_path(self) -> Path:
        return self.app.get_filename(self.CONFIGURATION_DIRECTORY_PATH, self.CONFIGURATION_FILE_NAME)


class CustomVisualization:
    # TODO: Couple visualization directory reference in this class

    @staticmethod
    def valid_preview_png_dimensions() -> tuple[int, int]:
        return 116, 76

    def __init__(
        self,
        app: "App",
        name: str,
        description: "ConfigurationSetting",
        label: "ConfigurationSetting",
        search_fragment: "ConfigurationSetting",
        lineno: int | None,
        allow_user_selection: Optional["ConfigurationSetting"] = None,
        default_height: Optional["ConfigurationSetting"] = None,
        disabled: Optional["ConfigurationSetting"] = None,
    ):
        self.app: "App" = app
        self.name: str = name
        self.lineno: int | None = lineno
        self.allow_user_selection: Optional["ConfigurationSetting"] = allow_user_selection
        self.default_height: Optional["ConfigurationSetting"] = default_height
        self.description: "ConfigurationSetting" = description
        self.disabled: Optional["ConfigurationSetting"] = disabled
        self.label: "ConfigurationSetting" = label
        self.search_fragment: "ConfigurationSetting" = search_fragment

    def visualization_directory(self) -> Path:
        return Path(CustomVisualizations.visualizations_directory(), self.name)

    def does_visualization_directory_exist(self) -> bool:
        return self.app.directory_exists(self.visualization_directory())

    def preview_png_file_path(self) -> Path:
        return Path(self.visualization_directory(), "preview.png")

    def does_preview_png_exist(self) -> bool:
        return self.app.file_exists(self.preview_png_file_path())
