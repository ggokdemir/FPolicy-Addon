# Copyright 2019 Splunk Inc. All rights reserved.
"""Splunk conf file abstraction base module"""
from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, KeysView, Optional

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.custom_types import ConfigurationFileType


class NoSectionError(Exception):
    """Exception raised when a specified section is not found."""


class NoOptionError(Exception):
    """Exception raised when a specified option is not found in the specified section."""


class DuplicateSectionError(Exception):
    """Exception raised if add_section() is called with the name of a section that is already present."""


class ConfigurationSetting(object):
    def __init__(
        self,
        name: str,
        value: str,
        header: Optional[list[str]] = None,
        lineno: Optional[int] = None,
        relative_path: Optional[Path] = None,
    ) -> None:
        self.name: str = name
        self.value: str = value
        self.header: list[str] = [] if header is None else header
        self.lineno: Optional[int] = lineno
        self.relative_path: Optional[Path] = relative_path

    def get_relative_path(self) -> Optional[Path]:
        return self.relative_path

    def get_line_number(self) -> Optional[int]:
        return self.lineno


class ConfigurationSection(object):
    def __init__(
        self,
        name: str,
        header: Optional[list[str]] = None,
        lineno: Optional[int] = None,
        relative_path: Optional[Path] = None,
    ) -> None:
        self.name: str = name
        self.header: list[str] = [] if header is None else header
        self.lineno: Optional[int] = lineno
        self.options: dict[str, ConfigurationSetting] = dict()
        self.relative_path: Optional[Path] = relative_path

    def add_option(
        self, name: str, value: str, header: Optional[list[str]] = None, lineno: Optional[int] = None
    ) -> None:
        self.options[name] = ConfigurationSetting(
            name, value, header=header, lineno=lineno, relative_path=self.relative_path
        )

    def has_option(self, optname: str) -> bool:
        return optname in self.options

    def has_setting_with_pattern(self, setting_key_regex_pattern: re.Pattern) -> bool:
        setting_key_regex_object = re.compile(setting_key_regex_pattern, re.IGNORECASE)
        for key, _ in iter(self.options.items()):
            if re.search(setting_key_regex_object, key):
                return True
        return False

    def get_option(self, optname: str) -> ConfigurationSetting:
        if optname in self.options:
            return self.options[optname]

        error_output = f"No option '{optname}' exists in section '{self.name}'"
        raise NoOptionError(error_output)

    def settings_names(self) -> Generator[str, Any, None]:
        yield from self.options.keys()

    def settings(self) -> Generator[ConfigurationSetting, Any, None]:
        yield from self.options.values()

    def settings_with_key_pattern(
        self, setting_key_regex_pattern: re.Pattern
    ) -> Generator[ConfigurationSetting, Any, None]:
        setting_key_regex_object = re.compile(setting_key_regex_pattern, re.IGNORECASE)
        for key, value in iter(self.options.items()):
            if re.search(setting_key_regex_object, key):
                yield value

    def items(self) -> list[tuple[str, str, Optional[int]]]:
        return [
            (property_name, configuration_setting.value, configuration_setting.lineno)
            for (property_name, configuration_setting) in iter(self.options.items())
        ]

    def get_relative_path(self) -> Optional[Path]:
        return self.relative_path

    def get_line_number(self) -> Optional[int]:
        return self.lineno

    def __getitem__(self, optname: str) -> ConfigurationSetting:
        return self.get_option(optname)


class MergedConfigurationSection(object):
    """
    Configuration section that proxies to one or more individual files.

    Note:
        This class will apply precedence logic, but otherwise the methods here will proxy to the ConfigurationSections
        that back the instance.

    Args:
      *sections: Actual config sections loaded from files, in order of precedence.

    """

    def __init__(self, *sections: ConfigurationSection) -> None:
        self.sections: tuple[ConfigurationSection, ...] = sections

    def add_option(self, name: str, value: str, header: Optional[list[str]] = None, lineno: Optional[int] = None):
        raise NotImplementedError

    def has_option(self, optname: str) -> bool:
        return any([section.has_option(optname) for section in self.sections])

    def has_setting_with_pattern(self, setting_key_regex_pattern: re.Pattern) -> bool:
        setting_key_regex_object = re.compile(setting_key_regex_pattern, re.IGNORECASE)
        for key in self.settings_names():
            if re.search(setting_key_regex_object, key):
                return True
        return False

    def get_option(self, optname: str) -> ConfigurationSetting:
        for section in self.sections:
            if section.has_option(optname):
                return section.get_option(optname)

        error_output = f"No option '{optname}' exists in section '{self.name}'"
        raise NoOptionError(error_output)

    def settings_names(self) -> Generator[str, Any, None]:
        touched = set()

        for section in self.sections:
            for setting_name in section.settings_names():
                if setting_name not in touched:
                    yield setting_name
                    touched.add(setting_name)

    def settings(self) -> Generator[ConfigurationSetting, Any, None]:
        for key in self.settings_names():
            yield self.get_option(key)

    def settings_with_key_pattern(
        self, setting_key_regex_pattern: re.Pattern
    ) -> Generator[ConfigurationSetting, Any, None]:
        setting_key_regex_object = re.compile(setting_key_regex_pattern, re.IGNORECASE)
        for key in iter(self.settings_names()):
            if re.search(setting_key_regex_object, key):
                yield self.get_option(key)

    @property
    def name(self) -> str:
        return self.sections[-1].name

    @property
    def lineno(self) -> Optional[int]:
        return self.get_line_number()

    @property
    def options(self) -> dict[str, ConfigurationSetting]:
        return {optname: self.get_option(optname) for optname in self.settings_names()}

    def items(self) -> list[tuple[str, str, Optional[int]]]:
        return [
            (property_name, configuration_setting.value, configuration_setting.lineno)
            for (property_name, configuration_setting) in iter(self.options.items())
        ]

    def get_relative_path(self) -> Optional[Path]:
        return self.sections[-1].get_relative_path()

    def get_line_number(self) -> Optional[int]:
        return self.sections[-1].get_line_number()

    def __getitem__(self, optname: str) -> ConfigurationSetting:
        return self.get_option(optname)


class ConfigurationFile(object):
    def __init__(self, name: Optional[str] = None, relative_path: Optional[Path] = None) -> None:
        self.headers: list[str] = []
        self.sects: dict[str, ConfigurationSection] = dict()
        self.errors: list[tuple[str, int, str]] = []
        self.name: Optional[str] = name
        self.relative_path: Optional[Path] = relative_path

    def set_main_headers(self, header: list[str]) -> None:
        self.headers = header

    def add_error(self, error: str, lineno: int, section: str) -> None:
        self.errors.append((error, lineno, section))

    def get(self, sectionname: str, key: str) -> str:
        if self.has_section(sectionname):
            option = self.sects[sectionname].get_option(key)
            if isinstance(option, ConfigurationSetting):
                return option.value

            error_output = (
                "The option does not exist in the section " f" searched. Section: {key}" f" Option: '{sectionname}'"
            )
            raise NoOptionError(error_output)
        else:
            raise NoSectionError(f"No section '{sectionname}' exists")

    def add_section(
        self, sectionname: str, header: Optional[list[str]] = None, lineno: Optional[int] = None
    ) -> ConfigurationSection:
        section = ConfigurationSection(sectionname, header=header, lineno=lineno, relative_path=self.relative_path)
        self.sects[sectionname] = section
        return section

    def has_option(self, sectionname: str, key: str) -> bool:
        return self.has_section(sectionname) and self.get_section(sectionname).has_option(key)

    def get_option(self, sectionname: str, key: str) -> ConfigurationSetting:
        return self.get_section(sectionname).get_option(key)

    def has_section(self, sectionname: str) -> bool:
        return sectionname in self.sects

    def get_section(self, sectionname: str) -> ConfigurationSection:
        if sectionname in self.sects:
            return self.sects[sectionname]

        raise NoSectionError(f"No such section: {sectionname}")

    def section_names(self) -> KeysView:
        return self.sects.keys()

    def sections(self) -> Generator[ConfigurationSection, Any, None]:
        for _, value in iter(self.sects.items()):
            yield value

    # Returns only sections that have a property that matches a regex pattern
    def sections_with_setting_key_pattern(
        self, setting_key_regex_pattern: re.Pattern, case_sensitive: bool = False
    ) -> Generator[ConfigurationSection, Any, None]:
        flag = 0 if case_sensitive else re.IGNORECASE
        setting_key_regex_object = re.compile(setting_key_regex_pattern, flags=(flag))
        for _, value in iter(self.sects.items()):
            for setting in value.settings():
                if re.search(setting_key_regex_object, setting.name):
                    yield value

    def items(self, sectionname: str) -> list[tuple[str, str, Optional[int]]]:
        return self.get_section(sectionname).items()

    def build_lookup(self) -> dict[str, list[str]]:
        """Build a dictionary from a config file where { sect => [options ...] }."""
        return {sect: [option for option in self.sects[sect].options] for sect in self.sects}

    def get_relative_path(self) -> Optional[Path]:
        return self.relative_path

    def __getitem__(self, sectionname: str) -> ConfigurationSection:
        return self.get_section(sectionname)

    def __contains__(self, sectionname: str) -> bool:
        return self.has_section(sectionname)


class MergedConfigurationFile:
    """
    Configuration file that proxies to one or more individual files

    Note:
        This class will apply precedence logic, but otherwise the methods
        here will proxy to the ConfigurationFiles that back the instance.

    Args:
        *sections: Actual config loaded from files, in order of precedence

    """

    def __init__(self, *configs: ConfigurationFile) -> None:
        self.configs = configs

    def set_main_headers(self, header: list[str]) -> None:
        raise NotImplementedError

    def add_error(self, error: str, lineno: int, section: str) -> None:
        raise NotImplementedError

    def get(self, sectionname: str, key: str) -> str:
        if not self.has_section(sectionname):
            raise NoSectionError(f"No section '{sectionname}' exists")

        for config in self.configs:
            if config.has_option(sectionname, key):
                option = config.get_option(sectionname, key)
                if isinstance(option, ConfigurationSetting):
                    return option.value

        error_output = (
            "The option does not exist in the section " f" searched. Section: {key}" f" Option: '{sectionname}'"
        )
        raise NoOptionError(error_output)

    def add_section(
        self, sectionname: str, header: Optional[list[str]] = None, lineno: Optional[int] = None
    ) -> ConfigurationSection:
        raise NotImplementedError

    def has_option(self, sectionname: str, key: str) -> bool:
        return any([config.has_option(sectionname, key) for config in self.configs])

    def has_section(self, sectionname: str) -> bool:
        return any([config.has_section(sectionname) for config in self.configs])

    def get_section(self, sectionname: str) -> MergedConfigurationSection | ConfigurationSection:
        section_configs = []

        for config in self.configs:
            if config.has_section(sectionname):
                section_configs.append(config[sectionname])

        if len(section_configs) == 0:
            raise NoSectionError(f"No such section: {sectionname}")
        elif len(section_configs) == 1:
            return section_configs[0]

        return MergedConfigurationSection(*section_configs)

    def get_option(self, sectionname: str, option: str) -> ConfigurationSetting:
        for config in self.configs:
            if config.has_option(sectionname, option):
                return config.get_option(sectionname, option)

        error_output = f"No option '{option}' exists in section '{sectionname}'"
        raise NoOptionError(error_output)

    def section_names(self) -> Generator[str, Any, None]:
        touched = []

        for config in self.configs:
            for section_name in config.section_names():
                if section_name not in touched:
                    yield section_name
                    touched.append(section_name)

    def sections(self) -> Generator[MergedConfigurationSection | ConfigurationSection, Any, None]:
        for sectionname in self.section_names():
            yield self.get_section(sectionname)

    # Returns only sections that have a property that matches a regex pattern
    def sections_with_setting_key_pattern(
        self, setting_key_regex_pattern: re.Pattern, case_sensitive: bool = False
    ) -> Generator[MergedConfigurationSection | ConfigurationSection, Any, None]:
        flag = 0 if case_sensitive else re.IGNORECASE
        setting_key_regex_object = re.compile(setting_key_regex_pattern, flags=(flag))
        for value in self.sections():
            for setting in value.settings():
                if re.search(setting_key_regex_object, setting.name):
                    yield value

    def items(self, sectionname: str) -> list[tuple[str, str, Optional[int]]]:
        return self.get_section(sectionname).items()

    def build_lookup(self) -> dict[str, list[str]]:
        raise NotImplementedError

    def get_relative_path(self) -> Optional[Path]:
        return self.configs[0].get_relative_path()

    def __getitem__(self, sectionname: str) -> MergedConfigurationSection | ConfigurationSection:
        return self.get_section(sectionname)

    def __bool__(self) -> bool:
        """
        Returns:
            False when there are no underlying configs, to make logic like this work::

                conf_file = app.merged_config["server"]
                if not (conf_file and conf_file.has_section("foo")):
                    return

        """

        return len(self.configs) > 0


class ConfigurationProxy:
    """
    A lazy-loader for in-app configuration files.

    Attributes:
        app: the app from where configs will be loaded.
        basedir: a path within the app from where configs will be loaded.
        configs: dict containing ConfigurationFile type objects.

    """

    def __init__(self, app: "App", basedir: str | Path) -> None:
        self.app: "App" = app
        self.basedir: str | Path = basedir
        self.configs: dict[str, "ConfigurationFileType"] = {}

    def __getitem__(self, conf_file_name: str) -> ConfigurationFile | None:
        """
        Get a configuration file, loading it from the app if needed.

        Returns:
            ConfigurationFile instance or None if it does not exist.

        """
        if not self.__contains__(conf_file_name):
            return None

        if not conf_file_name.endswith(".conf"):
            conf_file_name = f"{conf_file_name}.conf"

        if conf_file_name not in self.configs:
            self.configs[conf_file_name] = self.app.get_config(conf_file_name, self.basedir)
        return self.configs[conf_file_name]

    def __contains__(self, conf_file_name: str) -> bool:
        """
        Check for existence of a configuration file in the app.

        Returns:
            True if the configuration file exists, False otherwise.

        """

        if not conf_file_name.endswith(".conf"):
            conf_file_name = f"{conf_file_name}.conf"
        return self.app.file_exists(self.basedir, conf_file_name)


class MergedConfigurationProxy:
    """
    A lazy-loader for merging configuration files.

    Attributes:
      proxies: a list of ConfigurationProxy instances from which configs will be merged.

    """

    def __init__(self, *proxies: ConfigurationProxy) -> None:
        self.proxies: tuple[ConfigurationProxy, ...] = proxies

    def __getitem__(self, conf_file_name: str) -> MergedConfigurationFile:
        """
        Get a merged configuration file using all applicable proxies.

        Returns:
            MergedConfigurationFile instance.

        """
        configs: list[ConfigurationFile] = [proxy[conf_file_name] for proxy in self.proxies if conf_file_name in proxy]
        return MergedConfigurationFile(*configs)

    def __contains__(self, conf_file_name: str) -> bool:
        """
        Check for existence of a configuration file in any of the backing proxies.

        Returns:
            True if the configuration file exists in any proxy, False otherwise.

        """
        return any([conf_file_name in proxy for proxy in self.proxies])
