# Copyright 2019 Splunk Inc. All rights reserved.
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

import splunk_appinspect

from .file_resource import FileResource

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.configuration_file import ConfigurationSection, MergedConfigurationSection
    from splunk_appinspect.custom_types import ConfigurationProxyType


# http://docs.splunk.com/Documentation/Splunk/7.2.0/Search/Customcommandlocation#Platform-specific_custom_commands

RE_PATH_POINTER_SCRIPT = re.compile(r"SPLUNK_HOME/etc/apps/(?P<app_namne>\w+)/(?P<pointer_script>[\w\.\/]+)")


class Command:
    """Represents a custom search command."""

    def __init__(
        self,
        section: MergedConfigurationSection | ConfigurationSection,
        file_name: Optional[Path] = None,
        chunked: Optional[str] = None,
    ):
        self.chunked: Optional[str] = chunked
        self.name: str = section.name
        self.lineno: Optional[int] = section.lineno
        self.file_name: Optional[Path] = file_name
        self.type: str = ""
        self.args: dict[str, tuple[str, int]] = {}
        self.passauth: str = ""
        self.requires_srinfo: str = ""
        self.streaming_preop: str = ""
        self.requires_preop: str = ""
        self.enableheader: str = ""
        self.executable_files: list[FileResource] = []
        self.win_exes: list[FileResource] = []
        self.linux_exes: list[FileResource] = []
        self.win_arch_exes: list[FileResource] = []
        self.darwin_arch_exes: list[FileResource] = []
        self.linux_arch_exes: list[FileResource] = []
        self.v1_exes: list[FileResource] = []
        self.python_version: str = ""
        # the script with file name
        self.file_name_exe: Optional[FileResource] = None
        self.local: bool = False

    def executable_file(self) -> FileResource:
        return FileResource(self.file_name)

    def is_v2(self) -> bool:
        return self.chunked == "true"

    def file_name_specified(self) -> bool:
        return self.file_name is not None

    def count_v1_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.v1_exes)

    def count_win_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.win_exes)

    def count_linux_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.linux_exes)

    def count_win_arch_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.win_arch_exes)

    def count_linux_arch_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.linux_arch_exes)

    def count_darwin_arch_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.darwin_arch_exes)


class CustomCommands:
    """
    Represents a commands.conf file from default/commands.conf.

    The CustomCommands object has a 1 to many relation for Command objects.

    Attributes:
        app: The app object that represents a Splunk app.
        config: a set of configuration to be checked.
        V1_EXE_TAG: A string used to tag a FileResource object with its respective custom command location.
        WINDOWS_EXE_TAG: A string used to tag a FileResource object with its respective custom command location.
        NIX_EXE_TAG: A string used to tag a FileResource object with its respective custom command location.
        WINDOWS_EXES: A list of strings used that represents the allowed binary types that can be used for a custom
            command in a windows environment.
        NIX_EXES: A list of strings used that represents the allowed binary types that can be used for a custom
            command in a linux environment.
        V1_EXES: A list of strings used that represents the allowed binary types that can be used for a custom
            command in a linux environment.

    """

    def __init__(self, app: "App", config: Optional["ConfigurationProxyType"] = None):
        self.app: App = app
        self.config: Optional["ConfigurationProxyType"] = config

        # architecture stuff
        self.V1_EXE_TAG: str = "v1_exe"
        self.WINDOWS_EXE_TAG: str = "windows_exe"
        self.NIX_EXE_TAG: str = "nix_exe"

        self.V1_EXES: list[str] = [".py", ".pl"]
        self.WINDOWS_EXES: list[str] = self.V1_EXES + [".cmd", ".bat", ".exe", ".js"]
        self.NIX_EXES: list[str] = self.V1_EXES + [".sh", "", ".js"]
        self.ALL_VALID_EXES: list[str] = list(set(self.WINDOWS_EXES) | set(self.NIX_EXES))

    def configuration_file_exists(self) -> bool:
        if self.config is not None:  # class based checks
            return "commands" in self.config
        return self.app.file_exists("default", "commands.conf")

    def get_configuration_file(self) -> "ConfigurationProxyType":
        if self.config is not None:  # class based checks
            return self.config["commands"]
        return self.app.get_config("commands.conf")

    def find_pointer_scripts(self, pointer_file: FileResource) -> list[str]:
        pointer_scripts = []
        if not pointer_file.is_path_pointer:
            return pointer_scripts

        with open(self.app.get_filename(pointer_file.relative_path)) as path_file:
            for line in path_file:
                m = RE_PATH_POINTER_SCRIPT.match(line.strip())
                if m:
                    pointer_script_path = m.group("pointer_script")
                    if not self.app.file_exists(pointer_script_path):
                        continue
                    pointer_scripts.append(pointer_script_path)

        return pointer_scripts

    def find_exes(
        self, name: str, is_v2: bool, file_name: Optional[str] = None, case_sensitive: bool = True
    ) -> Generator[FileResource, Any, None]:
        """
        For a given named file, find scripts and exes in the standard folders.

        Args:
            name: the name of the file to search for.
            is_v2: Indicates if the custom command is chunked (a.k.a. custom command v2).
            case_sensitive: if the search for exe should be case-sensitive.

        Yields:
            FileResource object representing an executable file that can be used for custom commands.

        """
        # Find all the files across OS, across platform
        for arch in self.app.arch_bin_dirs:
            for bin_dir in self.app.arch_bin_dirs[arch]:
                # Determine which extensions to use when checking specific arch
                # folders.
                # only v2 command support platform specific executable

                # for any condition not matched, we will find all files in bin dir
                ext_filter = None

                if is_v2 and arch in (self.app.LINUX_ARCH, self.app.DARWIN_ARCH):
                    ext_filter = self.NIX_EXES
                elif is_v2 and arch == self.app.WIN_ARCH:
                    ext_filter = self.WINDOWS_EXES
                # elif arch == self.app.DEFAULT_ARCH:
                #     # find all files in bin dir
                #     ext_filter = None

                for directory, filename, file_extension in self.app.iterate_files(basedir=bin_dir, types=ext_filter):
                    file_base_name, _ = os.path.splitext(filename)
                    script_name = filename if file_name else file_base_name

                    # TODO: Add more flags if desired
                    regex_flags = 0 if case_sensitive else re.IGNORECASE

                    # This pattern is used in order to get an exact match for
                    # the name without checking length of the strings.
                    pattern = re.escape(str(file_name) or name)
                    file_regex_pattern = f"^{pattern}$"
                    file_name_regex_object = re.compile(file_regex_pattern, regex_flags)
                    found_file_matching_custom_command_name = (
                        re.search(file_name_regex_object, str(script_name)) is not None
                    )
                    if found_file_matching_custom_command_name:
                        file = Path(self.app.app_dir, directory, filename)
                        path = Path(self.app.name, directory, filename)
                        resource = splunk_appinspect.file_resource.FileResource(
                            file,
                            ext=file_extension,
                            app_file_path=path,
                            file_name=filename,
                        )
                        resource.tags.append(arch)

                        if file_extension in self.WINDOWS_EXES:
                            resource.tags.append(self.WINDOWS_EXE_TAG)

                        if file_extension in self.NIX_EXES:
                            resource.tags.append(self.NIX_EXE_TAG)

                        if not is_v2 and file_extension in self.V1_EXES:
                            resource.tags.append(self.V1_EXE_TAG)

                        yield resource
                    else:
                        pass

    def get_commands(self, case_sensitive: bool = True) -> Generator[Command, Any, None]:
        """
        Args:
            case_sensitive: if the search for custom commands should be case-sensitive.

        Yields:
            Custom Command object representing a Splunk Custom Command configuration.

        """

        for section in self.get_configuration_file().sections():
            command = Command(section)
            for key, value, lineno in self.get_configuration_file().items(section.name):
                command.args[key.lower()] = (value, lineno)

                if key.lower() == "filename":
                    command.file_name = Path(value)

                if key.lower() == "passauth":
                    command.passauth = value

                if key.lower() == "requires_srinfo":
                    command.requires_srinfo = value

                if key.lower() == "streaming_preop":
                    command.streaming_preop = value

                if key.lower() == "requires_preop":
                    command.requires_preop = value

                if key.lower() == "enableheader":
                    command.enableheader = value

                if key.lower() == "python.version":
                    command.python_version = value

                if key.lower() == "local":
                    command.local = value

                # V2 fields
                if key.lower() == "chunked":
                    command.chunked = value

            files = []
            # Splunk looks for the given filename in the app's bin directory.
            for file_resource in self.find_exes(
                command.name,
                command.is_v2(),
                file_name=command.file_name,
                case_sensitive=case_sensitive,
            ):
                command.file_name_exe = file_resource
                files.append(file_resource)

            # Set the specific architecture files
            command.v1_exes = list(
                filter(
                    lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.V1_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.win_exes = list(
                filter(
                    lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.WINDOWS_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.linux_exes = list(
                filter(
                    lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.win_arch_exes = list(
                filter(
                    lambda exe: self.app.WIN_ARCH in exe.tags and self.WINDOWS_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.linux_arch_exes = list(
                filter(
                    lambda exe: self.app.LINUX_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.darwin_arch_exes = list(
                filter(
                    lambda exe: self.app.DARWIN_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                    files,
                )
            )

            command.executable_files = list(files)

            yield command
