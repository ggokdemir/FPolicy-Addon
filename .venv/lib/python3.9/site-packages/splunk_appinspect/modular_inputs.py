# Copyright 2019 Splunk Inc. All rights reserved.

"""This is a helper module to encapsulate the functionality that represents
Splunk's modular inputs feature.
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

import splunk_appinspect

try:
    import itertools.ifilter as filter
except ImportError:
    pass

if TYPE_CHECKING:
    from splunk_appinspect.app import App
    from splunk_appinspect.file_resource import FileResource
    from splunk_appinspect.inputs_specification_file import InputsSpecification


logger = logging.getLogger(__name__)


class ModularInputs:
    """
    Encapsulates the logic and helper functions needed for Splunk's modular inputs.
    The ModularInputs object has a 1 to many relation for ModularInput objects.

    Attributes:
        app: The app object that represents a Splunk app.
        specification_directory_path: Relative path to where the modular inputs specification file exists.
        specification_filename: The modular inputs specification file name.
        CROSS_PLAT_EXE_TAG: A string used to tag a FileResource object with its respective modular input location.
        WINDOWS_EXE_TAG: A string used to tag a FileResource object with its respective modular input location.
        NIX_EXE_TAG: A string used to tag a FileResource object with its respective modular input location.
        WINDOWS_EXES: A list of strings used that represents the allowed binary types that can be used for a modular
            input in a Windows environment.
        NIX_EXES: A list of strings used that represents the allowed binary types that can be used for a modular
            input in a linux environment.
        CROSS_PLAT_EXES: A list of strings used that represents the allowed binary types that can be used for a modular
            input in a linux environment.

    """

    def __init__(self, app: "App") -> None:
        """
        Performs constructor initialization of the ModularInputs object.

        Args:
            app: The app object that represents a Splunk app.

        """
        self.app: App = app

        self.specification_directory_path: str = "README"
        self.specification_filename: str = "inputs.conf.spec"

        # architecture stuff
        self.CROSS_PLAT_EXE_TAG: str = "cross_plat_exe"
        self.WINDOWS_EXE_TAG: str = "windows_exe"
        self.NIX_EXE_TAG: str = "nix_exe"

        self.WINDOWS_EXES: list[str] = [".cmd", ".bat", ".py", ".exe"]
        self.NIX_EXES: list[str] = [".sh", ".py", ""]
        self.CROSS_PLAT_EXES: list[str] = splunk_appinspect.iter_ext.intersect(self.WINDOWS_EXES, self.NIX_EXES)

    @staticmethod
    def factory(app: "App") -> ModularInputs:
        """
        A factory function to return a ModularInputs object.

        Args:
            app: An app object that will be used to generate modular inputs from.

        Returns:
            A brand new ModularInputs object.

        """
        return ModularInputs(app)

    @staticmethod
    def modular_input_factory(name: str, lineno: int, chunked: bool = False) -> ModularInput:
        """
        A factory function to retrieve a ModularInput object, which belongs to a ModularInputs object (Note the 's').

        name: The name of a Modular Input. This is the stanza of the Modular Inputs specification file.
            This does NOT include the protocol prefix of `://`.
        lineno: The lineno of a Modular Input.
        chunked: Indicates if the modular input is chunked (a.k.a. mod input v2).

        Returns:
            A Modular Input object.

        """
        return ModularInput(name, lineno, chunked=chunked)

    # TODO: generalize this to accept the filename and directory
    def has_specification_file(self) -> bool:
        """
        Returns:
            Returns a boolean value representing if a modular inputs specification file exists.

        """
        return self.app.file_exists(self.specification_directory_path, self.specification_filename)

    # TODO: generalize this to accept the filename and directory
    def get_specification_file(self) -> "InputsSpecification":
        """
        Returns:
            InputsSpecification object that represents the Modular Inputs specification file.

        """
        return self.app.get_spec(
            self.specification_filename,
            dir=self.specification_directory_path,
            config_file=splunk_appinspect.inputs_specification_file.InputsSpecification(),
        )

    # TODO: generalize this to accept the filename and directory
    def get_raw_specification_file(self) -> bytes:
        """
        Returns:
            bytes string that represents the raw content of the Modular Inputs specification file.

        """
        return self.app.get_raw_conf(self.specification_filename, dir=self.specification_directory_path)

    def get_specification_app_filepath(self) -> Path:
        """
        Returns:
            Path object representing the absolute path to the Modular Inputs specification file.

        """
        return self.app.get_filename(self.specification_directory_path, self.specification_filename)

    def find_exes(self, name: str, case_sensitive: bool = True) -> Generator["FileResource", Any, None]:
        """
        For a given named file, find scripts and exes in the standard folders.

        Args:
            name: the name of the file to search for.
            case_sensitive: if the search for exe should be case-sensitive.

        Yields:
            FileResource object representing an executable file that can be used for modular inputs.

        """
        # Find all the files across OS, across platform
        for arch in self.app.arch_bin_dirs:
            for bin_dir in self.app.arch_bin_dirs[arch]:
                # Determine which extensions to use when checking specific arch
                # folders
                if arch in (self.app.LINUX_ARCH, self.app.DARWIN_ARCH):
                    ext_filter = self.NIX_EXES
                elif arch == self.app.WIN_ARCH:
                    ext_filter = self.WINDOWS_EXES
                elif arch == self.app.DEFAULT_ARCH:
                    ext_filter = self.WINDOWS_EXES + self.NIX_EXES

                for directory, filename, file_extension in self.app.iterate_files(
                    basedir=bin_dir, types=ext_filter, recurse_depth=0
                ):
                    file_base_name, file_extension = os.path.splitext(filename)

                    # TODO: Add more flags if desired
                    regex_flags = 0 if case_sensitive else re.IGNORECASE

                    # This pattern is used in order to get an exact match for
                    # the name without checking length of the strings.
                    file_regex_pattern = f"^{name}$"
                    file_name_regex_object = re.compile(file_regex_pattern, regex_flags)
                    found_file_matching_mod_input_name = re.search(file_name_regex_object, file_base_name) is not None
                    if found_file_matching_mod_input_name:
                        file = Path(self.app.app_dir, directory, filename)
                        path = Path(self.app.name, directory, filename)
                        resource = splunk_appinspect.file_resource.FileResource(
                            file, ext=file_extension, app_file_path=path
                        )
                        resource.tags.append(arch)

                        if file_extension in self.WINDOWS_EXES:
                            resource.tags.append(self.WINDOWS_EXE_TAG)

                        if file_extension in self.NIX_EXES:
                            resource.tags.append(self.NIX_EXE_TAG)

                        if file_extension in self.CROSS_PLAT_EXES:
                            resource.tags.append(self.CROSS_PLAT_EXE_TAG)

                        yield resource
                    else:
                        pass

    def has_modular_inputs(self) -> bool:
        """
        Returns:
            boolean representing the number of modular inputs detected.

        """
        return len(list(self.get_modular_inputs())) > 0

    def get_modular_inputs(self, case_sensitive: bool = True) -> Generator[ModularInput, Any, None]:
        """
        Args:
            case_sensitive: if the search for modular inputs should be case-sensitive.

        Yields:
             ModularInput object representing a Splunk ModularInput configuration.

        """
        for section in self.get_specification_file().sections():
            mod_input = self.modular_input_factory(section.name, section.lineno)

            if mod_input:
                for key, value, lineno in self.get_specification_file().items(section.name):
                    mod_input.args[key] = (value, lineno)

                files = list(self.find_exes(mod_input.name, case_sensitive=case_sensitive))

                # Set the specific architecture files
                mod_input.cross_plat_exes = list(
                    filter(
                        lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.CROSS_PLAT_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.win_exes = list(
                    filter(
                        lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.WINDOWS_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.linux_exes = list(
                    filter(
                        lambda exe: self.app.DEFAULT_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.win_arch_exes = list(
                    filter(
                        lambda exe: self.app.WIN_ARCH in exe.tags and self.WINDOWS_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.linux_arch_exes = list(
                    filter(
                        lambda exe: self.app.LINUX_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.darwin_arch_exes = list(
                    filter(
                        lambda exe: self.app.DARWIN_ARCH in exe.tags and self.NIX_EXE_TAG in exe.tags,
                        files,
                    )
                )

                mod_input.executable_files = list(files)

                yield mod_input


class ModularInput:
    """
    Represents a modular input.

    Attributes:
        name: The name of a Modular Input. This is the stanza of the Modular Inputs specification file.
            This does NOT include the protocol prefix of `://`.
        lineno: The lineno of a Modular Input.
        chunked: Indicates if the modular input is chunked (a.k.a. mod input v2).
        full_name: The name of a Modular Input. This is the stanza of the Modular Inputs specification file.
            This includes the protocol prefix of `://`.
        args: A dictionary that represents the properties and values of the Modular Inputs stanza
            from the specification file.
        executable_files: A list of FileResource objects that represent all the binary files detected for the modular
            input.
        win_exes: A list of FileResource objects that represent the binary files detected for the modular input,
            but only with respect to allowed Windows binaries.
        linux_exes: A list of FileResource objects that represent the binary files detected for the modular input,
            but only with respect to allowed Linux binaries.
        win_arch_exes: A list of FileResource objects that represent the binary files detected for the modular
            input, but only with respect to allowed windows architecture binaries.
        darwin_arch_exes: A list of FileResource objects that represent the binary files detected for the modular
            input, but only with respect to allowed OSX binaries.
        linux_arch_exes: A list of FileResource objects that represent the binary files detected for the modular
            input, but only with respect to allowed Linux architecture binaries.
        cross_plat_exes: A list of FileResource objects that represent the binary files detected for the modular
            input, but only with respect to allowed cross platform binaries.

    """

    def __new__(cls, name: str, *args: Any, **kwargs: Any) -> Optional[ModularInput]:
        if "://" in name:
            return super(ModularInput, cls).__new__(cls)

        return None

    def __init__(self, name: str, lineno: int, chunked: bool = False) -> None:
        """
        A constructor initializer.

        Args:
            name: The name of a Modular Input. This is the stanza of the Modular Inputs specification file.
                This does NOT include the protocol prefix of `://`.
            lineno: The lineno of a Modular Input.
            chunked: Indicates if the modular input is chunked (a.k.a. mod input v2).

        """
        self.name: str = name.split("://")[0]
        self.lineno: int = lineno
        self.chunked: bool = chunked

        self.full_name: str = name
        self.args: dict[str, tuple[str, int]] = {}
        self.executable_files: list["FileResource"] = []
        self.win_exes: list["FileResource"] = []
        self.linux_exes: list["FileResource"] = []
        self.win_arch_exes: list["FileResource"] = []
        self.darwin_arch_exes: list["FileResource"] = []
        self.linux_arch_exes: list["FileResource"] = []
        self.cross_plat_exes: list["FileResource"] = []

    @staticmethod
    def factory(name: str, lineno: int, chunked: bool = False) -> ModularInput:
        """
        A factory function to retrieve a ModularInput object, which belongs to a ModularInputs object (Note the 's').

        name: The name of a Modular Input. This is the stanza of the Modular Inputs specification file.
            This does NOT include the protocol prefix of `://`.
        lineno: The lineno of a Modular Input.
        chunked: Indicates if the modular input is chunked (a.k.a. mod input v2).

        Returns:
            A Modular Input object.
        """
        return ModularInput(name, lineno, chunked=chunked)

    def args_exist(self) -> bool:
        return len(self.args) > 0

    def count_cross_plat_exes(self) -> int:
        return splunk_appinspect.iter_ext.count_iter(self.cross_plat_exes)

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
