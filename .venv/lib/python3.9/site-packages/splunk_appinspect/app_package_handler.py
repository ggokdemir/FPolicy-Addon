# Copyright 2019 Splunk Inc. All rights reserved.

"""
AppPackageHandler class handles app package input which is passed to CLI.
This class currently can handle these cases:

- Simple Splunk App
    - Contains ONLY Splunk App files and directories
        - appserver/
        - default/
        - local/
        - etc.
- Nested Splunk Apps
    - Directory of multiple directory/tar/zip Splunk App packages
    - tar/zip of multiple directory/tar/zip Splunk App packages

Not implemented
- Static dependency support (.dependencies)
- Dynamic dependency support (app.manifest)
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Generator, Optional, Union

from tarsec.tarsec import TarSec

logger = logging.getLogger(__name__)


class AppPackageHandler:
    """
    A class intended to serve as the management interface for packages that are provided for certification.
    Not all apps are Splunk Apps.

    Attributes:
        apps: Dictionary of (app's folder name, app's path).
        app_packages: Array of all AppPackage objects.
        file_hash: Hash of package.
        origin_package: AppPackage derived object that represents the type of application provided.

    """

    def __init__(self, app_package_path: str) -> None:
        """
        __init__ constructor for AppPackageHandler.

        Args:
            app_package_path (String): The absolute path to the App that should
                be handled. This should be either a directory, spl, or tgz file.
        """
        # TODO: Remove self.apps, it is redundant and can be replaced by calling
        # the AppPackage.working_artifact_name and AppPackage.working_app_path
        self.apps: dict[str, Path] = {}
        self.app_packages: list[AppPackage] = []
        self.file_hash: str = self._get_file_hash(app_package_path)
        self.origin_package: AppPackage = AppPackage.factory(app_package_path)
        try:
            # Regular app
            if self.origin_package.is_splunk_app():
                # Found app in the root dir, this is a single app
                self._add_package(self.origin_package)
                logger.info("Found app in %s", self.origin_package.origin_path)

                # Gather and add any .dependencies app packages
                self._gather_package_dependencies()

                # Short circuits if simple app package is detected
                return

            # Invalid App, for example an invalid tarball that fails to extract
            if self.origin_package.working_artifact is None:
                # Treat as single app
                self._add_package(self.origin_package)
                logger.warning(
                    "Found invalid app with no package contents in %s",
                    self.origin_package.origin_path,
                )

                # Skip adding .dependencies app packages since no package contents
                # Short circuits if simple app package is detected
                return

            # Tar of tars, app of apps, etc.
            app_found = False
            files_not_part_of_valid_apps = []  # Array of filepaths outside of apps
            contents_path = self.origin_package.working_artifact
            resource_contents = []
            try:
                if os.path.isdir(contents_path):
                    resource_contents = self.origin_package.working_artifact.iterdir()
            except Exception:
                logger.warning("Issue reading contents of %s", self.origin_package.working_artifact)

            if resource_contents:
                try:
                    resource_contents = sorted(contents_path.iterdir())
                except Exception:
                    logger.warning("Issue reading contents of %s", contents_path)
                    resource_contents = []
                for resource in resource_contents:
                    generated_app_package = AppPackage.generate_app_package_from_file_or_folder(resource)
                    if generated_app_package is not None:
                        # If the app is generated from a package, use the origin package name
                        generated_app_package.origin_package_name = self.origin_package.origin_package_name
                        if not app_found:
                            # For first app == main app, make sure name is not a
                            # temp directory name - if so use name from origin
                            if generated_app_package.working_app_path == self.origin_package.working_artifact:
                                generated_app_package.working_artifact_name = self.origin_package.working_artifact_name
                        app_found = True
                        self._add_package(generated_app_package)
                        logger.info("Found app in %s", generated_app_package.origin_path)
                    else:
                        # Reject files/folders within the package but not
                        # app-related. Store as path relative to origin package
                        # contents folder
                        files_not_part_of_valid_apps.append(Path(resource.name))

            if not app_found:
                logger.warning("No app(s) found. Apps must adhere to the checks tagged with `packaging_standards`.")
                # Last ditch effort to support a package for review. Added as a
                # package so vetting can be performed using `packaging_standards`
                # tags to determine minimum package requirements needed in order
                # for full validation to be performed. Done so that validator.py
                # has a package to test with for validator.validate_package()
                self._add_package(self.origin_package)

            if len(self.app_packages) == 1 and isinstance(self.main_app_package, FolderAppPackage):
                # If there is a single app folder, this may be an app with valid
                # dependencies, assign the contents path outside the app to accomodate
                self.main_app_package.working_artifact = contents_path
            else:
                # Associate non-app files from the origin package with the
                # main_app_package so that they can be called out during package
                # validation
                self.main_app_package.origin_package_non_app_files = files_not_part_of_valid_apps

            # Gather and add any .dependencies app packages
            self._gather_package_dependencies()
        except Exception as exception:
            logger_output = (
                "An attempt was made to initialize AppPackageHandler, but failed." f" Exception: {str(exception)}"
            )
            logger.warning(logger_output)
            self.origin_package.clean_up()

    @staticmethod
    def _get_file_hash(file_path: str, algorithm: str = "md5") -> str:
        try:
            if os.path.isfile(file_path):
                gen = hashlib.__dict__[algorithm]()
                with open(file_path, "rb") as f:
                    gen.update(f.read())
                return gen.hexdigest()

            logger.debug("File hash is not available for non-file(directory) package.")
            return "N/A"

        except Exception as e:
            logger.error("Failed to generate file hash for app, and the error is %s", str(e))
            return "N/A"

    def _gather_package_dependencies(self) -> None:
        """
        Helper function to gather all dependencies, and their dependencies, etc. recursively from the .dependencies
        folder. Add any valid app packages to self.app_packages in a breadth-first-search manner.
        """
        app_package_queue = self.app_packages[:]
        while app_package_queue:
            package = app_package_queue.pop(0)  # dequeue the first package
            if package.dependencies_folder is not None:
                try:
                    if not os.path.exists(package.dependencies_folder):
                        raise FileNotFoundError(f"Path {package.dependencies_folder} does not exist")
                    dependency_paths = package.dependencies_folder.iterdir()
                except Exception:
                    logger.warning("Issue reading contents of %s", package.dependencies_folder)
                    dependency_paths = []  # in case of read error, etc

                for dependency_path in dependency_paths:
                    dependency_app_package = AppPackage.generate_app_package_from_file_or_folder(dependency_path)
                    if dependency_app_package is not None:
                        package.static_slim_dependency_app_packages.append(dependency_app_package)
                        dependency_app_package.is_static_slim_dependency = True
                        # Appends the package to self.app_packages
                        self._add_package(dependency_app_package)
                        # Also append to our working queue which is independent
                        # of self.app_packages
                        app_package_queue.append(dependency_app_package)

    def _add_package(self, package: AppPackage) -> None:
        """Adds package to the Package Handler for tracking."""
        self.apps[package.working_artifact_name] = package.working_app_path
        self.app_packages.append(package)

    def generate_package_hash_from_dir(self, algorithm: str = "md5") -> str:
        """Recursively generate hash from a directory with order."""

        def sorted_walk(top: Path) -> Generator[Path, Any, None]:
            """
            Recursively traverses the folder tree and returns a generator of files in a sorted order.

            Args:
                top: Path to the top folder

            Yields:
                File path

            """
            names = sorted(top.iterdir())
            dirs, non_dirs = [], []

            for name in names:
                if os.path.isdir(name):
                    dirs.append(name)
                else:
                    yield name

            for dir in dirs:
                if not os.path.islink(dir):
                    for x in sorted_walk(dir):
                        yield x

        try:
            gen = hashlib.__dict__[algorithm]()
            for app_package in self.app_packages:
                for file in sorted_walk(app_package.working_app_path):
                    with open(file, "rb") as f:
                        gen.update(f.read())
            return gen.hexdigest()

        except Exception as e:
            logger.error("Failed to generate hash for app, and the error is %s", str(e))
            return "N/A"

    @property
    def main_app_package(self) -> Optional[AppPackage]:
        """Returns an AppPackage derived object."""
        if len(self.app_packages) > 0:
            return self.app_packages[0]

        return None

    def cleanup(self) -> None:
        """Helper function to initiate the cleanup function of AppPackages that are being tracked."""
        for package in self.app_packages:
            package.clean_up()
        self.origin_package.clean_up()


class AppPackage:
    """
    This is a class meant to control the logic for interacting with a potential Splunk App package provided. This is
    intended to control the initially provided application artifact and the extracted contents of the
    application artifact.

    Attributes:
        DEPENDENCIES_LOCATION: Fixed expected location of slim static dependencies' folder. This is the relative
            path from the root of the Splunk App.
        NOT_ALLOWED_PATTERN: A regex pattern used to identify invalid paths for directory names.
        is_static_slim_dependency: True if this AppPackage was derived from a package within another
            AppPackage's dependencies directory, False otherwise.
        origin_package_non_app_files: Relative paths to files within origin package that are not associated
            with a valid app.
        origin_path: An absolute path to the initially provided Splunk Application. Typically, this will be the
            compressed Splunk Application as a .tgz, .spl, etc. or a directory that is provided.
        static_slim_dependency_app_packages: list of AppPackages derived from this
            AppPackage's dependency directory.
        working_app_path: An absolute path to the extracted directory of the Splunk App folder itself.
            This should always be a directory.
        working_artifact: the path to the package contents, for FolderAppPackages working_artifact will refer
            to folder input, for CompressedAppPackages working_artifact will refer to the root directory containing
            the extracted contents (not just the path to the app within those contents).
        working_artifact_name: A string that is the directory name of the extracted Splunk App OR compressed file
            name if directory name is a temporary directory.
        app_cloud_name: For most cases it will be the same to working_artifact_name, except that some apps would
            NOT have a standalone folder after extraction, this attr will simply point to those apps' temp folder.
            (see details ACD-2149)

    """

    DEPENDENCIES_LOCATION: str = ".dependencies"
    NOT_ALLOWED_PATTERN: re.Pattern = re.compile(
        r"""
            (?P<nix>
                ^\.         # Hidden folder
            )
            | (?P<macosx>
                ^__MACOSX   # Mac OSX folder
            )
        """,
        re.VERBOSE,
    )

    def __init__(self, app_package_path: Path) -> None:
        """
        Constructor/Initialization function.

        Args:
            app_package_path: A path to a potential Splunk App package.

        """
        self.is_static_slim_dependency: bool = False
        self.origin_package_non_app_files: list[str] = []
        self.origin_path: Path = app_package_path
        self.origin_package_name: str = app_package_path.name
        self.static_slim_dependency_app_packages: list[AppPackage] = []
        self.working_artifact: Optional[Path] = None
        self.working_artifact_name: str = self._get_basename_from_path(self.origin_path)
        self.app_cloud_name: str = self.working_artifact_name
        self.working_app_path: Optional[Path] = None

    @staticmethod
    def factory(app_package_path: Union[str, Path] = "") -> AppPackage:
        """
        A helper function to facilitate the creation of AppPackage objects.

        Args:
            app_package_path: An absolute path to the initially provided application artifact. Typically, this will be
                the compressed Splunk App as a .tgz, .spl, etc. or a simple directory that is provided.

        Returns:
            Returns an AppPackage derived object that represents the type of application provided.

        """
        app_package_path = Path(app_package_path)
        if os.path.isdir(app_package_path):
            return FolderAppPackage(app_package_path)
        if zipfile.is_zipfile(app_package_path):
            return ZipAppPackage(app_package_path)

        return TarAppPackage(app_package_path)

    @staticmethod
    def generate_app_package_from_file_or_folder(resource_path: Path) -> Optional[AppPackage]:
        """
        Detects whether input file or folder path is an app, returns AppPackage if so, None otherwise.

        Args:
            resource_path: absolute path to file or folder to check.

        Returns:
            AppPackage generated or None if not an app.

        """
        # Only attempt package addition if the package is one of our
        # supported types (directory, tar, zip)
        # is_tarfile and is_zipfile need to guard against directories
        # being used as parameters otherwise an IOError will be
        # raised if a directory path is pass into those functions.
        # Python built-in library should really handle this better, but
        # not sure why it doesn't
        is_resource_a_directory = os.path.isdir(resource_path)
        is_resource_a_tar_file = not is_resource_a_directory and tarfile.is_tarfile(resource_path)
        is_resource_a_zip_file = not is_resource_a_directory and zipfile.is_zipfile(resource_path)

        if is_resource_a_directory or is_resource_a_tar_file or is_resource_a_zip_file:
            app_package_candidate = AppPackage.factory(resource_path)
            try:
                if app_package_candidate.is_splunk_app():
                    return app_package_candidate

                app_package_candidate.clean_up()
            except Exception:
                app_package_candidate.clean_up()
        return None

    def _get_working_app_path(self, root_directory: Path) -> Path:
        """
        A function to retrieve the path identified as the folder containing the App itself. This will eventually be
        used as the App.app_dir which is the folder used for validation. A working app path should contain a
        default/ folder, a README file, etc. If multiple app-like folders are found then return the root_directory
        being searched.

        Args:
            root_directory: Absolute path to the directory that a `working_app_path` is being looked for.

        Returns:
            Absolute path to the app-level directory of an extracted artifact.

        """
        # If root_directory has a default/app.conf, call it good
        if self.does_dir_contain_default_app_conf(root_directory):
            return root_directory
        try:
            if not os.path.exists(root_directory):
                raise FileNotFoundError(f"Path {root_directory} does not exist")
            contents_of_root_dir = root_directory.iterdir()
        except Exception:
            logger.warning("Issue reading contents of %s", root_directory)
            # If read permissions error or other issue, abort and return root
            return root_directory
        # If exactly one app directory is found, return that - this will be
        # true of valid apps containing a .dependencies folder outside of the
        # app folder and also for apps containing invalid files outside of
        # the app folder
        app_folder = None
        for resource_path in contents_of_root_dir:
            if os.path.isdir(resource_path) and self.does_dir_contain_default_app_conf(resource_path):
                if app_folder is not None:
                    # If we already found another app_folder, we have an
                    # app of apps, so use the entire temp folder
                    return root_directory
                app_folder = resource_path
        if app_folder is not None:
            # We found exactly one app folder, use this
            return app_folder
        return root_directory

    @staticmethod
    def _get_basename_from_path(path_to_extract_from: Path) -> str:
        """
        Extracts basename of a file resource from a file path. This accounts for nuances associated with hidden
        directories, hidden files, and file extensions.

        Args:
            path_to_extract_from: An absolute path to a file resource.

        Returns:
            Basename of the file path provided.

        """
        # The splitting on `.` is done because python's os.path.splitext is not
        # sufficiently accounting for instances of files like example.tar.gz.
        # In that case it would end up returning the name `example.tar` instead
        # of just `example`
        file_resource_full_name = path_to_extract_from.name
        split_file_resource_full_name = file_resource_full_name.split(".")

        # Appinspect only accept '.tgz', '.tar.gz', '.spl', '.zip'
        # If the artifact has a '.' at the middle of its name. For something like
        # 'example.v1.tar.gz', it will look like
        # ['example','v1','tar','gz']. So the file_resource_name should be ['example','v1']

        if file_resource_full_name.endswith(".tar.gz"):
            file_resource_name = split_file_resource_full_name[0:-2]
        elif file_resource_full_name.endswith((".tgz", ".spl", ".zip", ".tar")):
            file_resource_name = split_file_resource_full_name[0:-1]
        else:
            file_resource_name = split_file_resource_full_name

        file_resource_name_to_return = ".".join(file_resource_name)

        return file_resource_name_to_return

    @property
    def origin_artifact_name(self) -> str:
        """
        A helper function to retrieve the name of the Splunk App compressed artifact.

        Returns:
            A string that is the name of the compressed application package.

        """
        return self._get_basename_from_path(self.origin_path)

    @property
    def working_path(self) -> Path:
        """Same as working_app_path, included for backwards compatibility."""
        return self.working_app_path

    @property
    def dependencies_folder(self) -> Optional[Path]:
        """
        Returns:
            Absolute path to the dependencies folder or None if none exists.

        """
        dependencies_path = self.working_artifact.joinpath(self.DEPENDENCIES_LOCATION)
        return dependencies_path if os.path.isdir(dependencies_path) else None

    def does_package_contain_dependencies_folder(self) -> bool:
        """
        Returns:
            True if dependencies folder exists, False otherwise.

        """
        return self.dependencies_folder is not None

    def does_origin_artifact_start_with_period(self) -> bool:
        """
        Helper function for part of the origin artifact validity tests.

        Returns:
            True if origin artifact starts with `.` otherwise False.

        """
        return (
            self.origin_path is not None
            and self.origin_artifact_name.startswith(".")
            or self.origin_package_name.startswith(".")
        )

    def is_origin_artifact_valid_compressed_file(self) -> bool:
        """
        Helper function for part of the origin artifact validity tests.

        Returns:
            True if origin artifact a valid compressed file otherwise False.

        """
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)

    def does_origin_artifact_have_read_permission(self) -> bool:
        """
        Helper function for part of the origin artifact validity tests.

        Returns:
            True if origin artifact has owner read permissions (400) otherwise False.

        """
        return bool(stat.S_IMODE(self.origin_path.lstat().st_mode) & stat.S_IRUSR)

    def is_origin_artifact_a_splunk_app(self) -> bool:
        """
        A function to determine if the artifact provided is a valid Splunk App.
        Valid Splunk Apps:
        - Origin artifact is a valid compressed file
        - Origin artifact has owner read permission
        - DO NOT start with a '.'

        Returns:
            True if a Splunk App, False if it is not a Splunk App.

        """
        return (
            self.is_origin_artifact_valid_compressed_file()
            and self.does_origin_artifact_have_read_permission()
            and not self.does_origin_artifact_start_with_period()
        )

    def does_working_artifact_contain_default_app_conf(self) -> bool:
        """
        Helper function for determining if the working artifact contains a `default/app.conf` file.

        Returns:
            True if `default/app.conf` exists.

        """
        return self.does_dir_contain_default_app_conf(self.working_app_path)

    @staticmethod
    def does_dir_contain_default_app_conf(directory: str) -> bool:
        """
        Helper function for determining if the input directory contains a `default/app.conf` file.

        Returns:
            True if `default/app.conf` exists.

        """
        dir_exists = directory is not None and os.path.isdir(directory)
        has_default_directory = os.path.isdir(os.path.join(directory, "default"))
        has_default_app_conf_file = os.path.isfile(os.path.join(directory, "default", "app.conf"))

        return dir_exists and has_default_directory and has_default_app_conf_file

    def does_working_artifact_contain_app_manifest(self) -> bool:
        """
        Helper function for determining if the working artifact contains a `app.manifest` file.

        Returns:
            True if `app.manifest` exists.

        """
        return self.does_dir_contain_app_manifest(self.working_app_path)

    @staticmethod
    def does_dir_contain_app_manifest(directory: str) -> bool:
        """
        Helper function for determining if the input directory contains a `app.manifest` file.

        Returns:
            True if `app.manifest` exists.

        """
        dir_exists = directory is not None and os.path.isdir(directory)
        has_app_manifest_file = os.path.isfile(os.path.join(directory, "app.manifest"))

        return dir_exists and has_app_manifest_file

    def is_working_artifact_a_directory(self) -> bool:
        """
        Helper function to determine if the working artifact is available and a directory.

        Returns:
            True if working directory is a directory, False if it is not a directory.

        """
        return os.path.isdir(self.working_app_path)

    def is_working_artifact_a_splunk_app(self) -> bool:
        """
        A function to determine if the provided artifact, after being extracted, is a valid Splunk App.
        Valid Splunk Apps:
        - DO contain a default/app.conf
        - DO not contain prohibited directories
            - __MACOSX
            - directories that start with '.' INCLUDING .dependencies as that
              folder should only exist OUTSIDE of the splunk app folder

        Returns:
            True if a Splunk App, False if it is not a Splunk App.

        """
        does_working_artifact_directory_start_with_a_period = self.working_artifact_name.startswith(".")

        return (
            self.does_working_artifact_contain_default_app_conf()
            and self.is_working_artifact_a_directory()
            and not does_working_artifact_directory_start_with_a_period
            and not self.does_contain_prohibited_files()
            and not self.does_contain_invalid_directories()
            and not self.does_contain_invalid_files()
        )

    def is_splunk_app(self) -> bool:
        """
        A helper function to determine if the Splunk App provided is a valid Splunk App.

        Returns:
            True if a Splunk App, False if it is not a Splunk App.

        """
        return self.is_origin_artifact_a_splunk_app() and self.is_working_artifact_a_splunk_app()

    @property
    def is_app(self) -> bool:
        """Same as is_splunk_app(), included for backwards compatibility."""
        return self.is_splunk_app()

    @staticmethod
    def find_prohibited_files(
        directory_to_search: Path, directory_allow_list: Optional[list[str]] = None
    ) -> list[Path | str]:
        """
        Function to locate prohibited directories and files.

        Args:
            directory_to_search: Absolute path to the directory to search.
            directory_allow_list: Names of files to ignore when returning list of prohibited files or None to
                include all.

        Returns:
            Array of prohibited directories or files.

        """
        directory_allow_list = set(directory_allow_list or [])
        file_paths_to_return = []

        directory_name = directory_to_search.name

        # Whether the `directory_to_search` is a file or a directory, if it
        # violates the `AppPackage.NOT_ALLOWED_PATTERN` it will be added
        if re.findall(AppPackage.NOT_ALLOWED_PATTERN, directory_name):
            file_paths_to_return.append(directory_name)

        # Searches subdirectories and files for matches
        for child in Path(directory_to_search).rglob("*"):
            if os.path.isdir(child) and child.name in directory_allow_list:
                continue
            if re.findall(AppPackage.NOT_ALLOWED_PATTERN, child.name):
                file_paths_to_return.append(child)

        return file_paths_to_return

    def does_contain_prohibited_files(self) -> bool:
        """
        Determine if package contains any prohibited files.

        Returns:
            True if a prohibited file is found, False if none are found.

        """
        prohibited_directories_and_files = self.find_prohibited_files(
            self.working_artifact, [self.DEPENDENCIES_LOCATION]
        )
        return len(prohibited_directories_and_files) > 0

    @staticmethod
    def find_invalid_directories_with_wrong_permission(directory_to_search: Path, permissions_mask: int) -> list[Path]:
        """
        Function to find directories with incorrect permissions. Directories and subdirectories must have the owner's
        permissions set to r/w/x (700).

        Args:
            directory_to_search: Absolute path to the directory to search.
            permissions_mask: permission mask code to check against.

        Returns:
            Array of directories with incorrect permissions.

        """
        invalid_directories = []

        # Check all subdirectories
        if os.path.isdir(directory_to_search):
            for directory in Path(directory_to_search).rglob("**"):
                try:
                    mode = directory.stat().st_mode
                except OSError:
                    invalid_directories.append(directory)
                else:
                    if (mode & permissions_mask) != permissions_mask:
                        invalid_directories.append(directory)

        return invalid_directories

    @staticmethod
    def find_files_with_incorrect_permissions(directory_to_search: str | Path, permissions_mask: int) -> list[Path]:
        """
        Function to find files with incorrect permissions. Files must have the owner's permissions set to r/w (600).

        Args:
            directory_to_search: absolute path to the directory to search.
            permissions_mask: permission mask code to check against.

        Returns:
            Array of files with incorrect permissions.

        """
        invalid_files = []

        for file in Path(directory_to_search).rglob("*"):
            if not os.path.isfile(file):
                continue
            try:
                mode = file.stat().st_mode
            except OSError:
                invalid_files.append(file)
            else:
                if (mode & permissions_mask) != permissions_mask:
                    invalid_files.append(file)

        return invalid_files

    def does_contain_invalid_directories(self) -> bool:
        """
        Determine if a directory contains invalid folders with incorrect permissions. Directories and subdirectories
        must have the owner's permissions set to r/w/x (700).

        Returns:
            True if an invalid directory with incorrect permission is found, False if none are found.

        """
        invalid_directories = self.find_invalid_directories_with_wrong_permission(self.working_artifact, stat.S_IRWXU)
        return len(invalid_directories) > 0

    def does_contain_invalid_files(self) -> bool:
        """
        Determine if a directory contains invalid folders with incorrect permissions. Files must have the owner's
        permissions include read and write (600).

        Returns:
            True if an invalid directory with incorrect permission is found, False if none are found.

        """
        invalid_files = self.find_files_with_incorrect_permissions(self.working_artifact, stat.S_IRUSR | stat.S_IWUSR)
        return len(invalid_files) > 0

    def check_valid_package_for_SSAI(self) -> bool:
        """
        Determine if the pacakge is not .ziptype. ZIP package is not valid for SSAI.

        Returns:
            True for valid, False for invalid.

        """
        if zipfile.is_zipfile(self.origin_path):
            return False

        return True

    def find_files_not_part_of_valid_apps(self) -> list[Path]:
        """
        Determine if files are contained in package that are not part of the valid app_dir nor .dependencies folder.

        Returns:
            Strings of absolute paths to any non-app files.

        """
        # If the working_artifact is the same as the working_dir (app_dir)
        # then it's a simple app folder, so any files in there are presumed to
        # be app related if the app is valid, if not valid simply return the
        # working_app_path folder
        working_app_path_is_app = self.is_working_artifact_a_splunk_app()
        if self.working_app_path == self.working_artifact:
            return [] if working_app_path_is_app else [self.working_app_path]
        # Determine if working_app_path is a valid app and if it contains an
        # app.manifest file, these will affect whether working_app_path and the
        # .dependencies folder are valid
        contents = set(Path(self.working_artifact).iterdir())
        if self.working_app_path in contents and working_app_path_is_app:
            # We can remove the working_app_path from contents as it is a valid app
            contents.remove(self.working_app_path)
            dependencies_folder = Path(self.working_artifact, self.DEPENDENCIES_LOCATION)
            working_app_path_has_manifest = self.does_working_artifact_contain_app_manifest()
            if dependencies_folder in contents and os.path.isdir(dependencies_folder) and working_app_path_has_manifest:
                # We can remove .dependencies folder as the app is valid, in
                # contents, and has an app.manifest. Otherwise, .dependencies
                # is not valid
                contents.remove(dependencies_folder)
        # TODO: apps other that working_app_path (e.g. app of apps)
        return list(contents)

    def clean_up(self) -> None:
        """An abstract function for managing the clean up of an extracted Splunk App."""
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)


class FolderAppPackage(AppPackage):
    """
    This is a derived AppPackage class meant to control the logic for interacting with a Splunk App that is provided
    in the form of a directory.
    """

    def __init__(self, app_package_path: Path) -> None:
        """
        Constructor/initialization function.

        Args:
            app_package_path: An absolute path to a potential Splunk App.

        """
        super(FolderAppPackage, self).__init__(app_package_path)
        self.working_artifact = Path(os.path.abspath(self.origin_path))
        self.working_app_path = self._get_working_app_path(self.working_artifact)
        self.working_artifact_name = self._get_basename_from_path(self.working_app_path)
        # Refer to ACD-2149 for purpose of app_cloud_name
        self.app_cloud_name = self.working_artifact_name

    def clean_up(self) -> None:
        """A function for managing the clean up of an extracted Splunk App."""
        # This is over-ridden so that the base class's method is not called
        # Directories do not need to be cleaned up.

    def is_origin_artifact_valid_compressed_file(self) -> True:
        """
        Helper function for part of the origin artifact validity tests.

        Returns:
            Always returns True because folders are not compressed.

        """
        # This is returning True every time because FolderAppPackage's are not a
        # compressed artifact.
        # This has to be over-ridden because the base class `AppPackage` will
        # have its `is_origin_artifact_valid_compressed_file` called during the
        # `is_origin_artifact_a_splunk_app` check.
        # The alternative is to override `is_origin_artifact_a_splunk_app`, but
        # that means that we would be overriding the logic for the general
        # validation which does not seem preferable be cause it means we will
        # have to make sure that all logic is handled correctly during different
        # validation changes. Perhaps we will reverse this decision in the future
        return True


class CompressedAppPackage(AppPackage):
    """This is the base class for any compressed app packages (.zip, .tgz, etc)."""

    def __init__(self, app_package_path: Path) -> None:
        """
        Constructor/initialization function.

        Args:
            app_package_path: Absolute path to a potential Splunk App package.

        """
        super().__init__(app_package_path)
        # Attempt to extract origin path
        self.extracted_path = Path(tempfile.mkdtemp())
        self.origin_artifact_is_valid_compressed_file = False
        try:
            traversal_attack_found = self._perform_extraction(  # pylint: disable=E1111
                self.origin_path, self.extracted_path
            )  # noqa pylint: disable=assignment-from-no-return
            self.origin_artifact_is_valid_compressed_file = not traversal_attack_found
            self.working_artifact = self.extracted_path
            # If user packs app by tar -cvzf app-folder.tgz app-folder, it's extracted in <temp-dir>/app-folder
            # If user packs app by tar -cvzf app-folder.tgz default bin metadata..., it's extracted in <temp-dor>
            # Checking app pattern for one layer deeper
            self.working_app_path = self._get_working_app_path(self.working_artifact)
            if self.working_app_path != self.working_artifact:
                # If we found an app dir within the extracted path, use this
                # for the working artifact name
                self.working_artifact_name = self._get_basename_from_path(self.working_app_path)
                # Refer to ACD-2149 for purpose of app_cloud_name
                self.app_cloud_name = self.working_artifact_name
            else:
                self.app_cloud_name = self.extracted_path.name
        except Exception as e:
            # If can't be extracted then just set resource to be compressed file
            self.working_app_path = self.origin_path
            application_name = self.origin_path.name
            logger.warning("Failed to extract %s", application_name)
            logger.error(str(e))

    def _perform_extraction(self, compressed_application_path: Path, temporary_directory: Path) -> bool:
        """
        Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path: An absolute path to a compressed artifact.
            temporary_directory: An absolute path to a temporary directory to extract to.

        Returns:
          True if a traversal attack found, False if not.

        """
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)

    def is_origin_artifact_valid_compressed_file(self) -> bool:
        """
        Helper function for part of the origin artifact validity tests.

        Returns:
            True if origin artifact a valid compressed file otherwise False.

        """
        return self.origin_artifact_is_valid_compressed_file

    def clean_up(self) -> None:
        """Function for managing the cleanup of an extracted Splunk App."""
        if self.extracted_path is not None and os.path.isdir(self.extracted_path):
            # ACD-940 Permission Denied
            os.chmod(self.extracted_path, 0o777)
            for root, dirs, _ in os.walk(self.extracted_path):
                for d in dirs:
                    os.chmod(Path(root, d), 0o777)

            logger.info("Cleaning temp directory: %s", self.extracted_path)

            try:
                shutil.rmtree(self.extracted_path)
            except OSError as e:
                logger.warning("OSError raised when cleaning temp directory. Error: %s", str(e))
                # WA ACD-3024
                # TODO: resolve the issue and re-raise exception
                # raise

    def get_content_path_names(self) -> list[str]:
        """Lists path names in compressed package."""
        error_message = "This is an abstract method meant to be over-ridden."
        raise NotImplementedError(error_message)


class TarAppPackage(CompressedAppPackage):
    """
    This is an AppPackage derived class meant to control the logic for interacting with a Splunk App that
    is provided in the form of a compressed Tar file.
    """

    def _perform_extraction(self, compressed_application_path: Path, temporary_directory: Path) -> bool:
        """
        Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path: An absolute path to a compressed artifact.
            temporary_directory: An absolute path to a temporary directory to extract to.

        Returns:
            True if a traversal attack found, False if not.

        """
        try:
            tarsec = TarSec(filename=str(compressed_application_path))
        except tarfile.TarError:
            logger.info("Encountered tarfile exception.", compressed_application_path)
            return True

        if not tarsec.is_safe():
            logger.info("The tar file is considered unsafe.", compressed_application_path)
            return True
        with tarfile.open(compressed_application_path) as tar:
            tar.extractall(path=temporary_directory)

        return False

    def get_content_path_names(self) -> list[str]:
        with tarfile.open(self.origin_path) as tar_file:
            return tar_file.getnames()


class ZipAppPackage(CompressedAppPackage):
    """
    This is an AppPackage derived class meant to control the logic for interacting with a Splunk App that
    is provided in the form of a compressed Zip file.
    """

    def _perform_extraction(self, compressed_application_path: str, temporary_directory: str) -> bool:
        """
        Extracts a compressed file to a temporary location.

        Args:
            compressed_application_path: An absolute path to a compressed artifact.
            temporary_directory: An absolute path to a temporary directory to extract to.

        Returns:
            True if a traversal attack found, False if not.

        """
        # ACD-450 Zip Traversal attack is managed by Python core
        with zipfile.ZipFile(compressed_application_path) as zip_file:
            zip_file.extractall(temporary_directory)
        # As of Python 2.7.4 traversal attacks should be handled automatically
        # for the ZipFile.extractall() method.
        # See: https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extract
        # and https://docs.python.org/2/library/zipfile.html#zipfile.ZipFile.extractall
        return False
