# Copyright 2019 Splunk Inc. All rights reserved.
"""Splunk Application abstraction module"""
from __future__ import annotations

import hashlib
import inspect
import logging
import os
import re
import shutil
import stat
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional, Union

import magic

from splunk_appinspect.checks import Check
from splunk_appinspect.configuration_parser import InvalidSectionError
from splunk_appinspect.python_modules_metadata import python_modules_metadata_store
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS

from . import (
    alert_actions,
    app_configuration_file,
    app_package_handler,
    authentication_configuration_file,
    authorize_configuration_file,
    collections_configuration_file,
    configuration_file,
    configuration_parser,
    custom_commands,
    custom_visualizations,
    file_resource,
    file_view,
    indexes_configuration_file,
    inputs_configuration_file,
    inputs_specification_file,
    inspected_file,
    modular_inputs,
    outputs_configuration_file,
    props_configuration_file,
    python_analyzer,
    rest_map,
    saved_searches,
    telemetry_configuration_file,
    web_configuration_file,
)

if TYPE_CHECKING:
    from splunk_appinspect.app_package_handler import AppPackage
    from splunk_appinspect.configuration_file import ConfigurationFile
    from splunk_appinspect.custom_types import ConfigurationProxyType
    from splunk_appinspect.python_analyzer.trustedlibs.trusted_libs_manager import TrustedLibsManager

logger = logging.getLogger(__name__)


class App(object):
    """A class for providing an interface to a Splunk App. Used to create helper
    functions to support common functionality needed to investigate a Splunk
    App and its contents.

    Args:
        location (str|Path): Either a package(.spl, .tgz, or .zip) or a directory
            containing the app
        package (AppPackage Object): Previously packaged AppPackage associated
            with the input location, None if package has not yet been generated

    Attributes:
        package (AppPackage derived object): The AppPackage object that
            represents the Splunk App passed into the App for initialization.
        package_handler (AppPackageHandler object): The AppPackageHandler
            object that is created using the Splunk App provided for
            initialization.
        app_dir (Path): The path of the Splunk App artifact after having been
            extracted.
        name (String): This is the file or directory name of the extracted
            Splunk App artifact passed in during initialization.
        dependencies_directory_path (Path): The path of the App's static .dependencies directory
            relative to the app's directory.
        is_static_slim_dependency (Boolean): True if this App was derived from
            a package within another App's dependencies directory, False
            otherwise.
        static_slim_app_dependencies (List of instances of this class): Apps
            or instances of subclass of App (e.g. DynamicApp) derived from
            AppPackages inside of this App's dependencies directory.
    """

    def __init__(
        self,
        location: Optional[str | Path] = None,
        package: Optional["AppPackage"] = None,
        python_analyzer_enable: bool = True,
        trusted_libs_manager: Optional["TrustedLibsManager"] = None,
    ) -> None:
        if location is None and package is None:
            logger_output = (
                "splunk_appinspect.App requires either a `location` or `package` argument to be initialized."
            )
            logger.error(logger_output)
            self.package = None
            raise ValueError(logger_output)
        if package is None:
            package = app_package_handler.AppPackage.factory(location)
        self.package = package
        self._id = None
        self._static_slim_app_dependencies = None
        self.python_analyzer_enable = python_analyzer_enable

        # Setup file view
        self.app_file_view = self.get_file_view()

        # Setup merged configuration holders
        self._default_config = None
        self._local_config = None
        self._merged_config = None
        self._users: set[str] = set()
        self._user_configs: Optional[dict[str, configuration_file.ConfigurationProxy]] = None
        self._merged_user_configs: Optional[dict[str, configuration_file.MergedConfigurationProxy]] = None

        # initialize trusted libs manager
        self._trusted_libs_manager = trusted_libs_manager
        self.LINUX_ARCH = "linux"
        self.WIN_ARCH = "win"
        self.DARWIN_ARCH = "darwin"
        self.DEFAULT_ARCH = "default"
        self.arch_bin_dirs = {
            self.LINUX_ARCH: [
                Path(self.app_dir, "linux_x86", "bin"),
                Path(self.app_dir, "linux_x86_64", "bin"),
            ],
            self.WIN_ARCH: [
                Path(self.app_dir, "windows_x86", "bin"),
                Path(self.app_dir, "windows_x86_64", "bin"),
            ],
            self.DARWIN_ARCH: [
                Path(self.app_dir, "darwin_x86", "bin"),
                Path(self.app_dir, "darwin_x86_64", "bin"),
            ],
            self.DEFAULT_ARCH: [Path(self.app_dir, "bin")],
        }
        # Store the base directories for scripts to be located. Generally
        # speaking any app-specific code will be in these base directories and
        # third-party libraries may be included within subdirectories of thesel
        self.base_bin_dirs = [
            Path(os.path.relpath(path, self.app_dir))
            for arch in self.arch_bin_dirs
            for path in self.arch_bin_dirs.get(arch)
        ] + [Path("bin", "scripts")]
        self.info_from_file = {}
        # configuration files cache
        self.app_conf_files = {}
        # Invalid conf files cache
        self.invalid_conf_files = {}
        # Custom conf files cache
        self._custom_conf_files = None
        self._user_custom_conf_files = None

        for directory, file, _ in self.iterate_files():
            current_file_relative_path = Path(directory, file)
            current_file_full_path = self.get_filename(current_file_relative_path)
            try:
                output = magic.from_file(str(current_file_full_path))
            except Exception as e:
                logger.debug("Magic library reports error: %s", str(e))
            else:
                self.info_from_file[current_file_relative_path] = output

        with Path(self.app_dir, "users") as users_path:
            if users_path.exists():
                for user_dir in Path(self.app_dir, "users").iterdir():
                    if user_dir.is_dir() and next(users_path.iterdir()) is not None:
                        self._users.add(user_dir.name)

        if self.python_analyzer_enable:
            try:
                py_modules_metadata = python_modules_metadata_store.metadata_store
                self._app_temp_dir = Path(tempfile.mkdtemp(), self.package.working_app_path.name)
                shutil.copytree(self.package.working_app_path, self._app_temp_dir)
                self._python_analyzer_client = python_analyzer.client.Client(
                    files_folder=self._app_temp_dir,
                    modules_metadata=py_modules_metadata,
                    trusted_libs_manager=self._trusted_libs_manager,
                )
            except Exception:
                logger.error(
                    "Folder %s is not found. App %s",
                    self.package.working_app_path,
                    self.name,
                )

    def targlob(self) -> bytes:
        """Create an in-memory tarball of all files in the directory

        Returns:
            The tarball archive as a bytes object.
        """
        # TODO: tests needed
        glob = BytesIO()
        tar = tarfile.open(mode="w", fileobj=glob)
        tar.add(self.app_dir, recursive=True, arcname=self.name)
        tar.close()
        return glob.getvalue()

    def __del__(self) -> None:
        self.cleanup()

    @property
    def name(self) -> str:
        """Helper function to return the name of the extracted Splunk App.

        Returns:
          name of the extracted Splunk App

        """
        return self.package.working_artifact_name

    @property
    def app_dir(self) -> Path:
        """Helper function to return the path to top level directory of the
        extracted Splunk App.

        Returns:
          An absolute path to the top level directory of the extracted
          Splunk App

        """
        return self.package.working_app_path

    @property
    def app_temp_dir(self) -> str | None:
        return self._app_temp_dir if hasattr(self, "_app_temp_dir") else None

    @property
    def dependencies_directory_path(self) -> Path:
        """
        Returns:
            Fixed expected location of slim static dependencies
                folder relative to app_dir
        """
        return Path(os.pardir, self.package.DEPENDENCIES_LOCATION)

    @property
    def is_static_slim_dependency(self) -> bool:
        """
        Returns:
          True if this App was derived from a package within another
          App's dependencies directory, False otherwise.

        """
        return self.package.is_static_slim_dependency

    @property
    def static_slim_app_dependencies(self) -> list[App]:
        """
        Returns:
          List of instances of this class (App or class inherited from App)
          derived from AppPackages within the dependencies directory of
          this App.

        """
        # If we haven't generated self._static_slim_app_dependencies yet,
        # do this once and store the resulting list
        if self._static_slim_app_dependencies is None:
            self._static_slim_app_dependencies = []
            for dependency_package in self.package.static_slim_dependency_app_packages:
                dependency_app = self.__class__(
                    package=dependency_package,
                    trusted_libs_manager=self._trusted_libs_manager,
                )
                self._static_slim_app_dependencies.append(dependency_app)
        return self._static_slim_app_dependencies

    @property
    def python_analyzer_client(self) -> python_analyzer.client.Client:
        if not self.python_analyzer_enable:
            raise Exception("Python analyzer is disabled. To enable, please run checks including ast tag.")

        if not hasattr(self, "_python_analyzer_client"):
            raise Exception("Python analyzer is failed in initialization.")
        return self._python_analyzer_client

    @property
    def id(self) -> str:
        if self._id is None:
            self._id = ""
            try:
                if self.file_exists("default", "app.conf"):
                    app_configuration_file = self.get_config("app.conf")
                    package_configuration_section = app_configuration_file.get_section("package")
                    if package_configuration_section.has_option("id"):
                        self._id = package_configuration_section.get_option("id").value
            except Exception:
                pass
        return self._id

    def cleanup(self) -> None:
        if self.package is not None:
            self.package.clean_up()
        if hasattr(self, "_app_temp_dir"):
            shutil.rmtree(self._app_temp_dir.parent)

    def get_config(
        self,
        name: str,
        dir: str | Path = "default",
        config_file: Optional["ConfigurationFile"] = None,
    ) -> "ConfigurationFile":
        """Returns a parsed config file as a ConfFile object. Note that this
        does not do any of Splunk's layering- this is just the config file,
        parsed into a dictionary that is accessed via the ConfFile's helper
        functions.

        Args:
          name: The name of the config file.  For example, 'inputs.conf'
          dir: The directory in which to look for the config file.  By default, 'default'

        """
        app_filepath = self.get_filename(dir, name)
        conf_file_key = str(app_filepath) + config_file.__class__.__name__
        if conf_file_key in self.invalid_conf_files:
            raise self.invalid_conf_files[conf_file_key]
        if not self.app_conf_files.get(conf_file_key):
            getconfig = "get_config"
            log_output = (
                f"'{__file__}' called '{getconfig}' to retrieve the configuration file '{name}'"
                f" at directory '{dir}'. App filepath: {app_filepath}"
            )
            logger.debug(log_output)
            if not self.file_exists(app_filepath):
                error_output = f"No such conf file: {app_filepath}"
                raise IOError(error_output)

            # Makes generic configuration file if no specified configuration file is
            # passed in
            if config_file is None:
                config_file = configuration_file.ConfigurationFile(
                    relative_path=Path(os.path.relpath(app_filepath, self.app_dir))
                )

            with open(app_filepath, "rb") as file:
                try:
                    config_file = configuration_parser.parse(
                        file, config_file, configuration_parser.configuration_lexer
                    )
                    self.app_conf_files[conf_file_key] = config_file
                except InvalidSectionError as e:
                    # re-raise the error from parser
                    e.file_name = app_filepath.relative_to(self.app_dir)
                    self.invalid_conf_files[conf_file_key] = e
                    raise

        return self.app_conf_files[conf_file_key]

    def get_spec(
        self,
        name: str,
        dir: str = "default",
        config_file: Optional["ConfigurationFile"] = None,
    ) -> "ConfigurationFile":
        """Returns a parsed config spec file as a ConfFile object.

        Args:
          name: The name of the config file.  For example, 'inputs.conf.spec'
          dir: The directory in which to look for the config file.  By default, 'default'
        """
        app_filepath = self.get_filename(dir, name)

        get_config = "get_config"
        log_output = (
            f"'{__file__}' called '{get_config}' to retrieve the configuration file '{name}'"
            f" at directory '{dir}'. App filepath: {app_filepath}"
        )
        logger.debug(log_output)
        if not self.file_exists(app_filepath):
            error_output = f"No such conf file: {app_filepath}"
            raise IOError(error_output)

        # Makes generic configuration file if no specified configuration file is
        # passed in
        if config_file is None:
            config_file = configuration_file.ConfigurationFile()

        with open(app_filepath, "rb") as file:
            try:
                config_file = configuration_parser.parse(
                    file,
                    config_file,
                    configuration_parser.specification_lexer,
                )
            except InvalidSectionError as e:
                # re-raise the error from parser
                e.file_name = app_filepath.relative_to(self.app_dir)
                raise

        return config_file

    def get_meta(
        self,
        name: str,
        directory: str | Path = "metadata",
        meta_file: Optional[configuration_file.ConfigurationFile] = None,
    ) -> configuration_file.ConfigurationFile:
        """Returns a parsed meta file as a Meta object.

        Args:
          name: The name of the meta file.  For example, 'default.meta'
          directory: The directory in which to look for the config file.
          By default, 'default'
        """
        # This uses the configuration file conventions because there does not
        # appear to be any difference between configuration files and meta
        # files.
        # TODO: investigate if meta file class should exist
        app_filepath = self.get_filename(directory, name)

        get_config = "get_config"
        log_output = (
            f"'{__file__}' called '{get_config}' to retrieve the configuration file '{name}'"
            f" at directory '{directory}'. App filepath: {app_filepath}"
        )
        logger.debug(log_output)
        if not self.file_exists(app_filepath):
            error_output = f"No such metadata file: {app_filepath}"
            raise IOError(error_output)

        # Makes generic meta file if no specified meta file is
        # passed in
        if meta_file is None:
            meta_file = configuration_file.ConfigurationFile(name)

        with open(app_filepath, "rb") as file:
            meta_file = configuration_parser.parse(file, meta_file, configuration_parser.configuration_lexer)

        return meta_file

    def get_raw_conf(self, name: str, dir: Union[str, Path] = "default") -> bytes:
        """Returns a raw version of the config file.

        Args:
          name: The name of the config file.  For example 'inputs.conf'
          dir: The directory in which to look for the config file.  By default, 'default'

        Returns:
          A raw representation of the conf file

        """
        # Should this be a with fh.open??
        app_filepath = self.get_filename(dir, name)
        fh = open(app_filepath, "rb")
        conf_content = fh.read()
        fh.close()

        raw_conf = "get_raw_conf"
        log_output = (
            f"'{__file__}' called '{raw_conf}' to retrieve the configuration file '{name}'"
            f" at directory '{dir}'. App filepath: {app_filepath}"
        )
        logger.debug(log_output)

        return conf_content

    def get_filename(self, *path_parts: Union[str, Path]) -> Path:
        """
        Given a relative path, return a fully qualified location to that file
        in a format suitable for passing to open, etc.

        example: app.get_filename('default', 'inputs.conf')

        """
        return Path(self.app_dir, *path_parts)

    def _get_app_info(self, stanza: str, option: str, app_conf_dir: str = "default") -> str:
        """A function to combine the efforts of retrieving app specific
        information from the `default/app.conf` file. This should always return
        a string.

        Returns:
          Will either be a string that is the value from the
          `default/app.conf` file or will be an error message string
          indicating that failure occurred.

        """
        try:
            logger_error_message = (
                "An error occurred trying to retrieve"
                " information from the app.conf file."
                " Error: {error}"
                " Stanza: {santa}"
                " Property: {property}"
            )

            app_config = self.app_conf(dir=app_conf_dir)

            property_to_return = app_config.get(stanza, option)
        except IOError as exception:
            error_message = repr(exception)
            logger_output = f"The `app.conf` file does not exist." f" Error: {error_message}"
            logger.error(logger_output)
            property_to_return = f"[MISSING `{app_conf_dir}/app.conf`]"
            raise exception
        except configuration_file.NoSectionError as exception:
            error_message = repr(exception)
            logger_output = logger_error_message.format(error=error_message, santa=stanza, property=option)
            logger.error(logger_output)
            property_to_return = f"[MISSING `{app_conf_dir}/app.conf` stanza `{stanza}`]"
            raise exception
        except configuration_file.NoOptionError as exception:
            # TODO: tests needed
            error_message = repr(exception)
            logger_output = logger_error_message.format(error=error_message, santa=stanza, property=option)
            logger.error(logger_output)
            property_to_return = f"[MISSING `{app_conf_dir}/app.conf` stanza [{stanza}] property `{option}`]"
            raise exception
        except Exception as exception:
            # TODO: tests needed
            error_message = repr(exception)
            logger_output = (
                "An unexpected error occurred while trying to"
                " retrieve information from the app.conf file"
                f" Error: {error_message}"
            )
            logger.error(logger_output)
            property_to_return = "[Unexpected error occurred]"
            raise exception
        finally:
            # The exceptions are swallowed here because raising an exception and
            # returning a value are mutually exclusive
            # If we want to always raise an exception this will have to be
            # re-worked
            return property_to_return

    def app_info(self) -> dict[str, str | None]:
        """Helper function to retrieve a set of information typically required
        for run-time. Tries to get author, description, version, label, and
        hash.

        Returns:
          Dict of string key value pairs

        """
        app_info = {}

        app_info["author"] = self.author
        app_info["description"] = self.description
        app_info["version"] = self.version
        app_info["name"] = self.name
        app_info["hash"] = self._get_hash()
        app_info["label"] = self.label
        app_info["package_id"] = self.package_id

        return app_info

    @property
    def author(self) -> str:
        """Helper function to retrieve the app.conf [launcher] stanza's author
        property.

        Returns:
          the default/app.conf [launcher] stanza's author property

        """
        return self._get_app_info("launcher", "author")

    @property
    def description(self) -> str:
        """Helper function to retrieve the app.conf [launcher] stanza's
        `description` property.

        Returns:
          the default/app.conf [launcher] stanza's `description`
          property

        """
        return self._get_app_info("launcher", "description")

    @property
    def version(self) -> str:
        """Helper function to retrieve the app.conf [launcher] stanza's
        `version` property.

        Returns:
          the default/app.conf [launcher] stanza's `version`
          property

        """
        return self._get_app_info("launcher", "version")

    @property
    def label(self) -> str:
        """Helper function to retrieve the app.conf [ui] stanza's `label`
        property.

        Returns:
          the default/app.conf [ui] stanza's `label` property

        """

        return self._get_app_info("ui", "label")

    @property
    def package_id(self) -> str | None:
        """Helper function to retrieve the app.conf [package] stanza's `id`
        property.

        Returns:
          the default/app.conf [package] stanza's `id` property

        """
        if self.file_exists("default", "app.conf") and self.app_conf().has_option("package", "id"):
            return self._get_app_info("package", "id")
        return None

    def _get_hash(self) -> str:
        md5 = hashlib.md5()

        try:
            for directory, filename, _ in self.iterate_files():
                file_path = Path(self.app_dir, directory, filename)
                file_obj = open(file_path, "rb")
                md5.update(file_obj.read())
        except Exception as exception:
            logger.error(exception)

        return md5.hexdigest()

    def iterate_files(
        self,
        basedir: str | Path | list[str | Path] = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        names: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: int | float = float("inf"),
        skip_compiled_binaries: bool = False,
    ) -> Generator[tuple[Path, str, str], Any, None]:
        """Iterates through each of the files in the app, optionally filtered
        by file extension.

        Example:

        for file in app.iterate_files(types=['.gif', '.jpg']):
            pass

        This should be considered to only be a top down traversal/iteration.
        This is because the filtering of directories, and logic used to track
        depth are based on the os.walk functionality using the argument of
        `topdown=True` as a default value. If bottom up traversal is desired
        then a separate function will need to be created.

        Args:
          basedir: The directory or list of directories to start in (Default value = "")
          excluded_dirs: These are directories to exclude when iterating.
        Exclusion is done by directory name matching only. This means if you
        exclude the directory 'examples' it would exclude both `examples/`
        and `default/examples`, as well as any path containing a directory
        called `examples`.
          types: An array of types that the filename should match (Default value = None)
          excluded_types: An array of file extensions that should be
        skipped. (Default value = None)
          excluded_bases: An array of file names (without extensions)
        that should be skipped. (Default value = None)
          recurse_depth: This is used to indicate how deep you want
        traversal to go. 0 means do no recurse, but return the files at the
        directory specified. (Default value = float("inf"))
          names:  (Default value = None)
          skip_compiled_binaries:  (Default value = False)

        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        names = names or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        excluded_bases = [base.lower() for base in excluded_bases]
        check_extensions = len(types) > 0
        check_names = len(names) > 0

        if not isinstance(basedir, list):
            basedir = [basedir]

        for subdir in basedir:
            root_path = Path(self.app_dir, subdir)
            # +1 is added for compatibility with the previous version
            # of this function before migrating to `pathlib`
            root_depth = len(root_path.parts)

            for base, directories, files in os.walk(root_path):
                base = Path(base)
                current_iteration_depth = len(base.parts)
                current_depth = current_iteration_depth - root_depth

                # Filters undesired directories
                directories[:] = [directory for directory in directories if directory not in excluded_dirs]

                # Create the file's relative path from within the app
                dir_in_app = base.relative_to(self.app_dir)
                if current_depth <= recurse_depth:
                    for file_name in files:
                        filebase, ext = os.path.splitext(file_name)
                        is_executable_binary = self._check_if_executable_binary(ext, base, file_name)
                        if (
                            (check_extensions and ext not in types)
                            or (check_names and file_name not in names)
                            or (ext != "" and ext in excluded_types)
                            or (filebase.lower() in excluded_bases)
                            or (skip_compiled_binaries and is_executable_binary)
                        ):
                            pass
                        else:
                            # guess check name with frame inspection
                            check_name, current_frame = None, inspect.currentframe()
                            while current_frame:
                                name = current_frame.f_code.co_name
                                f_locals = current_frame.f_locals
                                varnames = current_frame.f_code.co_varnames
                                if name == "run" and "self" in varnames and issubclass(type(f_locals["self"]), Check):
                                    # This is Check.run, where `self` is the Check object
                                    # so we can get `self` from f_locals
                                    check_name = f_locals["self"].name

                                current_frame = current_frame.f_back

                            if not self._filter_by_trusted_libs(dir_in_app, file_name, check_name):
                                yield dir_in_app, file_name, ext
                else:
                    pass

    @staticmethod
    def _check_if_executable_binary(ext: str, base: Union[Path, str], file_name: Union[Path, str]) -> bool:
        if ext == ".exe":
            return True
        if ext != "":
            return False

        file_path = os.path.join(base, file_name)
        file_type = magic.from_file(file_path).lower()
        return "executable" in file_type

    def get_filepaths_of_files(
        self,
        basedir: str | Path | list[str] | list[Path] = "",
        excluded_dirs: Optional[list[str]] = None,
        filenames: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
    ) -> Generator[tuple[Path, Path], Any, None]:
        excluded_dirs = excluded_dirs or []
        filenames = filenames or []
        types = types or []

        for directory, file, _ in self.iterate_files(
            basedir=basedir, excluded_dirs=excluded_dirs, types=types, excluded_types=[]
        ):
            current_file_full_path = Path(self.app_dir, directory, file)
            current_file_relative_path = Path(directory, file)
            split_filename = os.path.splitext(file)
            filename = split_filename[0]
            check_filenames = len(filenames) > 0

            filename_is_in_filenames = filename not in filenames
            if check_filenames and filename_is_in_filenames:
                pass
            else:
                yield current_file_relative_path, current_file_full_path

    def file_exists(self, *path_parts: str | Path) -> bool:
        """Check for the existence of a file given the relative path.

        Example:
        if app.file_exists('default', 'transforms.conf'):
             print "File exists! Validate that~!~"
        """
        file_path = Path(self.app_dir, *path_parts)
        does_file_exist = os.path.isfile(file_path)

        file_exist = "file_exists"
        log_output = (
            f"'{__file__}.{file_exist}' was called. File path being checked:'{file_path}'. "
            f"Does File Exist: {does_file_exist}"
        )
        logger.debug(log_output)
        return does_file_exist

    def get_config_file_paths(
        self, config_file_name: str, basedir: list[str] | list[Path] = ["default", "local"]
    ) -> dict[str | Path, str]:
        """Return a dict of existing config_file in given name and corresponding folder names

        Args:
          config_file_name: name of configuration file
          basedir: list of directories to search in

        Returns:
          config_file_paths: map of folder name and configuration file name

        """
        config_file_paths = {}
        for config_folder in basedir:
            if self.file_exists(config_folder, config_file_name):
                config_file_paths[config_folder] = config_file_name
        return config_file_paths

    def directory_exists(self, *path_parts: str | Path) -> bool:
        """Check for the existence of a directory given the relative path.

        Example:
        if app.file_exists('local'):
             print "Distributed apps shouldn't have a 'local' directory"

        """
        directory_path = Path(self.app_dir, *path_parts)
        does_file_exist = os.path.isdir(directory_path)

        directory_exists = "directory_exists"
        log_output = (
            f"'{__file__}.{directory_exists} was called.'. Directory path being checked:'{directory_path}'."
            f" Does Directory Exist:{does_file_exist}"
        )
        logger.debug(log_output)
        return does_file_exist

    def some_files_exist(self, files: list[str | Path]) -> bool:
        """Takes an array of relative filenames and returns true if any file listed exists."""
        # TODO: tests needed
        for file in files:
            if self.file_exists(file):
                return True
        return False

    def some_directories_exist(self, directories: list[str | Path]) -> bool:
        """Takes an array of relative paths and returns true if any file listed exists."""
        for directory in directories:
            if self.directory_exists(directory):
                return True
        return False

    def all_files_exist(self, files: list[str | Path]) -> bool:
        """Takes an array of relative filenames and returns true if all listed files exist."""
        # TODO: tests needed
        for file in files:
            if not self.file_exists(file):
                return False
        return True

    def all_directories_exist(self, directories: list[str | Path]) -> bool:
        """Takes an array of relative paths and returns true if all listed directories exists."""
        # TODO: tests needed
        for directory in directories:
            if not self.directory_exists(directory):
                return False
        return True

    def search_for_patterns(
        self,
        patterns: list[str],
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        names: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: int | float = float("inf"),
    ) -> list[tuple[str, re.Match]]:
        """Takes a list of patterns and iterates through all files, running
        each of the patterns on each line of each of those files.

        Returns:
            A list of tuples- the first element is the file (with line
            number), the second is the match from the regular expression.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        names = names or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        matches = []
        all_excluded_types = [".pyc", ".pyo"]
        all_excluded_types.extend(excluded_types)  # never search these files

        files_iterator = self.iterate_files(
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            names=names,
            types=types,
            excluded_types=all_excluded_types,
            excluded_bases=excluded_bases,
            recurse_depth=recurse_depth,
            skip_compiled_binaries=True,
        )
        for dir_in_app, file_name, _ in files_iterator:
            relative_filepath = Path(dir_in_app, file_name)
            file_to_inspect = inspected_file.InspectedFile.factory(self.get_filename(dir_in_app, file_name))
            found_matches = file_to_inspect.search_for_patterns(patterns)
            matches_with_relative_path = []
            for fileref_output, file_match in found_matches:
                _, line_number = fileref_output.rsplit(":", 1)
                relative_file_ref_output = f"{relative_filepath}:{line_number}"
                matches_with_relative_path.append((relative_file_ref_output, file_match))
            matches.extend(matches_with_relative_path)

        return matches

    def search_for_pattern(
        self,
        pattern: str,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        names: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: int | float = float("inf"),
    ) -> list[tuple[str, re.Match]]:
        """Takes a pattern and iterates over matching files, testing each line.
        Same as search_for_patterns, but with a single pattern.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        names = names or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        return self.search_for_patterns(
            [pattern],
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            names=names,
            types=types,
            excluded_types=excluded_types,
            excluded_bases=excluded_bases,
            recurse_depth=recurse_depth,
        )

    def search_for_crossline_patterns(
        self,
        patterns: list[str],
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        cross_line: int = 10,
    ) -> list[tuple[str, re.Match]]:
        """Takes a list of patterns and iterates through all files, running
        each of the patterns on all lines those files.

        Returns:
            a list of tuples- the first element is the file (with line
            number), the second is the match from the regular expression.

        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        matches = []
        all_excluded_types = [".pyc", ".pyo"]
        all_excluded_types.extend(excluded_types)  # never search these files

        files_iterator = self.iterate_files(
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            types=types,
            excluded_types=all_excluded_types,
            excluded_bases=excluded_bases,
            skip_compiled_binaries=True,
        )
        for directory, filename, _ in files_iterator:
            relative_filepath = Path(directory, filename)
            file_to_inspect = inspected_file.InspectedFile.factory(Path(self.app_dir, directory, filename))
            found_matches = file_to_inspect.search_for_crossline_patterns(patterns=patterns, cross_line=cross_line)
            matches_with_relative_path = []
            for fileref_output, file_match in found_matches:
                _, line_number = fileref_output.rsplit(":", 1)
                relative_file_ref_output = f"{relative_filepath}:{line_number}"
                matches_with_relative_path.append((relative_file_ref_output, file_match))
            matches.extend(matches_with_relative_path)

        return matches

    def search_for_crossline_pattern(
        self,
        pattern: str,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        cross_line: int = 10,
    ) -> list[tuple[str, re.Match]]:
        """Takes a pattern and iterates over matching files, testing each line.
        Same as search_for_crossline_patterns, but with a single pattern.
        """
        excluded_dirs = excluded_dirs or []
        types = types or []
        excluded_types = excluded_types or []
        excluded_bases = excluded_bases or []
        return self.search_for_crossline_patterns(
            [pattern],
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            types=types,
            excluded_types=excluded_types,
            excluded_bases=excluded_bases,
            cross_line=cross_line,
        )

    def is_executable(self, filename: Path, is_full_path: bool = False) -> bool:
        """Checks to see if any of the executable bits are set on a file"""
        # TODO: tests needed
        path = Path(self.app_dir, filename) if not is_full_path else filename
        st = path.stat()
        return bool(st.st_mode & (stat.S_IXOTH | stat.S_IXUSR | stat.S_IXGRP))

    def is_text(self, filename: Path) -> bool:
        """Checks to see if the file is a text type via the 'file' command.
        Notice: This method should only be used in Unix environment
        """
        if filename in self.info_from_file:
            return bool(re.search(r".* text", self.info_from_file[filename], re.IGNORECASE))
        try:
            file_path = self.get_filename(filename)
            output = magic.from_file(str(file_path))
            return bool(re.search(r".* text", output, re.IGNORECASE))
        except Exception:
            # TODO: Self log error here.  Issues with hidden folders
            return False

    # ---------------------------------
    # "Domain" Objects
    # ---------------------------------
    def get_alert_actions(self) -> alert_actions.AlertActions:
        return alert_actions.AlertActions(self)

    def get_custom_commands(
        self,
        config: Union[configuration_file.ConfigurationProxy, configuration_file.MergedConfigurationProxy, None] = None,
    ) -> custom_commands.CustomCommands:
        """Return a CustomCommands instance optionally supporting class-based
        checks config ConfigurationProxy / MergedConfigurationProxy

        Args:
          config: a set of configurations to be checked. Defaults to None.

        Returns:
          An instance of CustomCommands for interacting with architecture-specific command files
          and associated conf settings

        """
        return custom_commands.CustomCommands(self, config)

    def get_custom_executable_files(
        self,
        config: Union[configuration_file.ConfigurationProxy, configuration_file.MergedConfigurationProxy, None] = None,
        local: bool = False,
    ) -> list[str]:
        """Retrieve custom command executable files

        Args:
          config: a set of configurations to be checked. Defaults to None.
          local: If True, include commands with `command.local` set to a true truthy value (local to the search head),
          otherwise return commands without `command.local` or set to a false truthy value. Defaults to False.

        Returns:
          `FileResource`s corresponding to desired command files

        """
        executable_files = []
        custom_commands = self.get_custom_commands(config)
        for command in custom_commands.get_commands():
            # If set to "true", specifies that the command should be run on the search head only.
            if local is False and command.local:
                continue
            elif local is True and not command.local:
                continue
            for execute_file in command.executable_files:
                if execute_file.is_path_pointer:
                    executable_files.extend(custom_commands.find_pointer_scripts(execute_file))
                else:
                    executable_files.append(execute_file.relative_path)
        return executable_files

    def get_non_distributed_files(self, config: configuration_file.ConfigurationProxy) -> list[Path]:
        if "distsearch" not in config:
            return []
        conf_file = config["distsearch"]
        if not conf_file.has_section("replicationBlacklist") and not conf_file.has_section("replicationDenylist"):
            return []

        denylist_files = set()
        regexes = []
        for section_name in ("replicationBlacklist", "replicationDenylist"):
            if not conf_file.has_section(section_name):
                continue
            section = conf_file.get_section(section_name)
            for _, regex in section.options.items():
                regexes.append(regex.value)

        for directory, filename, _ in self.iterate_files():
            file_path = Path(directory, filename)
            regex_file_path = os.path.join("apps", self.package.origin_package_name, file_path)

            for regex in regexes:
                try:
                    if re.match(rf"{regex}", regex_file_path):
                        denylist_files.add(file_path)
                except re.error as ex:
                    logger.warning(f"error={ex}")
                    continue

        return list(denylist_files)

    def get_transforms_executable_files(
        self, config: configuration_file.ConfigurationProxy | configuration_file.MergedConfigurationProxy
    ) -> list[Path]:
        """Retrieve a list of files from transforms.conf `external_cmd = <file> <args>` properties.

        Args:
          config: a set of configurations to be checked.

        Returns:
          List of file names as they appear in transforms.conf

        """
        if not "transforms" in config:
            return []
        conf_file = config["transforms"]
        external_commands = set()
        for section in conf_file.sections():
            if section.has_option("external_cmd"):
                external_commands.add(section.get_option("external_cmd").value)
        executable_files = []
        for external_command in external_commands:
            executable_files.append(external_command.strip().split(" ")[0])
        files = []
        for file_name in executable_files:
            relative_path = Path("bin", file_name)
            if self.file_exists(relative_path):
                files.append(relative_path)
        return files

    def get_custom_visualizations(self) -> custom_visualizations.CustomVisualizations:
        return custom_visualizations.CustomVisualizations(self)

    def get_modular_inputs(self) -> modular_inputs.ModularInputs:
        return modular_inputs.ModularInputs.factory(self)

    def get_rest_map(self, config: configuration_file.ConfigurationProxy) -> rest_map.RestMap:
        return rest_map.RestMap(self, config)

    def get_saved_searches(self, config: "ConfigurationProxyType") -> saved_searches.SavedSearches:
        return saved_searches.SavedSearches(self, config)

    # ---------------------------------
    # ConfFile Helper Definitions
    # ---------------------------------
    def app_conf(self, dir: str | Path = "default") -> app_configuration_file.AppConfigurationFile:
        return self.get_config(
            "app.conf",
            dir=dir,
            config_file=app_configuration_file.AppConfigurationFile(),
        )

    def authentication_conf(
        self, dir: str | Path = "default"
    ) -> authentication_configuration_file.AuthenticationConfigurationFile:
        return self.get_config(
            "authentication.conf",
            dir=dir,
            config_file=authentication_configuration_file.AuthenticationConfigurationFile(),
        )

    def authorize_conf(self, dir: str | Path = "default") -> authorize_configuration_file.AuthorizeConfigurationFile:
        return self.get_config(
            "authorize.conf",
            dir=dir,
            config_file=authorize_configuration_file.AuthorizeConfigurationFile(),
        )

    def indexes_conf(self, dir: str | Path = "default") -> indexes_configuration_file.IndexesConfigurationFile:
        return self.get_config(
            "indexes.conf",
            dir=dir,
            config_file=indexes_configuration_file.IndexesConfigurationFile(),
        )

    def inputs_conf(self, dir: str | Path = "default") -> inputs_configuration_file.InputsConfigurationFile:
        return self.get_config(
            "inputs.conf",
            dir=dir,
            config_file=inputs_configuration_file.InputsConfigurationFile(),
        )

    def outputs_conf(self, dir: str | Path = "default") -> outputs_configuration_file.OutputsConfigurationFile:
        return self.get_config(
            "outputs.conf",
            dir=dir,
            config_file=outputs_configuration_file.OutputsConfigurationFile(),
        )

    def props_conf(self, dir: str | Path = "default") -> props_configuration_file.PropsConfigurationFile:
        return self.get_config(
            "props.conf",
            dir=dir,
            config_file=props_configuration_file.PropsConfigurationFile(),
        )

    def web_conf(self, dir: str | Path = "default") -> web_configuration_file.WebConfigurationFile:
        return self.get_config(
            "web.conf",
            dir=dir,
            config_file=web_configuration_file.WebConfigurationFile(),
        )

    def server_conf(self, dir: str | Path = "default") -> outputs_configuration_file.OutputsConfigurationFile:
        return self.get_config(
            "server.conf",
            dir=dir,
            config_file=outputs_configuration_file.OutputsConfigurationFile(),
        )

    def eventtypes_conf(self, dir: str | Path = "default") -> outputs_configuration_file.OutputsConfigurationFile:
        return self.get_config(
            "eventtypes.conf",
            dir=dir,
            config_file=outputs_configuration_file.OutputsConfigurationFile(),
        )

    def telemetry_conf(self, dir: str | Path = "default") -> telemetry_configuration_file.TelemetryConfigurationFile:
        return self.get_config(
            "telemetry.conf",
            dir=dir,
            config_file=telemetry_configuration_file.TelemetryConfigurationFile(),
        )

    def collections_conf(
        self, dir: str | Path = "default"
    ) -> collections_configuration_file.CollectionsConfigurationFile:
        return self.get_config(
            "collections.conf",
            dir=dir,
            config_file=collections_configuration_file.CollectionsConfigurationFile(),
        )

    # ---------------------------------
    # SpecFile Helper Definitions
    # ---------------------------------
    @staticmethod
    def get_inputs_specification() -> inputs_specification_file.InputsSpecification:
        return inputs_specification_file.InputsSpecification()

    # ---------------------------------
    # File Resource Helper Definitions
    # ---------------------------------
    def app_icon(self) -> file_resource.FileResource:
        return file_resource.FileResource(Path(self.app_dir, "appserver", "static", "appIcon.png"))

    def setup_xml(self) -> file_resource.FileResource:
        return file_resource.FileResource(Path(self.app_dir, "default", "setup.xml"))

    def custom_setup_view_xml(self, custom_setup_xml_name: str) -> file_resource.FileResource:
        return file_resource.FileResource(
            Path(
                self.app_dir,
                "default",
                "data",
                "ui",
                "views",
                f"{custom_setup_xml_name}.xml",
            )
        )

    def _filter_by_trusted_libs(self, dir_in_app: Path, file: str, check_name: Optional[str] = None) -> bool:
        filepath = Path(self.app_dir, dir_in_app, file)
        try:
            # check read permission
            if os.access(filepath, os.F_OK) and os.access(filepath, os.R_OK):
                with open(filepath, "rb") as f:
                    return self._trusted_libs_manager.check_if_lib_is_trusted(check_name, lib=f.read())
        except Exception:
            logger.error("read file %s failed", filepath)
        return False

    def get_file_view(self, *paths: str | Path) -> file_view.FileView:
        """Returns a FileView mounted on a given subdirectory of the app directory

        Args:
          a list of path segments which are joined to form the FileView path

        Returns:
          a FileView looking at the given path

        """
        return file_view.FileView(self, Path(*paths) if paths else Path(""))

    @property
    def custom_conf_files(self) -> set[Path]:
        if self._custom_conf_files is None:
            self._custom_conf_files = self._get_custom_conf_files(["default", "local"])
        return self._custom_conf_files

    @property
    def user_custom_conf_files(self) -> set[Path]:
        if self._user_custom_conf_files is None:
            self._user_custom_conf_files = self._get_custom_conf_files(self.get_user_paths("local"))
        return self._user_custom_conf_files

    def _get_custom_conf_files(self, basedir: list[str | Path]) -> set[Path]:
        custom_confs = set()
        for relative_file_path, _ in self.get_filepaths_of_files(types=[".conf"], basedir=basedir):
            filename = relative_file_path.name
            if filename not in SPLUNK_DEFINED_CONFS:
                custom_confs.add(relative_file_path)
        return custom_confs

    @property
    def lookups(self) -> file_view.FileView:
        return self.get_file_view("lookups")

    @property
    def default_config(self) -> configuration_file.ConfigurationProxy:
        if self._default_config is None:
            self._default_config = configuration_file.ConfigurationProxy(self, "default")
        return self._default_config

    @property
    def default_file_view(self) -> file_view.FileView | None:
        if "default" in self.app_file_view:
            return self.app_file_view["default"]
        return None

    @property
    def local_config(self) -> configuration_file.ConfigurationProxy:
        if self._local_config is None:
            self._local_config = configuration_file.ConfigurationProxy(self, "local")
        return self._local_config

    @property
    def local_file_view(self) -> file_view.FileView | None:
        if "local" in self.app_file_view:
            return self.app_file_view["local"]
        return None

    @property
    def merged_config(self) -> configuration_file.MergedConfigurationProxy:
        if self._merged_config is None:
            return configuration_file.MergedConfigurationProxy(self.local_config, self.default_config)
        return self._merged_config

    @property
    def merged_file_view(self) -> file_view.MergedFileView:
        """
        Returns:
            A MergedFileView which returns files first from the `local` FileView, if `local` exists,
            then from the `default` FileView, if `default` exists.

        """
        views = []
        if self.local_file_view:
            views.append(self.local_file_view)
        if self.default_file_view:
            views.append(self.default_file_view)
        return file_view.MergedFileView(*views)

    @property
    def users(self) -> set[str]:
        """Returns a set of usernames compiled from the directories under users/."""
        return self._users

    @property
    def user_local_config(self) -> dict[str, configuration_file.ConfigurationProxy]:
        """Returns a ConfigurationProxy for each folder users/<username>/local/."""
        if self._user_configs is None:
            self._user_configs = {
                username: configuration_file.ConfigurationProxy(self, self.get_user_path(username, "local"))
                for username in self.users
            }
        return self._user_configs

    @property
    def user_merged_config(self) -> dict[str, configuration_file.MergedConfigurationProxy]:
        """Returns a MergedConfigurationProxy for each folder users/<username>/local/.
        The order of the configuration lookup is:
        1. users/<username>/local/
        2. local/
        3. default/
        """
        if self._merged_user_configs is None:
            self._merged_user_configs = {
                username: configuration_file.MergedConfigurationProxy(conf, self.local_config, self.default_config)
                for username, conf in self.user_local_config.items()
            }
        return self._merged_user_configs

    @property
    def user_local_file_view(self) -> dict[str, Optional[file_view.FileView]]:
        """Returns a FileView for each folder users/<username>/local/."""

        def get_file_view(username):
            path = self.get_user_path(username, "local")
            if path in self.app_file_view:
                return self.app_file_view[path]
            return None

        return {username: get_file_view(username) for username in self.users}

    @property
    def user_merged_file_view(self) -> dict[str, file_view.MergedFileView]:
        """Returns a MergedFileView for each folder users/<username>/local/.
        The order of the file lookup is:
        1. users/<username>/local/
        2. local/
        3. default/
        """
        views = []
        if self.local_file_view:
            views.append(self.local_file_view)
        if self.default_file_view:
            views.append(self.default_file_view)
        return {
            username: file_view.MergedFileView(fw, *views) if fw else file_view.MergedFileView(*views)
            for username, fw in self.user_local_file_view.items()
        }

    @staticmethod
    def get_user_path(username: str, *args: str | Path) -> Path:
        """Returns a path in users/<username>/ directory."""
        return Path("users", username, *args)

    def get_user_paths(self, *args: str | Path) -> list[Path]:
        """Returns a list of paths under each users/<username>/ directory."""
        return [App.get_user_path(username, *args) for username in self.users]
