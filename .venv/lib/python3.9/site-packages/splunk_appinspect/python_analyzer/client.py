from __future__ import annotations

import inspect
import logging
import os.path
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional, Union

from splunk_appinspect.python_analyzer import ast_analyzer, ast_info_store, file_dep_manager
from splunk_appinspect.python_analyzer.trustedlibs.utilities import get_hash_file

if TYPE_CHECKING:
    from splunk_appinspect.custom_types import DependencyDictType
    from splunk_appinspect.python_analyzer.ast_types import AstModule, AstVariable
    from splunk_appinspect.python_analyzer.trustedlibs.trusted_libs_manager import TrustedLibsManager
    from splunk_appinspect.python_modules_metadata.python_modules_metadata_store import PythonModulesMetadata


logger = logging.getLogger(__name__)


class Client:
    """One app contains one client."""

    def __init__(
        self,
        filepaths: Optional[list[Path]] = None,
        files_folder: Optional[Path] = None,
        modules_metadata: Optional["PythonModulesMetadata"] = None,
        trusted_libs_manager: Optional["TrustedLibsManager"] = None,
    ) -> None:
        # initialize some variables
        self._dependency_graphs = {}
        # build graph
        assert filepaths is not None or files_folder is not None
        self.set_prior_known_filepath(files_folder)
        libs = None
        if files_folder:
            # Hardcode bin/lib folder as always searching paths,
            # as these two are Splunk default lib folder.
            libs = [
                Path(files_folder, "bin"),
                Path(files_folder, "lib"),
            ]
        self.file_dep_manager: file_dep_manager.FileDepManager = file_dep_manager.FileDepManager(
            files_folder, libs=libs
        )
        self.ast_info_store: ast_info_store.AstInfoStore = ast_info_store.AstInfoStore(libs=libs)
        self.modules_metadata: Optional["PythonModulesMetadata"] = modules_metadata
        self.trusted_libs: Optional["TrustedLibsManager"] = trusted_libs_manager

        logger.debug("DepManager and Trustedlibs initialization succeeded")

        if files_folder:
            self.file_dep_manager.add_folder(files_folder)
        if filepaths:
            for filepath in filepaths:
                self.file_dep_manager.add_file(filepath)
        # populate graph
        self._process_files()

    @property
    def has_circular_dependency(self) -> bool:
        return self.file_dep_manager.has_circular_dependency

    def get_circular_dependency(self) -> list[list[Path]]:
        relative_filepath_comps = []
        for abs_filepath_comp in self.file_dep_manager.get_circular_dependency():
            if not abs_filepath_comp:
                continue
            relative_filepath_comp = []
            for abs_filepath in abs_filepath_comp:
                relative_filepath_comp.append(self._relativize_filepath(abs_filepath))
            relative_filepath_comps.append(relative_filepath_comp)
        return relative_filepath_comps

    def get_circular_dependency_loops(self) -> dict[tuple[Path, ...]]:
        relative_filepath_comps = []
        for abs_filepath_comp_loops in self.file_dep_manager.find_circular_dependency_loops():
            relative_filepath_comp_loops = []
            for abs_filepath_loop in abs_filepath_comp_loops:
                relative_filepath_loop = map(lambda e: (self._relativize_filepath(e[0]), e[1]), abs_filepath_loop)
                relative_filepath_comp_loops.append(relative_filepath_loop)
            relative_filepath_comps.append(relative_filepath_comp_loops)
        sccs = self.get_circular_dependency()
        scc_loops_map = {}
        for idx, scc in enumerate(sccs):
            key: tuple[Path, ...] = tuple(scc)
            scc_loops_map[key] = relative_filepath_comps[idx]
        return scc_loops_map

    def get_ast_info(self, filepath: Path) -> ast_analyzer.AstAnalyzer:
        """
        Get corresponding AST analyzer.

        Args:
            filepath: If provided, return the ast analyzer.

        """
        abs_filepath = self._absolutize_filepath(filepath)
        assert abs_filepath in self.ast_info_store, "Provide valid filepath."
        return self.ast_info_store[abs_filepath]

    def get_all_ast_infos(
        self, check_name: Optional[str] = None
    ) -> Generator[tuple[Path, ast_analyzer.AstAnalyzer], Any, None]:
        return self._trusted_libs_filter(set(self.file_dep_manager.iter_files()), check_name=check_name)

    def get_syntax_error_files(self, check_name: Optional[str] = None) -> set[Path]:
        return set(
            map(
                lambda result: result[0],
                self._trusted_libs_filter(
                    set(self.file_dep_manager.get_syntax_error_files()),
                    check_name=check_name,
                ),
            )
        )

    def get_null_byte_error_files(self, check_name: Optional[str] = None) -> set[Path]:
        return set(
            map(
                lambda result: result[0],
                self._trusted_libs_filter(
                    set(self.file_dep_manager.get_null_byte_error_files()),
                    check_name=check_name,
                ),
            )
        )

    def get_other_exception_files(self) -> set[Path]:
        return set(
            map(
                self._relativize_filepath,
                self.file_dep_manager.get_other_exception_files(),
            )
        )

    def get_hidden_python_files(self) -> set[Path]:
        return set(
            map(
                self._relativize_filepath,
                self.file_dep_manager.get_hidden_python_files(),
            )
        )

    def get_dependences(self, filepath: Path) -> "DependencyDictType":
        """
        Returns:
            python file's dependency tree eg:
                   c
                  /
                 b
                /
               a
            so the result for `a` should be like::
                {
                    'parents': [
                        {
                            'parents': [
                                {
                                    'parents': [],
                                    'filepath': c filepath
                                }
                            ],
                            'filepath': b filepath
                        }
                    ],
                    'filepath': a filepath
                }
        """
        abs_filepath = self._absolutize_filepath(filepath)
        return self.file_dep_manager.get_dependencies(abs_filepath)

    def load_modules(self, import_chain: str) -> list["AstModule"]:
        pkg_path, obj_name = self.ast_info_store.get_pkg_path_and_obj_name(import_chain)
        if (pkg_path is None) or (pkg_path not in self.ast_info_store):
            if self.modules_metadata is None:
                return []
            obj_metadata_list = self.modules_metadata.query_namespace(import_chain)
            modules_list = []
            for func_metadata in obj_metadata_list:
                modules_list.append(func_metadata.instantiate())
            return modules_list
        if obj_name == "*":
            analyzer = self.ast_info_store[pkg_path]
            modules_list = []
            for exposed_mod in analyzer.exposed_module_set:
                if exposed_mod in analyzer.module.global_map:
                    modules_list.append(analyzer.module.global_map[exposed_mod])
                else:
                    # Very edge case
                    modules_list += self.load_modules(import_chain[:-2] + "." + exposed_mod)
            return modules_list

        if obj_name is None:
            analyzer = self.ast_info_store[pkg_path]
            return [analyzer.module]

        analyzer = self.ast_info_store[pkg_path]
        if obj_name in analyzer.module.global_map:
            return [analyzer.module.global_map[obj_name]]
        return []

    def set_prior_known_filepath(self, folder_path: Optional[Path | str]) -> None:
        self.prior_known_filepath = Path(folder_path)

    def _relativize_filepath(self, abs_filepath: Path) -> Path:
        abs_filepath_str = str(abs_filepath)
        prior_known_filepath = str(self.prior_known_filepath)
        if self.prior_known_filepath and abs_filepath_str.startswith(prior_known_filepath):
            return Path(abs_filepath_str[len(prior_known_filepath) + 1 :])

        return abs_filepath

    def _absolutize_filepath(self, relative_filepath: Path) -> Path:
        # FIXME: change to relative_filepath.is_relative_to(self.prior_known_filepath) after upgrading to python 3.9
        relative_filepath_str = str(relative_filepath)
        if self.prior_known_filepath and not relative_filepath_str.startswith(str(self.prior_known_filepath)):
            return Path(self.prior_known_filepath, relative_filepath_str)

        return relative_filepath

    def _process_files(self) -> None:
        """
        Traverse dependency graph in topological order, parse AST-analyzer for all files.

        If cycle is detected, this function will degrade to for-loop implementation like::
            for filepath in filepaths:
                ast_analyzer = AstAnalyzer(filepath)

        """
        logger.debug("start file or folder processing")
        for filepath in self.file_dep_manager.iter_files():
            logger.debug("start `%s` processing", filepath)
            filepath_str = str(filepath)
            self.ast_info_store.set_pointer(filepath)
            self.ast_info_store[filepath] = ast_analyzer.AstAnalyzer(python_file_path=filepath, module_manager=self)

            # special process for 2to3 backup files and preprocessed files
            if os.path.exists(filepath_str + ".raw"):
                self.ast_info_store[filepath].content_hash = get_hash_file(open(filepath_str + ".raw", "rb").read())
            elif os.path.exists(filepath_str + ".bak"):
                self.ast_info_store[filepath].content_hash = get_hash_file(open(filepath_str + ".bak", "rb").read())

            logger.debug("`%s` process succeeded", filepath)

        # remove all .bak and .raw files
        for filepath in self.file_dep_manager.iter_all_app_python_files():
            filepath_str = str(filepath)
            if os.path.exists(filepath_str + ".bak"):
                os.remove(filepath_str + ".bak")
            if os.path.exists(filepath_str + ".raw"):
                os.remove(filepath_str + ".raw")

    def _trusted_libs_filter(
        self, filepaths: set[Path], check_name: Optional[str] = None
    ) -> Generator[tuple[Path, ast_analyzer.AstAnalyzer], Any, None]:
        if check_name is None:
            frame = inspect.currentframe().f_back
            while frame:
                name = frame.f_code.co_name
                if name.startswith("check_"):
                    check_name = name
                    break
                frame = frame.f_back
        assert check_name is not None and check_name.startswith(
            "check_"
        ), f"Appropriate check name should be provided to trustedlib, {check_name} is given"

        for filepath in filepaths:
            relative_path = self._relativize_filepath(filepath)
            # if it is a well-formed python file
            if filepath in self.ast_info_store:
                filter_result = self.trusted_libs.check_if_lib_is_trusted(
                    check_name, content_hash=self.ast_info_store[filepath].content_hash
                )
            else:
                # otherwise we need to read bytes from python file
                with open(filepath, "rb") as f:
                    filter_result = self.trusted_libs.check_if_lib_is_trusted(check_name, lib=f.read())
            if not filter_result:
                logger.debug("get ast info for check: `%s`, file: `%s`", check_name, filepath)
                if filepath in self.ast_info_store:
                    yield relative_path, self.ast_info_store[filepath]
                else:
                    yield relative_path, None
            else:
                logger.debug("`%s` filtered by trustedlib", filepath)
