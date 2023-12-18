"""
Splunk App python file dependency manager module
"""
from __future__ import annotations

import ast
import itertools
import logging
import multiprocessing
import os
import platform
import shutil
from lib2to3.main import main as exec_two_to_three
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional

import magic

from splunk_appinspect.python_analyzer import ast_types, utilities

if TYPE_CHECKING:
    from splunk_appinspect.custom_types import DependencyDictType, T

__all__ = ["FileDepManager"]

logger = logging.getLogger(__name__)


class FileDepManager:
    """
    A class managing the import dependencies between python files within a root directory.

    Attributes:
        restriction_area: The restriction area for analyzing dependencies. Any dependencies that involves paths
            outside the restriction area will be dropped.
        _file_pool: The filepath -> fileNode dictionary.

    """

    def __init__(self, restriction_area: Optional[Path] = None, libs: Optional[list[Path | str]] = None) -> None:
        """
        Args:
            libs: The directories that the dep manager will always look for python modules/packages if ones couldn't
                be found based on the path of the file that imports them.
            restriction_area: The restriction area for analyzing dependencies. Any dependencies that involves paths
                outside the restriction area will be dropped.

        """
        self.restriction_area: Optional[Path] = Path(os.path.abspath(restriction_area)) if restriction_area else None
        self.libs: Optional[list[Path | str]] = libs
        self._file_pool: dict[Path, ast_types.FileNode] = {}
        self._user_friendly_dependency_graphs: DependencyDictType = {}
        self._circular_dependency: Optional[list[list[ast_types.FileNode]]] = None
        self._syntax_error_file: set[Path] = set()
        self._null_byte_error_file: set[Path] = set()
        self._other_exception_file: set[Path] = set()
        self._hidden_python_file: set[Path] = set()
        self._python_files_in_circular_dependency: set[ast_types.FileNode] = set()

    def flush(self) -> None:
        """clear all stored data"""
        self._file_pool.clear()
        self._user_friendly_dependency_graphs.clear()
        self._circular_dependency = None
        self._syntax_error_file.clear()
        self._null_byte_error_file.clear()
        self._other_exception_file.clear()
        self._hidden_python_file.clear()
        self._python_files_in_circular_dependency.clear()

    @property
    def has_circular_dependency(self) -> bool:
        return len(self.get_circular_dependency()) != 0

    def get_circular_dependency(self) -> list[list[str]]:
        if self._circular_dependency is None:
            self._populate_circular_dependency()
        translation = []
        for component in self._circular_dependency:
            tmp = list(map(lambda e: e.filepath, component))
            translation.append(tmp)
        return translation

    def find_circular_dependency_loops(self) -> list[list[list[tuple[str, ast_types.FileNode]]]]:
        def add_line_number(loop: tuple[str]) -> list[tuple[str, Optional[int]]]:
            loop_with_line_number = []
            parent_filenode = self._file_pool[loop[-1]]
            parent_stamp = self._file_pool[loop[0]].parent_stamps[parent_filenode]
            loop_with_line_number.append((loop[0], parent_stamp))
            for i in range(1, len(loop)):
                parent_filenode = self._file_pool[loop[i - 1]]
                parent_stamp = self._file_pool[loop[i]].parent_stamps[parent_filenode]
                loop_with_line_number.append((loop[i], parent_stamp))
            return loop_with_line_number

        if self._circular_dependency is None:
            self._populate_circular_dependency()
        loops_collection = []
        for component in self._circular_dependency:
            if len(component) > 50:
                # Skip computing loops for huge components.
                # As this will consume too much memory.
                loops_collection.append([])
                continue
            graph = _build_graph_from_scc(component)
            stack = []
            loops = set()
            for node in graph.values():
                loop = ast_types.Stack()
                stack.append((node, loop.append(node.id)))
                while stack:
                    cur_node, loop = stack.pop()
                    for next_node in cur_node.neighbors:
                        if not loop.empty and loop.list[0] == next_node.id:
                            loop_alligned = _allign_loop(loop.list)
                            loop_with_line_number = add_line_number(loop_alligned)
                            loops.add(tuple(loop_with_line_number))
                        elif loop.has(next_node.id):
                            continue
                        else:
                            new_loop = ast_types.Stack()
                            new_loop.copy(loop).append(next_node.id)
                            stack.append((next_node, new_loop))
            loops_collection.append([list(tup) for tup in loops])
        return loops_collection

    def __getitem__(self, file_path: Path) -> str | "DependencyDictType":
        return self.get_dependencies(file_path)

    def get_dependencies(self, filepath: Path) -> "DependencyDictType":
        if filepath in self._user_friendly_dependency_graphs:
            return self._user_friendly_dependency_graphs[filepath]
        assert filepath in self._file_pool, "Please provide valid filepath."
        # TODO assert not self.has_circular_dependency, "The graph has circular dependency."
        dependency_tree = {}
        self._user_friendly_dependency_graphs[filepath] = dependency_tree
        dependency_tree["filepath"] = filepath
        dependency_tree["parents"]: list["DependencyDictType"] = []
        for parent in self._file_pool[filepath].iter_parent():
            dependency_tree["parents"].append(self.get_dependencies(parent.filepath))
        return dependency_tree

    def iter_files(self) -> itertools.chain:
        return itertools.chain(
            self.iter_circular_dependency_files(),
            self.iter_non_circular_dependency_files(),
        )

    def iter_all_app_python_files(self) -> Generator[Path, Any, None]:
        for file_path in self._file_pool:
            yield file_path

    def get_syntax_error_files(self) -> set[Path]:
        return self._syntax_error_file

    def get_null_byte_error_files(self) -> set[Path]:
        return self._null_byte_error_file

    def get_other_exception_files(self) -> set[Path]:
        return self._other_exception_file

    def get_hidden_python_files(self) -> set[Path]:
        return self._hidden_python_file

    def iter_circular_dependency_files(self) -> Generator[Path, Any, None]:
        for scc in self.get_circular_dependency():
            for filepath in scc:
                yield filepath

    def iter_non_circular_dependency_files(self) -> Generator[Path, Any, None]:
        """
        Assume the file_pool is [a.py, b.py, c.py, d.py, e.py],
        whereas we have the following dependencies:

                 a.py        d.py      e.py
                /   \       /
               /     \     /
            b.py       c.py

                The lower depend on the upper

        The iterating order would be [a.py, b.py, d.py, c.py, e.py].
        Make sure to visit all its parents first before visit a node.
        """
        stack = []
        changeable_in_degree = {}
        # initialize in degree with default value
        for _, file_node in iter(self._file_pool.items()):
            changeable_in_degree[file_node] = file_node.in_degree
        # remove circular nodes' out edges
        for _, file_node in iter(self._file_pool.items()):
            if file_node in self._python_files_in_circular_dependency:
                for child_node in file_node.iter_child():
                    changeable_in_degree[child_node] -= 1
        # start topological sort
        for _, file_node in iter(self._file_pool.items()):
            if changeable_in_degree[file_node] == 0 and (file_node not in self._python_files_in_circular_dependency):
                stack.append(file_node)
        while stack:
            cur_file_node = stack.pop()
            for child_node in cur_file_node.iter_child():
                changeable_in_degree[child_node] -= 1
                if changeable_in_degree[child_node] == 0 and (
                    child_node not in self._python_files_in_circular_dependency
                ):
                    stack.append(child_node)
            yield cur_file_node.filepath

    def _populate_circular_dependency(self) -> None:
        id_idx = [0]
        stack = ast_types.Stack()
        visited = set()
        self._circular_dependency = []

        def dfs(cur_node: ast_types.FileNode) -> None:
            cur_node.id = id_idx[0]
            cur_node.low_link = id_idx[0]
            id_idx[0] += 1
            visited.add(cur_node)
            stack.append(cur_node)
            for child_node in cur_node.iter_child():
                if child_node not in visited:
                    dfs(child_node)
                    cur_node.low_link = min(child_node.low_link, cur_node.low_link)
                elif stack.has(child_node):
                    cur_node.low_link = min(child_node.id, cur_node.low_link)
            if cur_node.id == cur_node.low_link:
                cur_scc = []
                while not stack.empty:
                    tmp_node = stack.pop()
                    cur_scc.append(tmp_node)
                    if tmp_node == cur_node:
                        break
                cur_scc.reverse()
                if len(cur_scc) > 1:
                    self._circular_dependency.append(cur_scc)
                    self._python_files_in_circular_dependency |= set(cur_scc)

        for _, file_node in iter(self._file_pool.items()):
            if file_node not in visited:
                dfs(file_node)

    def add_file(self, filepath: Path | str) -> Optional[ast_types.FileNode]:
        """A file tree would be established based on the file's dependencies."""
        filepath = Path(os.path.abspath(filepath))
        if not os.path.isfile(filepath):
            raise Exception(f"{filepath} not found or isn't file")
        if filepath in self._file_pool:
            return self._file_pool[filepath]

        try:
            deps = utilities.find_imports(filepath, self.libs)
        except SyntaxError:
            # try to run 2to3 in python3 interpreter
            try:
                self._preprocess_file(filepath)
                if (
                    not eval(os.getenv("APPINSPECT_DISABLE_2TO3_CONCURRENCY", "False"))
                    and multiprocessing.cpu_count() > 1
                    and platform.system() != "Windows"
                ):
                    exec_two_to_three(
                        fixer_pkg="lib2to3.fixes",
                        args=["-w", str(filepath), "--no-diffs", "-j", "2"],
                    )
                else:
                    exec_two_to_three(
                        fixer_pkg="lib2to3.fixes",
                        args=["-w", str(filepath), "--no-diffs"],
                    )
                # retry find_imports again
                deps = utilities.find_imports(filepath, self.libs)
            except Exception:
                self._syntax_error_file.add(filepath)
                return None
        except (TypeError, ValueError):
            # TypeError in python2, ValueError in python3
            self._null_byte_error_file.add(filepath)
            return None
        except Exception:
            self._other_exception_file.add(filepath)
            return None
        # Only create new file node if the file is syntax correct.
        file_node = ast_types.FileNode(filepath)
        self._file_pool[filepath] = file_node
        for _, _, _, pkg_path, line_number in deps:
            if (
                not pkg_path
                or pkg_path.suffix != ".py"
                # FIXME: change to pkg_path.is_relative_to(self.restriction_area) after upgrading to python 3.9
                or (self.restriction_area and not str(pkg_path).startswith(str(self.restriction_area)))
            ):
                continue
            par_node = self.add_file(pkg_path)
            if par_node is not None and (filepath != pkg_path):
                file_node.add_parent(par_node, stamp=line_number)
        return file_node

    def add_folder(self, folder_path: Path | str) -> int:
        counter = 0
        folder_path = Path(os.path.abspath(folder_path))
        for root, _, files in os.walk(
            folder_path,
            topdown=False,
            onerror=lambda error: logger.warning("Walk App folder failed , `%s`", error.strerror),
        ):
            for file_name in files:
                file_path = Path(root, file_name)
                if file_name.endswith(".py"):
                    counter += 1
                    self.add_file(file_path)
                # temporary files, ignore them
                elif file_name.endswith((".py.bak", ".py.raw")):
                    continue
                else:
                    # check if it is hidden python file
                    window_filter_exts = [".conf"]
                    is_windows = platform.system() == "Windows"
                    mime_type = magic.from_file(str(file_path), mime=True).lower()
                    if (not is_windows and (mime_type == "text/x-python" or mime_type == "text/x-script.python")) or (
                        is_windows
                        and (
                            not any(
                                map(
                                    lambda ext: file_path.suffix == ext,
                                    window_filter_exts,
                                )
                            )
                        )
                    ):
                        try:
                            ast.parse(open(file_path, mode="rb").read())
                            counter += 1
                            self.add_file(file_path)
                        except Exception:
                            # try 2to3 when py version is three
                            try:
                                self._preprocess_file(file_path)
                                if (
                                    not eval(
                                        os.getenv(
                                            "APPINSPECT_DISABLE_2TO3_CONCURRENCY",
                                            "False",
                                        )
                                    )
                                    and multiprocessing.cpu_count() > 1
                                    and platform.system() != "Windows"
                                ):
                                    exec_two_to_three(
                                        fixer_pkg="lib2to3.fixes",
                                        args=[
                                            "-w",
                                            str(file_path),
                                            "--no-diffs",
                                            "-j",
                                            "2",
                                        ],
                                    )
                                else:
                                    exec_two_to_three(
                                        fixer_pkg="lib2to3.fixes",
                                        args=["-w", str(file_path), "--no-diffs"],
                                    )

                                ast.parse(open(file_path, mode="rb").read())
                                counter += 1
                                self.add_file(file_path)
                            except Exception:
                                # 2to3 parser and python3 parser are more stricter
                                # stored in syntax error file to guarantee we won't leave it out
                                if file_path.suffix == ".py":
                                    self._syntax_error_file.add(file_path)
                                else:
                                    self._hidden_python_file.add(file_path)

        self._populate_circular_dependency()
        return counter

    @staticmethod
    def _preprocess_file(file_path: Path) -> None:
        lines = []
        with open(file_path, "rb") as fr:
            for line in fr.readlines():
                comps = line.split(b"\t")
                if len(comps) == 1:
                    lines.append(line)
                else:
                    converted_comps = []
                    for comp in comps[0:-1]:
                        offset = (1 + len(comp)) % 8
                        offset = (8 - offset) if offset else offset
                        converted_comps.append(comp + b" " + b" " * offset)

                    lines.append(b"".join(converted_comps) + comps[-1])

        shutil.copy(file_path, file_path.with_suffix(".raw"))

        with open(file_path, "wb") as fw:
            fw.writelines(lines)


class _Node:
    def __init__(self, id: str) -> None:
        self.id: str = id
        self.neighbors: list[_Node] = []

    def add_neighbor(self, target: _Node) -> None:
        self.neighbors.append(target)


def _build_graph_from_scc(scc: list[ast_types.FileNode]) -> dict[str, _Node]:
    graph = {}
    for filenode in scc:
        if filenode.filepath in graph:
            avatar = graph[filenode.filepath]
        else:
            avatar = _Node(filenode.filepath)
            graph[filenode.filepath] = avatar
        for next_filenode in scc:
            if filenode is next_filenode:
                continue
            if filenode.has_child(next_filenode):
                if next_filenode.filepath in graph:
                    avatar.add_neighbor(graph[next_filenode.filepath])
                else:
                    graph[next_filenode.filepath] = _Node(next_filenode.filepath)
                    avatar.add_neighbor(graph[next_filenode.filepath])
    return graph


def _shift_loop(loop: list[T], target: T) -> list[T]:
    for idx, e in enumerate(loop):
        if target is e:
            return loop[idx:] + loop[:idx]
    return loop


def _allign_loop(loop: list[T]) -> tuple[T, ...]:
    starter = sorted(loop)[0]
    return tuple(_shift_loop(loop, starter))
