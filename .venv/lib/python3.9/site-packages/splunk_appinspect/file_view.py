# -*- coding: utf-8 -*-
"""Interfaces for accessing files in a consistent manner

The ``FileView`` class provides an interface for interacting with an app or
one of its subdirectories at the file level. The ``MergedFileView`` class
provides the same interface, but will merge two subdirectories in order of
precedence. ``MergedFileView`` can be used, for example, to interact with
the default/data and local/data directories together, the way Splunk would
apply merging precedence.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Optional, Union

if TYPE_CHECKING:
    from splunk_appinspect.app import App


class FileView:
    """
    View of a single app or one of its subdirectories.

    Attributes:
        app the app for which a view is provided.
        basedir: a subdirectory within the app to limit scope.

    """

    def __init__(self, app: "App", basedir: Optional[str | Path] = None) -> None:
        self.app: "App" = app
        self.basedir: Path = Path(basedir) if basedir else Path("")

    @property
    def app_dir(self) -> Path | "App":
        """The root directory of the underlying app."""
        if hasattr(self.app, "app_dir"):
            return self.app.app_dir
        return self.app

    def __getitem__(self, name: str | Path) -> FileView | Path:
        path_in_app = Path(self.basedir, name)
        if name not in self:
            raise KeyError(name)
        if os.path.isdir(self.app_dir.joinpath(path_in_app)):
            return FileView(self.app, path_in_app)
        return path_in_app

    def has_matching_files(
        self,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: float | int = float("inf"),
        base_depth: Optional[int] = None,
    ) -> bool:
        """
        Checks for files in the app / directory, optionally filtered by file extension.

        Example::

            if not file_view.has_matching_files(types=['.gif', '.jpg']):
                reporter.not_applicable(...)

        See FileView.iterate_files for param meaning.

        """
        matching_files = self.iterate_files(
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            types=types,
            excluded_types=excluded_types,
            excluded_bases=excluded_bases,
            recurse_depth=recurse_depth,
            base_depth=base_depth,
        )
        if next(matching_files, None):
            return False
        return True

    def iterate_files(
        self,
        basedir: Union[str, Path] = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: float | int = float("inf"),
        base_depth: Optional[int] = None,
    ) -> Generator[tuple[Path, str, str], Any, None]:
        """
        Iterates through each of the files in the app, optionally filtered by file extension.

        Example::

            for file in file_view.iterate_files(types=['.gif', '.jpg']):
                pass

        This should be considered to only be a top-down traversal/iteration. This is because the filtering of
        directories, and logic used to track depth are based on the `os.walk` functionality using the argument of
        `topdown=True` as a default value. If bottom up traversal is desired then a separate function will need
        to be created.

        Args:
            basedir: The directory or list of directories to start in.
            excluded_dirs: These are directories to exclude when iterating. Exclusion is done by directory name
                matching only. This means if you exclude the directory 'examples' it would exclude both `examples/`
                and `default/examples`, as well as any path containing a directory called `examples`.
            types: An array of types that the filename should match.
            excluded_types: An array of file extensions that should be skipped.
            excluded_bases: An array of file names (without extensions) that should be skipped.
            recurse_depth: This is used to indicate how deep you want traversal to go. 0 means do no recurse, but
                return the files at the directory specified.
            base_depth: For recursion, indicates the starting depth.

        """

        if not os.path.exists(os.path.join(self.app_dir, self.basedir, basedir)):
            return

        # -1 is added for compatibility with previous os.path implementation
        base_depth = base_depth or len(self.basedir.parts)

        subviews = []

        for file in Path(self.app_dir, self.basedir, basedir).iterdir():
            path_in_app = file.relative_to(self.app_dir)
            current_depth = len(path_in_app.parts) - base_depth
            if os.path.isdir(file):
                if excluded_dirs and file.name in excluded_dirs:
                    continue
                if current_depth > recurse_depth:
                    continue
                subview = FileView(self.app, path_in_app)
                subviews.append(subview)
            else:
                filebase, ext = file.stem, file.suffix
                if types and ext not in types:
                    continue
                if excluded_types and ext != "" and ext in excluded_types:
                    continue
                if excluded_bases and filebase.lower() in excluded_bases:
                    continue
                yield path_in_app.parent, file.name, ext

        for subview in subviews:
            yield from subview.iterate_files(
                basedir="",
                excluded_dirs=excluded_dirs,
                types=types,
                excluded_types=excluded_types,
                excluded_bases=excluded_bases,
                recurse_depth=recurse_depth,
                base_depth=base_depth,
            )

    def get_filepaths_of_files(
        self,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        filenames: None = None,
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
            filename = Path(file).stem
            check_filenames = len(filenames) > 0

            filename_is_in_filenames = filename not in filenames
            if check_filenames and filename_is_in_filenames:
                pass
            else:
                yield current_file_relative_path, current_file_full_path

    def __contains__(self, other: str | Path) -> bool:
        return os.path.exists(os.path.join(self.app_dir, self.basedir, other))


class MergedFileView:
    """
    Merged view of one-or-more directories within an app.

    Attributes:
        views: FileView instances in order of precedence.

    """

    def __init__(self, *views: FileView) -> None:
        self.views: tuple[FileView, ...] = views

    @property
    def app_dir(self) -> Union[None, Path, "App"]:
        """
        Returns:
            The root directory of the underlying app, based on the first view in precedence.
            Returns None if there are no views.

        """
        if not self.views:
            return None
        return self.views[0].app_dir

    def __getitem__(self, name: str) -> "MergedFileView":
        views = [view[name] for view in self.views if name in view]
        if len(views) > 0:
            return MergedFileView(*views)
        raise KeyError(name)

    def has_matching_files(
        self,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: float | int = float("inf"),
    ) -> bool:
        """See FileView.has_matching_files."""
        matching_files = self.iterate_files(
            basedir=basedir,
            excluded_dirs=excluded_dirs,
            types=types,
            excluded_types=excluded_types,
            excluded_bases=excluded_bases,
            recurse_depth=recurse_depth,
        )
        if next(matching_files, None):
            return False
        return True

    def iterate_files(
        self,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        types: Optional[list[str]] = None,
        excluded_types: Optional[list[str]] = None,
        excluded_bases: Optional[list[str]] = None,
        recurse_depth: float | int = float("inf"),
    ) -> Generator[tuple[Path, str, str], Any, None]:
        """See FileView.iterate_files."""
        seen = set()

        for view in self.views:
            for path, filename, ext in view.iterate_files(
                basedir=basedir,
                excluded_dirs=excluded_dirs,
                types=types,
                excluded_types=excluded_types,
                excluded_bases=excluded_bases,
                recurse_depth=recurse_depth,
            ):
                relpath = Path(path, filename).relative_to(view.basedir)
                if relpath in seen:
                    continue
                seen.add(relpath)
                yield path, filename, ext

    def get_filepaths_of_files(
        self,
        basedir: str | Path = "",
        excluded_dirs: Optional[list[str]] = None,
        filenames: None = None,
        types: Optional[list[str]] = None,
    ) -> Generator[tuple[Path, Path], Any, None]:
        """See FileView.get_filepaths_of_files."""
        seen = set()

        for view in self.views:
            for relative_path, full_path in view.get_filepaths_of_files(
                basedir=basedir,
                excluded_dirs=excluded_dirs,
                filenames=filenames,
                types=types,
            ):
                relpath = relative_path.relative_to(view.basedir)
                if relpath in seen:
                    continue
                seen.add(relpath)
                yield relative_path, full_path

    def __contains__(self, other: str | Path) -> bool:
        return any([other in view for view in self.views])
