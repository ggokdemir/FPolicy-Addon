"""TarSec Module for Tar Safety."""
from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path
from typing import Generator


def resolve_path(path: Path) -> Path:
    return path.absolute().resolve()


def is_bad_path(path: str, base: Path) -> bool:
    path = Path(path)
    full_path = resolve_path(base / path)
    if len(base.parts) > len(full_path.parts):
        return True
    for i in range(len(base.parts)):
        if full_path.parts[i] != base.parts[i]:
            return True
    return False


def is_bad_link(info: tarfile.TarInfo, base: Path) -> bool:
    # symlinks resolve relative to their parent directory, so we need to take
    # both the symlink value and its path into account
    parent_dir = resolve_path(base / Path(info.name).parent)
    return is_bad_path(info.linkname, parent_dir)


class TarSec:
    """Tar-file Security checker."""

    def __init__(
        self,
        *,
        filename: str = None,
        contents: io.BytesIO = None,
        mode: str = "r:*",
        max_mb: int = 1024,
        file_limit: int = 10_000_000,
    ):
        """
        Create a TarSec object used check attack vectors in Tar files.

        :param filename: The name of the file.
        :param mode: The mode of the file (defaults to 'r:*'
                [read & determine compression])
        :param contents: A BytesIO stream of data to be treated as a tarball.
        :param max_mb: Maximum aggregate contents size of archive.
        :param file_limit: Maximum number of files allowed in archive.
        :raises ValueError: If the `contents` cannot be read or neither
                `filename` or `contents` are specified.
        :raises FileNotFoundError: If a filename was specified
                and could not be found.
        """
        self._filename = filename
        self._mode = mode
        self._max_mb = max_mb
        self._file_limit = file_limit
        self._cwd = Path.cwd()
        self._file_contents = None
        self._reason = None

        if not (filename or contents):
            raise ValueError("Expected `filename` or `contents` specified.")

        #  What's happening here is that if we get a file, we read in the
        #  contents to _file_contents and close the file. If we get a
        #  BytesIO stream, we similarly write that to self._file_contents.
        if contents:
            if not isinstance(contents, io.BytesIO):
                raise ValueError("`contents` must be of type `BytesIO`")
            self._file_contents = tarfile.open(fileobj=contents, mode=self._mode)
        else:
            with open(self._filename, mode="rb") as f:
                b = f.read()
            self._file_contents = tarfile.open(fileobj=io.BytesIO(b), mode=self._mode)

    @property
    def reason(self) -> str:
        """Return reason for failure."""
        return self._reason

    def yield_safe_members(
        self, members: list[tarfile.TarInfo], path: str
    ) -> Generator[tarfile.TarInfo, None, None]:
        """Yield safe tarinfo members.

        Only yields tarinfo members that don't write outside the provided path.
        Breaks if an unsafe member is found.
        """
        base = resolve_path(Path(path))
        for info in members:
            # no directory paths that point outside
            if is_bad_path(info.name, base):
                self._reason = f"Directory escape detected. file={info.name}"
                break

            # no symlinks or hardlinks that point outside
            elif (info.issym() or info.islnk()) and is_bad_link(info, base):
                self._reason = f"Contains sym or hard links. file = {info.name}"
                break

            # no character or block devices
            # elif info.ischr() or info.isblk():
            elif not (info.isfile() or info.isdir() or info.issym()):
                self._reason = (
                    f"Block device or named pipe found in tar file. file = {info.name}"
                )
                break

            # don't actually write files, but don't block them either
            elif info.isfile():
                pass
            else:
                yield info

    def is_safe(self) -> bool:
        """
        Validate the file is safe (per these checks).

        :return: True if safe (per these checks) else False
        """
        file_count = 0
        total_size = 0
        for file in self._file_contents:
            file_count += 1
            total_size += file.size

            # too many files
            if file_count > self._file_limit:
                self._reason = f"Too many files in Tar. > {self._file_limit}"
                return False

            # too much space
            # 1048576 = 1 MB. We're checking in MB here.
            if (total_size / 1048576) > self._max_mb:
                self._reason = "Extracted size too large."
                return False

        # In order to truly, properly resolve if a tarfile has tarslips in it,
        # unfortunately the best way is to actually just unpack it and check
        # each member with `realpath` for escape as you go. to prevent blowing up
        # the file system with the contents of the archive before we've even
        # properly processed it, we won't actually write any files during this process,
        # only directories and symlinks.
        with tempfile.TemporaryDirectory() as tempdir_name:
            try:
                safe_members = self.yield_safe_members(
                    self._file_contents.getmembers(), tempdir_name
                )
                self._file_contents.extractall(tempdir_name, members=safe_members)
            except OSError as err:  # pragma: no cover
                self._reason = f"Encountered OSError when extracting tarball: {err}"
                return False

        # If reason is populated then the tarball is not safe
        if self._reason:
            return False

        # close the in-memory tar
        self._file_contents.close()
        return True
