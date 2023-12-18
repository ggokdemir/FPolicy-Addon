from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Iterator, Optional

from splunk_appinspect.python_analyzer import utilities

if TYPE_CHECKING:
    from splunk_appinspect.python_analyzer.ast_analyzer import AstAnalyzer


logger = logging.getLogger()


class AstInfoStore:
    def __init__(self, libs: Optional[list[Path]] = None) -> None:
        self._data: dict[Path, "AstAnalyzer"] = {}
        self._pointer: Optional[Path] = None
        self._libs: Optional[list[Path]] = libs

    def set_pointer(self, position: Path) -> None:
        self._pointer = position

    def get_pkg_path_and_obj_name(self, import_chain: str) -> tuple[Optional[Path], Optional[str]]:
        assert self._pointer
        if import_chain.startswith("."):
            # Relative importing doesn't consider persistent libs
            import_chain_proced, pointer = utilities.relative_import_dump(import_chain, self._pointer)
            return self._get_pkg_path_and_obj_name_helper(import_chain_proced, pointer)
        return self._get_pkg_path_and_obj_name_helper(import_chain, self._pointer, libs=self._libs)

    @staticmethod
    def _get_pkg_path_and_obj_name_helper(
        import_chain_proced: str, pointer: Path | str, libs: Optional[list[str]] = None
    ) -> tuple[Optional[Path], Optional[str]]:
        if import_chain_proced == "*":
            if str(pointer).endswith(".py"):
                pointer = Path(pointer).parent
            pkg_path = Path(pointer, "__init__.py")
            return pkg_path, "*"

        if import_chain_proced.endswith(".*"):
            pkg_name = import_chain_proced[:-2]
            pkg_path = utilities.find_pkg_path(pointer, pkg_name, libs)
            return pkg_path, "*"

        pkg_name = import_chain_proced
        pkg_path = utilities.find_pkg_path(pointer, pkg_name, libs)
        if pkg_path:
            return pkg_path, None
        import_chain_segs = import_chain_proced.split(".")
        pkg_name = ".".join(import_chain_segs[:-1])
        obj_name = import_chain_segs[-1]
        if pkg_name == "":
            return None, None

        pkg_path = utilities.find_pkg_path(pointer, pkg_name, libs)
        if pkg_path:
            return pkg_path, obj_name

        return None, None

    def flush(self) -> None:
        self._data = {}

    def items(self) -> Iterator[tuple[str, "AstAnalyzer"]]:
        return iter(self._data.items())

    def iteritems(self) -> Iterator[tuple[str, "AstAnalyzer"]]:
        return iter(self._data.items())

    def __setitem__(self, key: Path, value: "AstAnalyzer") -> None:
        self._data[key] = value

    def __getitem__(self, key: Path) -> "AstAnalyzer":
        return self._data[key]

    def __contains__(self, key: Path) -> bool:
        return key in self._data
