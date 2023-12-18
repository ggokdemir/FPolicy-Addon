# Copyright 2019 Splunk Inc. All rights reserved.

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Optional, Union


class InspectedFile:
    def __init__(self, path: Path = Path("")):
        self._path: Path = path

    @staticmethod
    def factory(path: Path = Path("")) -> Optional[InspectedFile]:
        """
        Args:
            path: file path.

        Returns:
            Inspected File object.

        """
        if not (os.path.isfile(path) and os.access(path, os.R_OK)):
            return None

        fext = path.suffix
        if fext == ".py":
            return PythonFile(path)
        if fext == ".js":
            return CStyleFile(path)
        ###
        # Add more type here
        # TODO:
        # - html
        # - conf
        # - etc.
        ###
        return InspectedFile(path)

    def _preserve_line(self, text: str) -> str:
        """
        Args:
            text: multi-line string.

        Returns:
            multiple empty lines.

        """
        re_endline = re.compile(r"\r?\n", re.MULTILINE)
        return "".join([x[0] for x in re_endline.findall(text)])

    def _evaluate_match(self, match: re.Match, keep_group: str, remove_group: str) -> str:
        """
        Args:
            match: regex match.
            keep_group: name of group to be kept.
            remove_group: name of group to be removed.

        Returns:
            string after evaluated.

        """
        group = match.groupdict()
        if group[keep_group]:
            return group[keep_group]
        return self._preserve_line(group[remove_group])

    def _remove_comments(self, content: str) -> str:
        """
        Args:
            content: text string.

        Returns:
            content without comments.

        """
        # In general text file, no need to remove comments
        return content

    def search_for_patterns(
        self, patterns: list[str | re.Pattern], exclude_comments: bool = True, regex_option: int = 0
    ) -> list[tuple[str, re.Match[str]]]:
        """
        Args:
            patterns: regex patterns array.
            exclude_comments: excluded comment from test.
            regex_option: regex option.

        Returns:
           Array of match objects.

        """

        matches = []

        inspected_file = open(self._path, "r", encoding="utf-8", errors="ignore")
        line_no = 0
        content = inspected_file.read()
        inspected_file.close()

        if exclude_comments:
            content = self._remove_comments(content)
        for line in content.splitlines():
            line_no += 1
            for rx in [re.compile(p, regex_option) for p in patterns]:
                for p_match in rx.finditer(line):
                    fileref_output = f"{self._path}:{line_no}"
                    matches.append((fileref_output, p_match))

        return matches

    def search_for_pattern(
        self, pattern: str | re.Pattern, exclude_comments: bool = True, regex_option: int = 0
    ) -> list[tuple[str, re.Match[str]]]:
        """Same with search_for_patterns except single pattern."""
        return self.search_for_patterns([pattern], exclude_comments, regex_option)

    def search_for_patterns_in_whole_file(
        self, pattern: re.Pattern, regex_option: int = 0
    ) -> list[tuple[str, re.Match[str]]]:
        """
        Args:
            pattern: regex pattern.
            regex_option: regex option.

        Returns:
            Array of match objects.

        """
        matches = []
        inspected_file = open(self._path, "r", encoding="utf-8", errors="ignore")
        content = inspected_file.read()
        inspected_file.close()
        for rx in [re.compile(p, regex_option) for p in [pattern]]:
            for p_match in rx.finditer(content):
                fileref_output = f"{self._path}"
                matches.append((fileref_output, p_match))

        return matches

    def search_for_crossline_patterns(
        self, patterns: list[str | re.Pattern], exclude_comments: bool = True, cross_line: int = 10
    ) -> list[tuple[str, re.Match[str]]]:
        """
        Args:
            patterns: regex patterns array.
            exclude_comments: excluded comment from test.
            cross_line: Cross line for the pattern.

        Returns:
            array of match objects.

        """

        matches = []

        inspected_file = open(self._path, "r", encoding="utf-8", errors="ignore")
        content = inspected_file.read()
        inspected_file.close()

        if exclude_comments:
            content = self._remove_comments(content)

        lines_content = content.splitlines()
        lines_count = len(lines_content)

        for line_no in range(0, lines_count):
            multi_line = ""
            start_line = line_no
            end_line = (start_line + cross_line) if (start_line + cross_line) <= lines_count else lines_count
            for item in lines_content[start_line:end_line]:
                multi_line += item + "\n"

            for rx in [re.compile(p) for p in patterns]:
                if rx.match(multi_line):
                    fileref_output = f"{self._path}:{line_no + 1}"
                    matches.append((fileref_output, rx.match(multi_line)))

        return matches

    def search_for_crossline_pattern(
        self, pattern: re.Pattern, exclude_comments: bool = True, cross_line: int = 10
    ) -> list[tuple[str, re.Match[str]]]:
        """Same with search_for_crossline_patterns except single pattern."""
        return self.search_for_crossline_patterns(
            patterns=[pattern],
            exclude_comments=exclude_comments,
            cross_line=cross_line,
        )


class PythonFile(InspectedFile):
    COMMENT_PATTERN = re.compile(
        r"""
            (?P<comments>
                \s*\#(?:[^\r\n])*	# single line comment
            )
            | (?P<code>
                .[^\#]*           # sourcecode
            )
            """,
        re.VERBOSE | re.MULTILINE | re.DOTALL,
    )
    DOCSTRING_PATTERN = re.compile(
        r"""
            (?P<start>
                ^\s*"{3}	# start triple double quotes
                | ^\s*'{3}	# start triple single quotes
            )
            | (?P<end>
                "{3}\s*$	# end triple double quotes
                | '{3}\s*$	# end trible single quotes
            )
        """,
        re.VERBOSE,
    )

    def __init__(self, path: Path = Path("")) -> None:
        self._path: Path = path
        super().__init__(path)

    def _remove_comments(self, content: str) -> str:
        """Override _remove_comments."""
        content = "".join(
            map(
                lambda m: self._evaluate_match(m, "code", "comments"),
                self.COMMENT_PATTERN.finditer(content),
            )
        )
        stripped_content = ""
        line_skip = False
        for line in content.splitlines():
            match = self.DOCSTRING_PATTERN.findall(line)
            if match:
                if len(match) == 1:
                    line_skip = not line_skip  # Only one tripe double/single quotes
                # If there are 2 triple double/single quotes, it's already
                # completed docstring
                stripped_content += "\r\n"
                continue

            if line_skip:
                stripped_content += "\r\n"
                continue

            stripped_content += line + "\r\n"

        return stripped_content


class CStyleFile(InspectedFile):
    COMMENT_PATTERN = re.compile(
        r"""
              (?P<comments>
                    /\*[^*]*\*+(?:[^/*][^*]*\*+)*/          # multi-line comments
                  | \s*(?<!:)//(?:[^\r\n])*                 # single line comment
              )
            | (?P<code>
                .[^/]*                              # sourcecode
              )
        """,
        re.VERBOSE | re.MULTILINE | re.DOTALL,
    )

    def __init__(self, path: Path = Path("")) -> None:
        self._path: Path = path
        super().__init__(path)

    def _remove_comments(self, content: str) -> str:
        """Override _remove_comments."""
        return "".join(
            map(
                lambda m: self._evaluate_match(m, "code", "comments"),
                self.COMMENT_PATTERN.finditer(content),
            )
        )
