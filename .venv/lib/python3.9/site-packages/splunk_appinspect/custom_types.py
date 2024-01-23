from __future__ import annotations

import ast
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Protocol, TypeVar, Union

from splunk_appinspect.checks import Check
from splunk_appinspect.configuration_file import (
    ConfigurationFile,
    ConfigurationProxy,
    MergedConfigurationFile,
    MergedConfigurationProxy,
)
from splunk_appinspect.file_view import FileView, MergedFileView
from splunk_appinspect.python_analyzer.ast_types import AstClass, AstFunction, AstModule
from splunk_appinspect.reflected_xss_detector import ReflectedXSSDetectRule

ConfigurationFileType = Union[ConfigurationFile, MergedConfigurationFile]
ConfigurationProxyType = Union[ConfigurationProxy, MergedConfigurationProxy]
FileViewType = Union[FileView, MergedFileView]

CheckType = TypeVar("CheckType", bound=Check)

ReportRecordDict = Dict[str, Union[str, int, None]]
GroupChecksDict = Dict[str, Union[str, List[ReportRecordDict]]]
GroupDict = Dict[str, Union[str, List[GroupChecksDict]]]
MetricsDict = Dict[str, Union[datetime, None]]
FormattedAppReportDict = Dict[str, Union[str, MetricsDict, List[GroupDict]]]

ReflectedXSSDetectRuleType = TypeVar("ReflectedXSSDetectRuleType", bound=ReflectedXSSDetectRule)

DependencyDictType = Dict[Path, Union[str, List["DependencyDictType"]]]
AstInfoQueryFilterCallable = Callable[[ast.AST], bool]
AstVariableValue = Union[str, float, AstClass, AstModule, AstFunction, None]

T = TypeVar("T")


class ReportCallable(Protocol):
    def __call__(self, message: str, file_name: Optional[str] = None, line_number: Optional[int] = None) -> None:
        ...
