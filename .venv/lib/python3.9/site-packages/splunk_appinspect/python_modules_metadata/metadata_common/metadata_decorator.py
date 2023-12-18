from __future__ import annotations

from typing import Callable

from splunk_appinspect.python_modules_metadata.metadata_common.metadata_consts import TagConsts


def tags(*object_tags: TagConsts) -> Callable:
    def wrap(func: Callable):
        func.tags: tuple[TagConsts] = object_tags
        return func

    return wrap


def executable(func: Callable) -> Callable:
    func.executable = True
    return func
