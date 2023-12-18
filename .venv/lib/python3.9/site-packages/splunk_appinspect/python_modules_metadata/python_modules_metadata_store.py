from __future__ import annotations

import enum
import inspect
import os
from collections import deque
from pathlib import Path
from types import ModuleType
from typing import Iterable, Optional

from splunk_appinspect.python_modules_metadata.metadata_common import metadata_types
from splunk_appinspect.python_modules_metadata.metadata_common.metadata_exceptions import (
    EmptyNamespace,
    IllegalAsteriskNamespace,
)


class PythonModulesMetadata:
    def __init__(self) -> None:
        self._root_module: metadata_types.ModuleMetadata = metadata_types.ModuleMetadata(
            "metadata",
            "",
            "virtual root node",
        )

        # internal function names
        self._allow_list_functions: set[str] = {"tags", "executable"}
        # internal class names
        self._allow_list_classes: set[str] = {"TagConsts", "AstVariable"}

        from . import metadata

        for module_name in dir(metadata):
            # self-defined modules, don't need to use allow_list to filter noisy
            if inspect.ismodule(getattr(metadata, module_name)):
                self._root_module.add(self._build_metadata_tree(getattr(metadata, module_name), ""))

    def _build_metadata_tree(self, metadata_obj: ModuleType, namespace: str) -> Optional[metadata_types.Metadata]:
        if inspect.ismodule(metadata_obj):
            # it is a module which doesn't belong to metadata folder, exclude it from metadata tree
            if not self._check_module_name(metadata_obj):
                return None

            module_name = metadata_obj.__name__.split(".")[-1]

            # special check for case-sensitive situation
            # eg: `SocketServer` and `socketserver`, here I use `___socketserver` to represents `socketserver`
            if module_name.startswith("___"):
                module_name = module_name[3:]

            namespace = module_name if namespace == "" else namespace + "." + module_name
            module = metadata_types.ModuleMetadata(
                module_name, namespace, metadata_obj.__doc__, python_object=metadata_obj
            )
            # if module tags are set
            if hasattr(metadata_obj, "__tags__"):
                tags = metadata_obj.__tags__
                if hasattr(tags, "__iter__"):
                    module.tags = set(tags)

            for attribute_name in dir(metadata_obj):
                if not attribute_name.startswith("__"):
                    attr = self._build_metadata_tree(getattr(metadata_obj, attribute_name), namespace)
                    if attr:
                        module.add(attr)
            return module

        if inspect.isfunction(metadata_obj) or inspect.ismethod(metadata_obj):
            function_name = metadata_obj.__name__.split(".")[-1]
            namespace = function_name if namespace == "" else namespace + "." + function_name
            if function_name in self._allow_list_functions:
                return None

            tags = set(list(metadata_obj.tags)) if hasattr(metadata_obj, "tags") else set()
            func = metadata_types.FunctionMetadata(
                function_name,
                namespace,
                metadata_obj.__doc__,
                tags=tags,
                python_object=metadata_obj,
            )
            return func

        if inspect.isclass(metadata_obj):
            class_name = metadata_obj.__name__.split(".")[-1]
            namespace = class_name if namespace == "" else namespace + "." + class_name
            if class_name in self._allow_list_classes:
                return None

            tags = set(list(metadata_obj.tags)) if hasattr(metadata_obj, "tags") else set()
            class_obj = metadata_types.ClassMetadata(
                class_name,
                namespace,
                metadata_obj.__doc__,
                tags=tags,
                python_object=metadata_obj,
            )
            for attribute_name in dir(metadata_obj):
                if not attribute_name.startswith("__"):
                    attr = self._build_metadata_tree(getattr(metadata_obj, attribute_name), namespace)
                    if attr:
                        class_obj.add(attr)
            return class_obj

        return None

    @property
    def root_module(self) -> metadata_types.ModuleMetadata:
        return self._root_module

    def query(self) -> MetadataQuery:
        """Start a new query execution."""
        return MetadataQuery(self)

    def query_namespace(self, namespace: str) -> list[metadata_types.ModuleMetadata]:
        """Used by analyzer extension only, fetch all executable functions, legal modules and classes."""
        self._check_namespace(namespace)

        root_node = self._root_module
        for name in namespace.split("."):
            if name == "*":
                # collect all components belong to current namespace
                if isinstance(root_node, metadata_types.ModuleMetadata):
                    return (
                        root_node.sub_modules
                        + root_node.classes
                        + [func for func in root_node.functions if func.instantiate()]
                    )
                if isinstance(root_node, metadata_types.ClassMetadata):
                    return [func for func in root_node.functions if func.instantiate()] + root_node.classes

                return []

            if isinstance(root_node, metadata_types.ModuleMetadata):
                find = False
                for child_node in root_node.sub_modules + root_node.functions + root_node.classes:
                    if child_node.name == name:
                        root_node = child_node
                        find = True
                        break
                if not find:
                    return []
            elif isinstance(root_node, metadata_types.ClassMetadata):
                find = False
                for child_node in root_node.classes + root_node.functions:
                    if child_node.name == name:
                        root_node = child_node
                        find = True
                        break
                if not find:
                    return []
            else:
                return []
        return [root_node] if root_node.instantiate() else []

    @staticmethod
    def _check_namespace(namespace: str) -> None:
        if namespace == "":
            raise EmptyNamespace("Illegal namespace string, namespace is empty")
        if namespace == "*":
            # only one asterisk is also illegal
            raise IllegalAsteriskNamespace("One asterisk is illegal namespace")

        names = namespace.split(".")
        # asterisk could only be the last element
        total_number_of_asterisks = sum(map(lambda name: 1 if name == "*" else 0, names))
        if total_number_of_asterisks > 1 or (total_number_of_asterisks == 1 and names[-1] != "*"):
            raise IllegalAsteriskNamespace(
                "Illegal namespace string, asterisk could only be used in the last position, eg: a.b.*"
            )

    @staticmethod
    def _check_module_name(metadata_module: ModuleType) -> bool:
        # use __file__ path to check first
        if hasattr(metadata_module, "__file__"):
            filepath = Path(os.path.abspath(metadata_module.__file__))
            for path in filepath.parts:
                # it is in metadata folder
                if path == "metadata":
                    return True
            return False

        return "metadata" in metadata_module.__name__


class MetadataQuery:
    def __init__(self, metadata_set: PythonModulesMetadata) -> None:
        self.__metadata_set: PythonModulesMetadata = metadata_set
        # include logic
        self._tag_set: set[str] = set()
        self._name_set: set[str] = set()
        self._namespace_prefix_set: set[str] = set()
        # exclude logic
        self._exclude_tag_set: set[str] = set()
        self._exclude_name_set: set[str] = set()
        self._exclude_namespace_prefix_set: set[str] = set()
        # tag group logic
        self._tag_group_list: list[set[str]] = []

    # Transform operators

    def tag(self, tag: enum.Enum) -> MetadataQuery:
        """Include all elements contains `tag`"""
        if isinstance(tag, enum.Enum):
            self._tag_set.add(tag)
        else:
            raise Exception("Illegal tag argument")

        return self

    def exclude_tag(self, tag: enum.Enum) -> MetadataQuery:
        """Exclude all elements contains `tag`."""
        if isinstance(tag, enum.Enum):
            self._exclude_tag_set.add(tag)
        else:
            raise Exception("Illegal tag argument to exclude")

        return self

    def tags(self, tags: Iterable[enum.Enum]) -> MetadataQuery:
        for tag_argument in tags:
            self.tag(tag_argument)
        return self

    def exclude_tags(self, tags: Iterable[enum.Enum]) -> MetadataQuery:
        for tag_argument in tags:
            self.exclude_tag(tag_argument)
        return self

    def tag_group(self, tags: Iterable[str]) -> MetadataQuery:
        """Include all elements contain all tags mentioned in tag_group."""
        if hasattr(tags, "__iter__"):
            self._tag_group_list.append(set(tags))
        else:
            raise Exception("Illegal tag group, please use an iterable collection")
        return self

    def namespace_prefix(self, name_prefix: str | enum.Enum) -> MetadataQuery:
        """Include all elements start with `name_prefix`."""
        if isinstance(name_prefix, str):
            self._namespace_prefix_set.add(name_prefix)
        elif isinstance(name_prefix, enum.Enum):
            self._namespace_prefix_set.add(name_prefix.value)
        else:
            raise Exception("Illegal namespace prefix argument")

        return self

    def exclude_namespace_prefix(self, name_prefix: str | enum.Enum) -> MetadataQuery:
        """Exclude all elements start with `name_prefix`."""
        if isinstance(name_prefix, str):
            self._exclude_namespace_prefix_set.add(name_prefix)
        elif isinstance(name_prefix, enum.Enum):
            self._exclude_namespace_prefix_set.add(name_prefix.value)
        else:
            raise Exception("Illegal namespace prefix argument to exclude")

        return self

    def namespace_prefixes(self, name_prefixes: Iterable[str | enum.Enum]) -> MetadataQuery:
        for prefix in name_prefixes:
            self.namespace_prefix(prefix)
        return self

    def exclude_namespace_prefixes(self, name_prefixes: Iterable[str | enum.Enum]) -> MetadataQuery:
        for prefix in name_prefixes:
            self.exclude_namespace_prefix(prefix)
        return self

    def name(self, name: str | enum.Enum) -> MetadataQuery:
        """Include all elements with element's name is `name`, name is the last string in namespace."""
        if isinstance(name, enum.Enum):
            self._name_set.add(name.value)
        elif isinstance(name, str):
            self._name_set.add(name)
        else:
            raise Exception("Illegal name argument")

        return self

    def exclude_name(self, name: str | enum.Enum) -> MetadataQuery:
        """Exclude all elements with element's name is `name`, name is the last string in namespace."""
        if isinstance(name, enum.Enum):
            self._exclude_name_set.add(name.value)
        elif isinstance(name, str):
            self._exclude_name_set.add(name)
        else:
            raise Exception("Illegal name argument to exclude")

        return self

    def names(self, names: Iterable[str | enum.Enum]) -> MetadataQuery:
        for filter_name in names:
            self.name(filter_name)
        return self

    def exclude_names(self, names: Iterable[str | enum.Enum]) -> MetadataQuery:
        for filter_name in names:
            self.exclude_name(filter_name)
        return self

    def python_compatible(self) -> MetadataQuery:
        """If current py version is py2, exclude py3 exclusive features otherwise, include all possible features."""
        return self

    # Action operators

    def collect(self) -> list[metadata_types.Metadata]:
        """Return all elements under current constraints."""
        result_list = []

        queue = deque()
        for module in self.__metadata_set.root_module.sub_modules:
            queue.append(module)

        while queue:
            current_object = queue.popleft()
            # check if current tuple being filtered
            if not self._is_filtered(current_object):
                result_list.append(current_object)
            # modules, functions could be nested in module and class
            if isinstance(current_object, metadata_types.ModuleMetadata):
                next_iter_list = current_object.sub_modules + current_object.functions + current_object.classes
            elif isinstance(current_object, metadata_types.ClassMetadata):
                next_iter_list = current_object.functions + current_object.classes
            else:
                next_iter_list = []
            for next_obj in next_iter_list:
                queue.append(next_obj)

        return result_list

    def functions(self) -> list[metadata_types.FunctionMetadata]:
        """Return all functions under current constraints."""
        return list(
            filter(
                lambda node: isinstance(node, metadata_types.FunctionMetadata),
                self.collect(),
            )
        )

    def modules(self) -> list[metadata_types.ModuleMetadata]:
        """Return all modules under current constraints."""
        return list(
            filter(
                lambda node: isinstance(node, metadata_types.ModuleMetadata),
                self.collect(),
            )
        )

    def classes(self) -> list[metadata_types.ClassMetadata]:
        """Return all classes under current constraints."""
        return list(
            filter(
                lambda node: isinstance(node, metadata_types.ClassMetadata),
                self.collect(),
            )
        )

    def reset(self) -> None:
        """Reset all filter logic."""
        self._tag_set.clear()
        self._name_set.clear()
        self._namespace_prefix_set.clear()

        self._exclude_tag_set.clear()
        self._exclude_name_set.clear()
        self._exclude_namespace_prefix_set.clear()

        self._tag_group_list = []

    def _is_filtered(self, obj: metadata_types.Metadata) -> bool:
        # Filter by name
        if self._name_set and obj.name not in self._name_set:
            return True
        # Filter by tag
        if self._tag_set and not (obj.tags & self._tag_set):
            return True
        # Filter by namespace_prefix
        if self._namespace_prefix_set and all(
            map(
                lambda prefix: not self._is_namespace_prefix(prefix, obj.namespace),
                self._namespace_prefix_set,
            )
        ):
            return True

        # Excluded by name
        if obj.name in self._exclude_name_set:
            return True
        # Excluded by tag
        if obj.tags & self._exclude_tag_set:
            return True
        # Excluded by namespace_prefix
        if any(
            map(
                lambda prefix: self._is_namespace_prefix(prefix, obj.namespace),
                self._exclude_namespace_prefix_set,
            )
        ):
            return True

        # Filter by tag group
        for tag_group in self._tag_group_list:
            # Not all tag_group are found
            if (obj.tags & tag_group) != tag_group:
                return True

        return False

    @staticmethod
    def _is_namespace_prefix(prefix: str, namespace: str) -> bool:
        name_array1, name_array2 = prefix.split("."), namespace.split(".")
        if len(name_array1) > len(name_array2):
            return False

        for name1, name2 in zip(name_array1, name_array2):
            if not name1 == name2:
                return False
        return True


# singleton instance
metadata_store = PythonModulesMetadata()
