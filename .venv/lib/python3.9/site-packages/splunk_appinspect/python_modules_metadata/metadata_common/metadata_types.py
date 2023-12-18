from __future__ import annotations

import enum
from enum import Enum
from types import ModuleType
from typing import Iterable, Optional

from splunk_appinspect.python_analyzer.ast_types import (
    AstCallableFunction,
    AstClass,
    AstContext,
    AstModule,
    AstVariable,
    Copyable,
)


class Metadata(object):
    def __init__(
        self,
        name: str,
        namespace: str,
        description: Optional[str],
        tags: Optional[Iterable[enum.Enum]],
        python_object: Optional[ModuleType],
    ) -> None:
        self.name: str = name
        self.namespace: str = namespace
        self.description: str = description.strip() if description else ""
        self.tags: set[enum.Enum] = set(tags) if tags else set()
        self.python_object: Optional[ModuleType] = python_object

        assert isinstance(self.name, str)
        assert isinstance(self.namespace, str)
        assert isinstance(self.description, str)

    def add(self, metadata: Metadata) -> None:
        pass

    def instantiate(self) -> Optional[Copyable]:
        pass


class ModuleMetadata(Metadata):
    def __init__(
        self,
        name: str,
        namespace: str,
        description: Optional[str],
        tags: Optional[Iterable[enum.Enum]] = None,
        python_object: ModuleType = None,
    ) -> None:
        # in case check writer pass a enum as argument
        if isinstance(name, Enum):
            name = name.value
        super().__init__(name, namespace, description, tags, python_object)
        self._sub_modules: list[ModuleMetadata] = []
        self._functions: list[FunctionMetadata] = []
        self._classes: list[ClassMetadata] = []

    def __str__(self) -> str:
        return (
            f"Module name: {self.name}, Sub Module names: "
            f"{', '.join(map(lambda node: node.name, self._sub_modules))}, "
            f"Function names: {', '.join(map(lambda node: node.name, self._functions))}, "
            f"Classes: {', '.join(map(lambda node: node.name, self._classes))}"
        )

    def add(self, metadata: Metadata) -> None:
        if isinstance(metadata, ModuleMetadata):
            self.sub_modules.append(metadata)
        elif isinstance(metadata, FunctionMetadata):
            self.functions.append(metadata)
        elif isinstance(metadata, ClassMetadata):
            self.classes.append(metadata)
        else:
            raise Exception("Illegal Metadata types {}".format(str(type(metadata))))

    def instantiate(self) -> AstModule:
        ast_module = AstModule(self.name, namespace=self.namespace)
        for sub_module in self._sub_modules:
            ast_module.global_map[sub_module.name] = sub_module.instantiate()
        for function in [func for func in self._functions if func.instantiate()]:
            ast_module.global_map[function.name] = function.instantiate()
        for class_instance in self._classes:
            ast_module.global_map[class_instance.name] = class_instance.instantiate()
        return ast_module

    @property
    def sub_modules(self) -> list[ModuleMetadata]:
        return self._sub_modules

    @property
    def functions(self) -> list[FunctionMetadata]:
        return self._functions

    @property
    def classes(self) -> list[ClassMetadata]:
        return self._classes


class ClassMetadata(Metadata):
    def __init__(
        self,
        name: str,
        namespace: str,
        description: Optional[str],
        tags: Optional[Iterable[enum.Enum]],
        python_object: ModuleType,
    ) -> None:
        super().__init__(name, namespace, description, tags, python_object)
        self._functions: list[FunctionMetadata] = []
        self._classes: list[ClassMetadata] = []

    def add(self, metadata: Metadata) -> None:
        if isinstance(metadata, FunctionMetadata):
            self._functions.append(metadata)
        elif isinstance(metadata, ClassMetadata):
            self._classes.append(metadata)
        else:
            raise Exception("Illegal metadata type {}".format(str(type(metadata))))

    def instantiate(self) -> AstClass:
        ast_class = AstClass(self.name, AstContext(0, None), namespace=self.namespace)
        for function in [func for func in self._functions if func.instantiate()]:
            ast_class.function_dict[function.name] = function.instantiate()
        for sub_class in self._classes:
            ast_class.class_context.variable_map[sub_class.name] = AstVariable(
                None, {AstVariable.CLASS_TYPE}, sub_class.instantiate()
            )
        return ast_class

    def __str__(self) -> str:
        return (
            f"Class name: {self.name}, "
            f"Class names: {', '.join(map(lambda node: node.name, self._classes))}, "
            f"Function names: {', '.join(map(lambda node: node.name, self._functions))}"
        )

    @property
    def functions(self) -> list[FunctionMetadata]:
        return self._functions

    @property
    def classes(self) -> list[ClassMetadata]:
        return self._classes

    @property
    def module_name(self) -> str:
        return ".".join(self.namespace.split(".")[:-1])


class FunctionMetadata(Metadata):
    def __init__(
        self,
        name: str,
        namespace: str,
        description: Optional[str],
        tags: Optional[Iterable[enum.Enum]] = None,
        python_object: Optional[ModuleType] = None,
    ):
        super().__init__(name, namespace, description, tags, python_object)

    def __str__(self) -> str:
        return f"Function name: {self.name}, function description: {self.description}"

    def instantiate(self) -> Optional[AstCallableFunction]:
        python_function_object_in_metadata, function_name, function_namespace = (
            self.python_object,
            self.name,
            self.namespace,
        )

        if not hasattr(python_function_object_in_metadata, "executable"):
            return None

        class PythonFunction(AstCallableFunction):
            def __init__(self):
                AstCallableFunction.__init__(self, function_name, function_namespace)

            def action(self, function_node, analyzer, args, keywords, context):
                # Delegate function call procedure to python function object
                # Keep user defined function simple, only args and keywords are required positional arguments
                # other arguments are optional keyword arguments
                return python_function_object_in_metadata(
                    args,
                    keywords,
                    function_node=function_node,
                    analyzer=analyzer,
                    context=context,
                )

        return PythonFunction()

    @property
    def module_name(self) -> str:
        return ".".join(self.namespace.split(".")[:-1])
