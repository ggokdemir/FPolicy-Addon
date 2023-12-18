from __future__ import annotations

import ast
import copy
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator, Generic, Optional, TypeVar

if TYPE_CHECKING:
    from splunk_appinspect.custom_types import AstVariableValue
    from splunk_appinspect.python_analyzer.ast_analyzer import AstAnalyzer

T = TypeVar("T")


class Stack(Generic[T]):
    def __init__(self) -> None:
        self._list: list[T] = []
        self._set: set[T] = set()

    @property
    def empty(self) -> bool:
        return len(self._list) == 0

    def pop(self) -> T:
        res = self._list.pop()
        self._set.remove(res)
        return res

    def append(self, target: T) -> Stack:
        self._set.add(target)
        self._list.append(target)
        return self

    def has(self, target: T) -> bool:
        return target in self._set

    @property
    def list(self) -> list[T]:
        return self._list

    def copy(self, target: Stack) -> Stack:
        self._list = target._list[:]  # pylint: disable=W0212
        self._set = set()
        self._set.update(target._set)  # pylint: disable=W0212
        return self


class FileNode:
    """A class defining the node structure of a python file. This structure is used in FileDepManager."""

    def __init__(self, filepath: Path | str) -> None:
        self.filepath: Path = Path(os.path.abspath(filepath))
        self._parents: set[FileNode] = set()
        self._children: set[FileNode] = set()
        self.parent_stamps: dict[FileNode, Optional[int]] = {}

        # Assist members for finding scc
        self.id: int = -1
        self.low_link: int = -1

    @property
    def in_degree(self) -> int:
        return len(self._parents)

    @property
    def out_degree(self) -> int:
        return len(self._children)

    def __str__(self) -> str:
        return f"<FileNode: {self.filepath}>"

    def add_parent(self, parent: FileNode, stamp: Optional[int] = None) -> None:
        self._parents.add(parent)
        parent._children.add(self)  # pylint: disable=W0212
        self.parent_stamps[parent] = stamp

    def iter_child(self) -> Generator[FileNode, Any, str]:
        for ele in self._children:
            yield ele

    def iter_parent(self) -> Generator[FileNode, Any, str]:
        for ele in self._parents:
            yield ele

    def is_root_file(self) -> int:
        return len(self._parents) == 0

    def has_parent(self, parent: FileNode) -> bool:
        return parent in self._parents

    def has_child(self, child: FileNode) -> bool:
        return child in self._children


class Copyable:
    def copy(self) -> Copyable:
        raise NotImplementedError("copy method should be implemented in Copyable class")


class AstVariable(Copyable):
    """One variable could have more than one variable types."""

    # some basic variable types
    STRING_TYPE = "str"
    NUMBER_TYPE = "num"
    # class variable
    CLASS_TYPE = "instance"
    # function variable
    FUNCTION_TYPE = "function"
    # module variable
    MODULE_TYPE = "module"
    # builtin variable
    BUILTIN_TYPE = "__builtin__"
    # callable function
    CALLABLE_FUNCTION = "callable_function"

    SPECIAL_TYPES = [
        STRING_TYPE,
        NUMBER_TYPE,
        CLASS_TYPE,
        FUNCTION_TYPE,
        MODULE_TYPE,
        BUILTIN_TYPE,
        CALLABLE_FUNCTION,
    ]

    def __init__(
        self,
        variable_value_node: Optional[ast.AST],
        variable_type_set: set[str],
        variable_value: AstVariableValue = None,
        name: Optional[str] = None,
    ) -> None:
        # variable name
        self.name: Optional[str] = name
        # AST node in ='s right side
        self.variable_value_node: Optional[ast.AST] = variable_value_node
        # variable types, `str`, `num`, `class` or modules
        self.variable_type_set: set[str] = variable_type_set
        # string type: variable_value should be string
        # number type: variable_value should be number
        # class type: variable_value should be AstClass instance
        # module type: variable_value should be AstModule
        # function type: variable_value should be AstFunction
        # other types: None
        self.variable_value: "AstVariableValue" = variable_value

    def copy(self) -> AstVariable:
        copy_variable_value_node, copy_variable_type_set, copy_variable_value = (
            self.variable_value_node,
            copy.deepcopy(self.variable_type_set),
            self.variable_value.copy()
            if isinstance(self.variable_value, Copyable)
            else copy.deepcopy(self.variable_value),
        )
        return AstVariable(
            copy_variable_value_node,
            copy_variable_type_set,
            copy_variable_value,
            self.name,
        )

    @staticmethod
    def is_class_instance(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.CLASS_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_string(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.STRING_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_number(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.NUMBER_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_function(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.FUNCTION_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_module(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.MODULE_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_builtin(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.BUILTIN_TYPE in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_callable_function(ast_variable: Any) -> bool:
        return (
            isinstance(ast_variable, AstVariable)
            and (AstVariable.CALLABLE_FUNCTION in ast_variable.variable_type_set)
            and len(ast_variable.variable_type_set & set(AstVariable.SPECIAL_TYPES)) == 1
        )

    @staticmethod
    def is_callable(ast_variable: Any) -> bool:
        return AstVariable.is_builtin(ast_variable) or AstVariable.is_callable_function(ast_variable)


class AstFunction(Copyable):
    def __init__(self, name: str, root_node: ast.AST, return_value: Optional[AstVariable] = None) -> None:
        self.name: str = name
        self.root_node: ast.AST = root_node
        self.return_value: Optional[AstVariable] = return_value

    def copy(self) -> AstFunction:
        # copy_return_value = self.return_value.copy() if isinstance(self.return_value, Copyable) else copy.deepcopy(self.return_value)
        return AstFunction(self.name, self.root_node, self.return_value)

    def action(self) -> Optional[AstVariable]:
        return None if self.return_value is None else self.return_value.copy()


class AstClass(Copyable):
    # TODO doesn't align with python implementation
    """
    Python won't copy context from super class to current class, just link them together. So If I change a attribute
    in super class, inherited class or instances will also be affected. In current implementation, we could not support
    this feature, since super class and inherited class are isolated environments, they won't affect each other.

    Current design facilitate Analyzer's implementation, make code easy to maintain.
    Need to refactor these logic when necessary.

    """

    def __init__(
        self,
        name: str,
        class_context: AstContext,
        function_dict: Optional[dict[str, AstFunction]] = None,
        modules: Optional[set[str]] = None,
        namespace: Optional[str] = None,
    ) -> None:
        self.name: str = name
        self.namespace: Optional[str] = namespace
        self.class_context: AstContext = class_context
        self.function_dict: dict[str, AstFunction] = {} if function_dict is None else function_dict
        self.modules: set[str] = set() if modules is None else modules

    def copy(self) -> AstClass:
        copy_class_context = self.class_context.copy()
        copy_function_dict = {}
        for function_name, function in self.function_dict.items():
            copy_function_dict[function_name] = function
        return AstClass(
            self.name,
            copy_class_context,
            copy_function_dict,
            copy.deepcopy(self.modules),
            self.namespace,
        )


class AstModule(Copyable):
    def __init__(
        self, name: str, global_map: Optional[dict[str, AstVariable]] = None, namespace: Optional[str] = None
    ) -> None:
        self.name: str = name
        self.namespace: Optional[str] = namespace
        self.global_map: dict[str, AstVariable] = {} if global_map is None else global_map

    def copy(self) -> AstModule:
        copy_global_map = {}
        for name, item in self.global_map.items():
            copy_global_map[name] = item
        return AstModule(self.name, copy_global_map, self.namespace)


class AstCallableFunction(Copyable):
    def __init__(self, name: str, namespace: Optional[str] = None) -> None:
        self.name: str = name
        self.namespace: Optional[str] = namespace

    def action(self, function_node, analyzer, args, keywords, context):
        """Simulate function call here(eg: func_name()). Other arguments are same as below."""

    def copy(self) -> AstCallableFunction:
        """Immutable object, return callable function itself."""
        return self


# All builtin functions start with AstBuiltin prefix, they will be collected in ast-analyzer


class AstBuiltinFunction(Copyable):
    def __init__(self, name: str) -> None:
        self.name: str = name

    def action(self, function_node, analyzer, args, keywords, context):
        """
        Simulate builtin function call here, eg: __import__ function call.

        Args:
            function_node: current function node.
            analyzer: analyzer object.
            args: positional arguments parsed in AstVariable type.
            keywords: keyword arguments parsed in AstVariable type.
            context: local context.

        Returns:
            builtin function's return value, if builtin function doesn't have any return value, please return a dummy
                AstVariable, eg: AstVariable(None, set()).
        """

    def copy(self) -> AstBuiltinFunction:
        # immutable object, don't need to create a new object
        return self


class AstBuiltinOpenFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "open")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        return AstVariable(function_node, {"file"}, None)


class AstBuiltinEvalFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "eval")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        # Now eval has no side effect, just return a empty variable
        code_string = self._get_code_string(args, keywords)
        if code_string:
            # re-parse code_string
            try:
                expr_node = self._get_expr_ast_node(ast.parse(code_string))
            except SyntaxError:
                # bypass unexpected code string
                pass
            else:
                if expr_node:
                    # two possible risky usages
                    # 1. function call
                    # 2. variable assignation
                    ast_node = expr_node.value
                    return_variable = analyzer._get_variable_from_node(ast_node, context)  # pylint: disable=W0212
                    # special check for call nodes, since it is dangerous
                    for node in ast.walk(expr_node):
                        if isinstance(node, ast.Call):
                            modules = analyzer._get_modules_used_in_ast_name_and_attribute_chain(
                                node, context
                            )  # pylint: disable=W0212
                            analyzer._update_inverted_index_dict_with_key_set(
                                modules,
                                function_node,
                                analyzer._module_function_call_usage,
                            )  # pylint: disable=W0212
                    return return_variable
        return AstVariable(function_node, set(), None)

    @staticmethod
    def _get_expr_ast_node(ast_node: ast.AST) -> Optional[ast.Expr]:
        for node in ast.walk(ast_node):
            if isinstance(node, ast.Expr):
                return node
        return None

    @staticmethod
    def _get_code_string(
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
    ) -> Optional[str]:
        # First positional argument
        argument: AstVariable = args[0] if args else None
        if AstVariable.is_string(argument):
            return argument.variable_value

        return None


class AstBuiltinExecfileFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "execfile")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        # No side effect in execfile handler
        return AstVariable(function_node, set(), None)


class AstBuiltinFileFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "file")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        # No side effect in file handler
        return AstVariable(function_node, {"file"}, None)


class AstBuiltinMemoryViewFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "memoryview")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        # No side effect in memoryview handler
        return AstVariable(function_node, {"memoryview"}, None)


class AstBuiltinImportFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "__import__")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable | AstModule:
        import_name = self._get_imported_module_name(args, keywords)
        if import_name:
            module_names = import_name.split(".")
            # use first module name as imported module
            module_name = module_names[0]
            if analyzer.module_manager:
                modules: list[AstModule] = analyzer.module_manager.load_modules(module_name)
                if modules:
                    # Here `__import__` is very similar to `import`
                    # Only one module should be loaded
                    assert len(modules) == 1
                    return modules[0]
            # collect all possible modules
            module_name_set = set()
            for i in range(len(module_names)):
                module_string = ".".join(module_names[0 : i + 1])
                module_name_set.add(module_string)
            return AstVariable(function_node, module_name_set)

        return AstVariable(function_node, set())

    @staticmethod
    def _get_imported_module_name(args: list[AstVariable], keywords: dict[str, AstVariable]) -> Optional[str]:
        if args:
            arg = args[0]
            if AstVariable.is_string(arg):
                return arg.variable_value
        if "name" in keywords:
            arg = keywords["name"]
            if AstVariable.is_string(arg):
                return arg.variable_value
        return None


class AstBuiltinGetattrFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "getattr")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:  # noqa: C901
        node: Optional[AstVariable] = None
        attribute_name: Optional[str] = None
        default_value: Optional[AstVariable] = None
        # check arg first
        if len(args) > 0:
            node = args[0]
        if len(args) > 1 and AstVariable.is_string(args[1]):
            attribute_name = args[1].variable_value
        if len(args) > 2:
            default_value = args[2]
        # then check keyword
        if "object" in keywords:
            node = keywords["object"]
        if "name" in keywords and AstVariable.is_string(keywords["name"]):
            attribute_name = keywords["name"].variable_value
        if "default" in keywords:
            default_value = keywords["default"]
        # attribute name and node are available
        if attribute_name and node:
            # if it is a class
            if AstVariable.is_class_instance(node) and attribute_name in node.variable_value.class_context.variable_map:
                return node.variable_value.class_context.variable_map[attribute_name]

            if isinstance(node, AstClass) and attribute_name in node.class_context.variable_map:
                return node.class_context.variable_map[attribute_name]

            # if it is a module
            if AstVariable.is_module(node) and attribute_name in node.variable_value.global_map:
                return node.variable_value.global_map[attribute_name]

            if isinstance(node, AstModule) and attribute_name in node.global_map:
                return node.global_map[attribute_name]

            if default_value:
                return default_value

            type_set = set()
            # collect modules used in variable
            if isinstance(node, AstVariable):
                for variable_type in node.variable_type_set - set(AstVariable.SPECIAL_TYPES):
                    type_set.add(variable_type + "." + attribute_name)
                if AstVariable.is_class_instance(node):
                    for variable_type in node.variable_value.modules - set(AstVariable.SPECIAL_TYPES):
                        type_set.add(variable_type + "." + attribute_name)
            # collect modules used in AstClass
            elif isinstance(node, AstClass):
                for variable_type in node.modules - set(AstVariable.SPECIAL_TYPES):
                    type_set.add(variable_type + "." + attribute_name)

            return AstVariable(function_node, type_set, None)

        # return a variable without any types
        return AstVariable(function_node, set(), None)


class AstBuiltinSetattrFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "setattr")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        node: Optional[AstVariable] = None
        attribute_name: Optional[str] = None
        value: Optional[AstVariable] = None
        # first check args
        if len(args) > 0:
            node = args[0]
        if len(args) > 1 and AstVariable.is_string(args[1]):
            attribute_name = args[1].variable_value
        if len(args) > 2:
            value = args[2]
        # then check keywords
        if "object" in keywords:
            node = keywords["object"]
        if "name" in keywords and AstVariable.is_string(keywords["name"]):
            attribute_name = keywords["name"].variable_value
        if "value" in keywords:
            value = keywords["value"]
        if attribute_name and node:
            if AstVariable.is_class_instance(node):
                node.variable_value.class_context.variable_map[attribute_name] = value
            elif isinstance(node, AstClass):
                node.class_context.variable_map[attribute_name] = value
            elif AstVariable.is_module(node):
                node.variable_value.global_map[attribute_name] = value
            elif isinstance(node, AstModule):
                node.global_map[attribute_name] = value
        # return a variable without any types
        return AstVariable(function_node, set(), None)


class AstBuiltinDelattrFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "delattr")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        node: Optional[AstVariable] = None
        attribute_name: Optional[str] = None
        if len(args) > 0:
            node = args[0]
        if len(args) > 1 and AstVariable.is_string(args[1]):
            attribute_name = args[1].variable_value
        if "object" in keywords:
            node = keywords["object"]
        if "name" in keywords and AstVariable.is_string(keywords["name"]):
            attribute_name = keywords["name"].variable_value

        if node and attribute_name:
            if AstVariable.is_class_instance(node):
                if attribute_name in node.variable_value.class_context.variable_map:
                    del node.variable_value.class_context.variable_map[attribute_name]
            elif isinstance(node, AstClass):
                if attribute_name in node.class_context.variable_map:
                    del node.class_context.variable_map[attribute_name]
            elif AstVariable.is_module(node):
                if attribute_name in node.variable_value.global_map:
                    del node.variable_value.global_map[attribute_name]
            elif isinstance(node, AstModule):
                if attribute_name in node.global_map:
                    del node.global_map[attribute_name]

        return AstVariable(function_node, set(), None)


class AstBuiltinSuperFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "super")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        # collect all possible modules from argument nodes
        module_set = set()
        for arg in args:
            if isinstance(arg, AstVariable):
                module_set |= arg.variable_type_set
                arg = arg.variable_value
            # for class and module, some special collection
            if isinstance(arg, AstClass):
                module_set |= arg.modules
            elif isinstance(arg, AstBuiltinFunction):
                # `builtin type` and `builtin.func_name`
                module_set |= {
                    AstVariable.BUILTIN_TYPE,
                    AstVariable.BUILTIN_TYPE + "." + arg.name,
                }
            if getattr(arg, "namespace", None):
                names = arg.namespace.split(".")
                for j in range(len(names)):
                    module_string = ".".join(names[: j + 1])
                    module_set.add(module_string)
        module_set -= set(AstVariable.SPECIAL_TYPES)
        return AstVariable(function_node, module_set)


class AstBuiltinApplyFunction(AstBuiltinFunction):
    def __init__(self) -> None:
        AstBuiltinFunction.__init__(self, "apply")

    def action(
        self,
        function_node: ast.Call,
        analyzer: "AstAnalyzer",
        args: list[AstVariable],
        keywords: dict[str, AstVariable],
        context: AstContext,
    ) -> AstVariable:
        if function_node.args:
            type_set = analyzer._get_modules_used_in_ast_name_and_attribute_chain(
                function_node.args[0], context
            )  # pylint: disable=W0212
            # update possible function call usages
            analyzer._update_inverted_index_dict_with_key_set(
                type_set, function_node, analyzer._module_function_call_usage
            )  # pylint: disable=W0212
        # return a variable without any types
        return AstVariable(function_node, set(), None)


class AstContext(Copyable):
    # parse from top to bottom
    PARSING_MODE = "parsing"
    # simulate function calls
    SIMULATE_MODE = "simulate"
    # collect all possible variable types in this mode, used to handle if-else statement
    COLLECT_MODE = "collect"

    def __init__(self, level: int, root_node: ast.AST, parent_context: Optional[AstContext] = None) -> None:
        self.variable_map: dict[str, AstVariable] = {}
        # current namespace
        self.namespace: str = ""

        self.level: int = level
        self.root_node: ast.AST = root_node
        self.parent_context: Optional[AstContext] = parent_context

        self.context_mode: str = self.PARSING_MODE

    def copy(self) -> AstContext:
        context = AstContext(self.level, self.root_node, self.parent_context)
        # copy variable map
        context.variable_map = dict()
        for variable_name, ast_variable in self.variable_map.items():
            context.variable_map[variable_name] = ast_variable
        # copy namespace
        context.namespace = copy.deepcopy(self.namespace)
        # copy context mode
        context.context_mode = copy.deepcopy(self.context_mode)

        return context
