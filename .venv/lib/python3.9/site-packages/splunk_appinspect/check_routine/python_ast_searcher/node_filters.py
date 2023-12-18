"""
Sets of pre-defined node filters
"""

import ast
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from splunk_appinspect.python_analyzer.ast_analyzer import AstAnalyzer


def is_sub_class_def(node: ast.AST, ast_info: "AstAnalyzer") -> bool:
    """Subclass filter to identify if parent node of node is of ast.ClassDef instance."""
    parent_node = ast_info.get_parent_ast_node(node)
    return isinstance(parent_node, ast.ClassDef)
