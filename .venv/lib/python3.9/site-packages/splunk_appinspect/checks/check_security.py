# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Security vulnerabilities
"""
from __future__ import annotations

import ast
import logging
import os
import platform
import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

import splunk_appinspect
from splunk_appinspect.check_routine.python_ast_searcher.ast_searcher import AstSearcher
from splunk_appinspect.constants import Tags
from splunk_appinspect.python_analyzer.ast_types import AstVariable
from splunk_appinspect.python_modules_metadata.metadata_common import metadata_consts
from splunk_appinspect.python_modules_metadata.python_modules_metadata_store import metadata_store
from splunk_appinspect.regex_matcher import SecretDisclosureInAllFilesMatcher, SecretDisclosureInNonPythonFilesMatcher

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.python_analyzer.ast_analyzer import AstAnalyzer
    from splunk_appinspect.reporter import Reporter


logger = logging.getLogger(__name__)
report_display_order = 5

potentially_dangerous_windows_filetypes = [
    ".cmd",
    ".ps1",
    ".bat",
    ".ps2",
    ".ws",
    ".wsf",
    ".psc1",
    ".psc2",
]


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_pexpect(app: "App", reporter: "Reporter") -> None:
    """Check for use of `pexpect` to ensure it is only controlling app
    processes.
    """
    for match in app.search_for_pattern("pexpect.run", types=[".py"]):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = f"Possible use of pexpect- detected in {match[0]}. " f"File: {filename}, Line: {line}."
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_secret_disclosure(app: "App", reporter: "Reporter") -> None:
    """Check for passwords and secrets."""
    # the messages in props.conf or transforms.conf need to filter by _secret_disclosure_commands_allow_list
    # extract the messages with the structure: {file_path: {lineno: [result1, result2]}}
    messages_in_special_files = {}
    special_files = [
        Path("default", "props.conf"),
        Path("default", "transforms.conf"),
    ]
    conditional_excluded_paths = tuple(
        [
            os.path.join("default", "data", "ui", "views"),
            os.path.join("local", "data", "ui", "views"),
            os.path.join("default", "data", "ui", "panels"),
            os.path.join("local", "data", "ui", "panels"),
        ]
    )

    dashboard_token_keyword = "token"

    # general regex patterns
    matcher = SecretDisclosureInAllFilesMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir, app.iterate_files(skip_compiled_binaries=True)
    ):
        # extract the messages in props.conf or transforms.conf and combine them
        if file_path in special_files:
            _combine_messages_in_special_files(file_path, lineno, result, messages_in_special_files)
            continue
        if _secret_disclosure_values_allow_list(result):
            continue
        if dashboard_token_keyword in result and str(file_path).startswith(conditional_excluded_paths):
            continue
        reporter_output = (
            "The following line will be inspected during code review. "
            "Possible secret disclosure found."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.manual_check(reporter_output, file_path, lineno)

    # regex patterns target non-python files, python files would be covered in check_python_files
    matcher = SecretDisclosureInNonPythonFilesMatcher()
    for result, file_path, lineno in matcher.match_results_iterator(
        app.app_dir, app.iterate_files(excluded_types=[".py"], skip_compiled_binaries=True)
    ):
        # extract the messages in props.conf or transforms.conf and combine them
        if file_path in special_files:
            _combine_messages_in_special_files(file_path, lineno, result, messages_in_special_files)
            continue
        if _secret_disclosure_values_allow_list(result):
            continue
        if _secret_disclosure_values_savedsearches_allowlist(file_path, result):
            continue
        if dashboard_token_keyword in result and str(file_path).startswith(conditional_excluded_paths):
            continue
        reporter_output = (
            "The following line will be inspected during code review."
            "Possible secret disclosure found."
            f" Match: {result}"
            f" File: {file_path}"
            f" Line: {lineno}"
        )
        reporter.manual_check(reporter_output, file_path, lineno)

    # process the messages_in_props_or_transforms_file: {file_path: {lineno: [result1, result2]}}
    for file_path, messages in messages_in_special_files.items():
        for lineno, results in messages.items():
            if _secret_disclosure_commands_allow_list(file_path, results):
                continue
            for result in results:
                if _secret_disclosure_values_allow_list(result):
                    continue
                reporter_output = (
                    "The following line will be inspected during code review."
                    "Possible secret disclosure found."
                    f" Match: {result}"
                    f" File: {file_path}"
                    f" Line: {lineno}"
                )
                reporter.manual_check(reporter_output, file_path, lineno)


def _secret_disclosure_values_allow_list(line_message: str) -> bool:
    """
    Args:
        line_message: the line message matched by secret_patterns regex in check_for_secret_disclosure

    """
    # if the secret credential is equal to following values, then pass
    values_allow_list = [
        "value",
        "string",
        "not_set",
        "str",
        "password",
        "enabled",
        "true",
        "false",
        "Enter",
        "YourSecretPassword",
        "YOUR_ADMIN_PASSWORD",
        "undefined",
        "received",
        "self",
        "changeme",
        "Heavy",
        "null",
        "0+",
        "x+",
        "X+",
        r"\*+",
        r"\^+",
    ]
    # (?i) case insensitive
    values_patterns = (
        r"((?i)((?:(key|pass|pwd|token|login|passwd|password|community|privpass))[ ]{0,10}=[ ]{0,10}((<|\"|\'|\\\"|\\\')?(%s)(>|\"|\'|\\\"|\\\')?)$))"
        % ("|".join(values_allow_list))
    )
    if re.search(values_patterns, line_message):
        return True

    key_value_set = {
        "change_own_password": "(enabled|disabled)",
    }
    for key, value in key_value_set.items():
        if re.match(
            rf"\s*{key}\s*=\s*((<|\"|\'|\\\"|\\\')?{value}(>|\"|\'|\\\"|\\\')?)\s*",
            line_message,
        ):
            return True

    return False


def _secret_disclosure_values_savedsearches_allowlist(file_path: Path, line_message: str) -> bool:
    savedsearches_files = [
        Path("default", "savedsearches.conf"),
        Path("local", "savedsearches.conf"),
    ]
    if file_path not in savedsearches_files:
        return False

    if re.match(
        r"\s*(alert.[\w-]+.params.[\w-]+)\s*=\s*((<|\"|\'|\\\"|\\\')?([\w]+)(>|\"|\'|\\\"|\\\')?)\s*",
        line_message,
    ):
        return False

    return True


def _conf_options_secret_disclosure_allow_list(file_path: Path, line_message: str) -> bool:
    """
    Checks if the line message matched by the secret disclosure regex is an allow listed configuration option.

    Args:
        file_path: the file path of this matched line
        line_message: the line message matched by secret_patterns regex in check_for_secret_disclosure

    """

    # List of all configuration files and the options that have been allowed
    conf_options_allow_list = {Path("default", "savedsearches.conf"): ["action.email.show_password"]}

    # Iterate through each configuration file that have allowed options and
    # check to see if it matches the line message
    for configuration_file, allow_list_options in conf_options_allow_list.items():
        if file_path == configuration_file:
            for allow_list_option in allow_list_options:
                if re.search(allow_list_option, line_message):
                    return True

    return False


def _secret_disclosure_commands_allow_list(file_path: Path, messages: list[str]) -> bool:
    """
    Args:
        file_path: the file path of this matched line
        messages: the message list in one line matched by secret_patterns regex in check_for_secret_disclosure
            the structure is [message1, message2]

    """

    # if the line begins with following commands in props.conf and transforms.conf, then pass
    # In props.conf e.g. SEDCMD-<class>, EXTRACT-<classs>, REPORT-<class>, TRANSFORMS-<class>, LOOKUP-<class>,
    # EVAL-<class>, FIELDALIAS-<class>
    # In transforms.conf, e.g. REGEX=, FORMAT=

    commands_allow_list_in_props_file = [
        "SEDCMD-",
        "EXTRACT-",
        "REPORT-",
        "TRANSFORMS-",
        "LOOKUP[-|_]?",
        "lookup[-|_]?",
        "EVAL-",
        "FIELDALIAS-",
    ]
    commands_allow_list_in_transforms_file = ["REGEX[ ]*=", "FORMAT[ ]*="]

    if file_path == Path("default", "props.conf"):
        commands_patterns = r"(^(?=%s))" % ("|".join(commands_allow_list_in_props_file))
    elif file_path == Path("default", "transforms.conf"):
        commands_patterns = r"(^(?=%s))" % ("|".join(commands_allow_list_in_transforms_file))
    else:
        # the filename is not valid
        return False

    for message in messages:
        if re.search(commands_patterns, message):
            return True

    return False


def _combine_messages_in_special_files(
    file_path: Path, lineno: int | str, result: str, messages_in_special_files: dict[dict[Path, list[str]]]
) -> None:
    """
    Combine the messages and update the messages_in_special_files

    Args:
        file_path:
        lineno:
        result:
        messages_in_special_files: the structure is {file_path: {lineno: [result1, result2]}}

    """
    if file_path in messages_in_special_files.keys():
        if lineno in messages_in_special_files[file_path].keys():
            messages_in_special_files[file_path][lineno].append(result)
        else:
            messages_in_special_files[file_path][lineno] = [result]
    else:
        message = {lineno: [result]}
        messages_in_special_files[file_path] = message


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SECURITY,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.6.1")
def check_for_sensitive_info_in_url(app: "App", reporter: "Reporter") -> None:
    """Check for sensitive information being exposed in transit via URL query string parameters"""
    sensitive_info_patterns = (
        r"((?i)[ \f\r\t\v]*[0-9a-z_\.]*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=[ \f\r\t\v]*[\"\']?https?://[^\"\'\s]*?(key|pass|pwd|token)[0-9a-z]*=[^&\"\'\s]+[\"\']?|"  # Single line url
        r"[ \f\r\t\v]*[0-9a-z_\.]*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=[ \f\r\t\v]*([\"\']\{\}://\{\}:\{\}@\{\}:\{\}[\"\'])\.format\([^\)]*(key|password|pass|pwd|token|cridential|secret|login|auth)[^\)]*\))"
    )  # Multi line url

    sensitive_info_patterns_for_report = (
        r"((?i)[0-9a-z_\.]*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=[ \f\r\t\v]*[\"\']?https?://[^\"\'\s]*?(key|pass|pwd|token)[0-9a-z]*=[^&\"\'\s]+[\"\']?|"  # Single line url
        r"[0-9a-z_\.]*(url|uri|host|server|prox|proxy_str)s?[ \f\r\t\v]*=[ \f\r\t\v]*([\"\']\{\}://\{\}:\{\}@\{\}:\{\}[\"\'])\.format\([^\)]*(key|password|pass|pwd|token|cridential|secret|login|auth)[^\)]*\))"
    )  # Multi line url

    for match in app.search_for_crossline_pattern(pattern=sensitive_info_patterns, cross_line=5):
        filename, line = match[0].rsplit(":", 1)
        # handle massage
        for rx in [re.compile(p) for p in [sensitive_info_patterns_for_report]]:
            for p_match in rx.finditer(match[1].group()):
                description = p_match.group()
                reporter_output = (
                    f"Possible sensitive information being exposed via URL in {match[0]}: {description}."
                    f" File: {filename}, Line: {line}."
                )
                reporter.warn(reporter_output, filename, line)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_vbs_command_injection(app: "App", reporter: "Reporter") -> None:
    """Check for command injection in VBS files."""
    for match in app.search_for_pattern("Shell.*Exec", types=[".vbs"]):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = (
            f"Possible command injection in {match[0]}: {match[1].group()}. " f"File: {filename}, Line: {line}."
        )
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_command_injection_through_env_vars(app: "App", reporter: "Reporter") -> None:
    """Check for command injection through environment variables."""
    for match in app.search_for_pattern("start.*%", types=potentially_dangerous_windows_filetypes):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = (
            f"Possible command injection in {match[0]}: {match[1].group()}. " f"File: {filename}, Line: {line}."
        )
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.CLOUD, Tags.MANUAL, Tags.AST)
@splunk_appinspect.cert_version(min="1.7.0")
def check_for_insecure_http_calls_in_python(app: "App", reporter: "Reporter") -> None:
    """Check for insecure HTTP calls in Python."""
    report_template = (
        "Possible insecure HTTP Connection." " Match: {}" " Positional arguments, {}; Keyword arguments, {}"
    )

    query = metadata_store.query().tag(metadata_consts.TagConsts.HTTP_CONNECTION).python_compatible()

    def is_secure_var(var: ast.Constant, ast_info: "AstAnalyzer") -> bool:
        variable = ast_info.get_variable_details(var)
        return AstVariable.is_string(variable) and variable.variable_value.startswith("https")

    def is_arg_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        # check if https prefix is found
        is_secure = False
        # only pay attention to first two arguments, url will always be included
        for arg in call_node.args[:2]:
            is_secure = is_secure_var(arg, ast_info)
            if is_secure:
                break
        return is_secure

    def is_keyword_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        is_secure = False
        possible_argument_keys = {"url", "fullurl", "host"}
        for keyword in call_node.keywords:
            if keyword.arg in possible_argument_keys:
                is_secure = is_secure_var(keyword.value, ast_info)
                if is_secure:
                    break
        return is_secure

    def is_arg_secure_or_keyword_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        return not is_arg_secure(call_node, ast_info) and not is_keyword_secure(call_node, ast_info)

    components = query.functions() + query.classes()
    files_with_results = AstSearcher(app.python_analyzer_client).search(
        components, node_filter=is_arg_secure_or_keyword_secure, get_func_params=True
    )
    reporter.ast_manual_check(report_template, files_with_results)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SECURITY,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_CLASSIC,
    Tags.PRIVATE_VICTORIA,
    Tags.AST,
    Tags.MIGRATION_VICTORIA,
)
@splunk_appinspect.cert_version(min="2.37.0")
def check_for_insecure_http_calls_in_python_private(app: "App", reporter: "Reporter") -> None:
    """Check for insecure HTTP calls in Python."""
    report_template = "Insecure HTTP Connection found" " Match: {}" " Positional arguments, {}; Keyword arguments, {}"

    query = metadata_store.query().tag(metadata_consts.TagConsts.HTTP_CONNECTION).python_compatible()

    def is_not_secure_var(var, ast_info: "AstAnalyzer") -> bool:
        variable = ast_info.get_variable_details(var)
        return AstVariable.is_string(variable) and not variable.variable_value.startswith("https")

    def is_arg_not_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        # check if https prefix is found
        is_not_secure = False
        # only pay attention to first two arguments, url will always be included
        for arg in call_node.args[:2]:
            is_not_secure = is_not_secure_var(arg, ast_info)
            if is_not_secure:
                break
        return is_not_secure

    def is_keyword_not_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        is_not_secure = False
        possible_argument_keys = {"url", "fullurl", "host"}
        for keyword in call_node.keywords:
            if keyword.arg in possible_argument_keys:
                is_not_secure = is_not_secure_var(keyword.value, ast_info)
                if is_not_secure:
                    break
        return is_not_secure

    def is_arg_secure_or_keyword_secure(call_node: ast.Call, ast_info: "AstAnalyzer") -> bool:
        return is_arg_not_secure(call_node, ast_info) or is_keyword_not_secure(call_node, ast_info)

    components = query.functions() + query.classes()
    if len(components) > 0:
        files_with_results = AstSearcher(app.python_analyzer_client).search(
            components, node_filter=is_arg_secure_or_keyword_secure, get_func_params=True
        )
        reporter.ast_warn(report_template, files_with_results)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_stacktrace_returned_to_user(app: "App", reporter: "Reporter") -> None:
    """Check that stack traces are not being returned to an end user."""
    for match in app.search_for_pattern("format_exc", types=[".py"]):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = (
            f"Stacktrace being formatted in {match[0]}: {match[1].group()}. " f"File: {filename}, Line: {line}."
        )
        reporter.manual_check(reporter_output, filename, line)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SECURITY, Tags.CLOUD, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.1.0")
def check_for_environment_variable_use_in_python(app: "App", reporter: "Reporter") -> None:
    """Check for environment variable manipulation and attempts to monitor
    sensitive environment variables."""
    # Catch `os.environ.get(` or `os.getenv(` but allow for `"SPLUNK_HOME` or
    # `'SPLUNK_HOME`
    # Catch `os.environ` other than `os.environ.get` (which is covered above)
    env_manual_regex = (
        r"((os[\s]*\.[\s]*environ[\s]*\.[\s]*get)"
        r"|(os[\s]*\.[\s]*getenv))"
        r"(?![\s]*\([\s]*[\'\"]SPLUNK\_HOME)"
        r"|(os[\s]*\.[\s]*environ(?![\s]*\.[\s]*get))"
    )
    for match in app.search_for_pattern(env_manual_regex, types=[".py"]):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = (
            f"Environment variable being used in {match[0]}: {match[1].group()}. " f"File: {filename}, Line: {line}."
        )
        reporter.manual_check(reporter_output, filename, line)
    # Fail for use of `os.putenv` / `os.unsetenv` in any scenario
    env_set_regex = r"(os[\s]*\.[\s]*putenv|os[\s]*\.[\s]*unsetenv)"
    for match in app.search_for_pattern(env_set_regex, types=[".py"]):
        filename, line = match[0].rsplit(":", 1)
        reporter_output = (
            f"Environment variable manipulation detected in {match[0]}: {match[1].group()}."
            f"File: {filename}, Line: {line}."
        )
        reporter.fail(reporter_output, filename, line)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.SECURITY,
    Tags.CLOUD,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="1.5.2")
def check_symlink_outside_app(app: "App", reporter: "Reporter") -> None:
    """Check no symlink points to the file outside this app"""
    if platform.system() == "Windows":
        reporter_output = "Please run AppInspect using another OS to enable this check. Or use AppInspect API."
        reporter.warn(reporter_output)
    else:
        for basedir, file, _ in app.iterate_files():
            app_file_path = Path(basedir, file)
            full_file_path = app.get_filename(app_file_path)
            # it is a symbolic link file
            if os.path.islink(full_file_path):
                # For python 2.x, os.path.islink will always return False in windows
                # both of them are absolute paths
                link_to_absolute_path = os.path.abspath(Path(full_file_path).resolve())
                # link to outer path
                # FIXME: change to is_relative_to(app_root_dir) after upgrading to python 3.9
                if not link_to_absolute_path.startswith(str(app.app_dir)):
                    reporter_output = (
                        f"Link file found in path: {full_file_path}. The file links to a path "
                        f"outside of this app, the link path is: {link_to_absolute_path}. "
                        f"File: {app_file_path}"
                    )
                    reporter.fail(reporter_output, app_file_path)


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.PRIVATE_APP,
    Tags.SPLUNK_9_0,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
    Tags.PURA,
)
@splunk_appinspect.cert_version(min="2.17.0")
def check_for_supported_tls_private(app: "App", reporter: "Reporter") -> None:
    """Check that all outgoing connections use TLS in accordance to Splunk Cloud Platform policy."""
    client = app.python_analyzer_client
    internals_addresses = ["localhost", "127.0.0.1", "::1"]
    protocols = ["http://", "https://"]
    allowed_urls = [protocol + internal_address for protocol in protocols for internal_address in internals_addresses]
    allowed_urls = allowed_urls + internals_addresses
    allowed_urls = tuple(allowed_urls)

    def _report_if_all_kwrgs_found(
        ast_info: "AstAnalyzer",
        file_path: Path,
        reporter: "Reporter",
        lib_name: str,
        url_param_index: int,
        url_param_key: str,
        check_kwrgs: dict[str, Any],
    ) -> None:
        usages = ast_info.get_module_function_call_usage(lib_name, fuzzy=True)
        for usage in usages:
            is_local = False
            find_count = 0
            variable_count = 0
            is_url_variable = False
            if hasattr(usage, "keywords"):
                for keyword in usage.keywords:
                    if hasattr(keyword, "arg") and hasattr(keyword, "value") and hasattr(keyword.value, "value"):
                        for k, v in check_kwrgs.items():
                            if keyword.arg == k and keyword.value.value == v:
                                find_count = find_count + 1
                        if (
                            keyword.arg == url_param_key
                            and keyword.value.value
                            and (isinstance(keyword.value.value, ast.Constant) or isinstance(keyword.value.value, str))
                            and keyword.value.value.startswith(allowed_urls)
                        ):
                            is_local = True
                    elif hasattr(keyword, "arg"):
                        for k, v in check_kwrgs.items():
                            if keyword.arg == k:
                                variable_count = variable_count + 1
                        if keyword.arg == url_param_key:
                            is_url_variable = True
            if (
                hasattr(usage, "args")
                and len(usage.args) >= url_param_index + 1
                and hasattr(usage.args[url_param_index], "value")
                and usage.args[url_param_index].value
                and (
                    isinstance(usage.args[url_param_index].value, ast.Constant)
                    or isinstance(usage.args[url_param_index].value, str)
                )
                and usage.args[url_param_index].value.startswith(allowed_urls)
            ):
                is_local = True
            elif (
                hasattr(usage, "args")
                and len(usage.args) >= url_param_index + 1
                and not hasattr(usage.args[url_param_index], "value")
            ):
                is_url_variable = True

            if find_count != len(check_kwrgs) and variable_count == 0:
                continue
            if is_local and not is_url_variable:
                reporter_output = "The SSL certificate validation is disabled for communication with itself. Ensure the SSL certificate validation for commmunications with outside the Splunk Cloud stack. This can be done by specifying the relevant parameters (verify, cafile etc) to True or the certificate path."
                reporter.warn(reporter_output, file_path, usage.lineno)
            else:
                reporter_output = "The SSL certificate validation is disabled. Enable the SSL certificate validation for commmunications with outside the Splunk Cloud stack. This can be done by specifying the relevant parameters (verify, cafile etc) to True or the certificate path."
                reporter.warn(reporter_output, file_path, usage.lineno)

    for file_path, ast_info in client.get_all_ast_infos():
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "http.client.HTTPSConnection",
            0,
            "host",
            {"cert_file": None},
        )
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "urllib.request.urlopen",
            0,
            "url",
            {
                "cafile": None,
                "capath": None,
            },
        )
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "httplib2.Http",
            0,
            "uri",
            {"disable_ssl_certificate_validation": True},
        )
        for request_method in (
            "requests.request",
            "requests.get",
            "requests.post",
            "requests.patch",
            "requests.put",
        ):
            param_index = 0
            if request_method == "requests.request":
                param_index = 1
            _report_if_all_kwrgs_found(
                ast_info, file_path, reporter, request_method, param_index, "url", {"verify": False}
            )


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.SPLUNK_9_0, Tags.PURA, Tags.MANUAL)
@splunk_appinspect.cert_version(min="2.37.0")
def check_for_supported_tls(app: "App", reporter: "Reporter") -> None:
    """Check that all outgoing connections use TLS in accordance to Splunk Cloud Platform policy."""
    client = app.python_analyzer_client
    internals_addresses = ["localhost", "127.0.0.1", "::1"]
    protocols = ["http://", "https://"]
    allowed_urls = [protocol + internal_address for protocol in protocols for internal_address in internals_addresses]
    allowed_urls = allowed_urls + internals_addresses
    allowed_urls = tuple(allowed_urls)

    def _report_if_all_kwrgs_found(
        ast_info: "AstAnalyzer",
        file_path: Path,
        reporter: "Reporter",
        lib_name: str,
        url_param_index: int,
        url_param_key: str,
        check_kwrgs: dict[str, Any],
    ) -> None:
        usages = ast_info.get_module_function_call_usage(lib_name, fuzzy=True)
        for usage in usages:
            is_local = False
            find_count = 0
            variable_count = 0
            is_url_variable = False
            if hasattr(usage, "keywords"):
                for keyword in usage.keywords:
                    if hasattr(keyword, "arg") and hasattr(keyword, "value") and hasattr(keyword.value, "value"):
                        for k, v in check_kwrgs.items():
                            if keyword.arg == k and keyword.value.value == v:
                                find_count = find_count + 1
                        if (
                            keyword.arg == url_param_key
                            and keyword.value.value
                            and (isinstance(keyword.value.value, ast.Constant) or isinstance(keyword.value.value, str))
                            and keyword.value.value.startswith(allowed_urls)
                        ):
                            is_local = True
                    elif hasattr(keyword, "arg"):
                        for k, v in check_kwrgs.items():
                            if keyword.arg == k:
                                variable_count = variable_count + 1
                        if keyword.arg == url_param_key:
                            is_url_variable = True
            if (
                hasattr(usage, "args")
                and len(usage.args) >= url_param_index + 1
                and hasattr(usage.args[url_param_index], "value")
                and usage.args[url_param_index].value
                and (
                    isinstance(usage.args[url_param_index].value, ast.Constant)
                    or isinstance(usage.args[url_param_index].value, str)
                )
                and usage.args[url_param_index].value.startswith(allowed_urls)
            ):
                is_local = True
            elif (
                hasattr(usage, "args")
                and len(usage.args) >= url_param_index + 1
                and not hasattr(usage.args[url_param_index], "value")
            ):
                is_url_variable = True

            if (find_count == len(check_kwrgs) and variable_count == 0) and (not is_local and not is_url_variable):
                reporter_output = "The SSL certificate validation is disabled. Enable the SSL certificate validation for commmunications with outside the Splunk Cloud stack. This can be done by specifying the relevant parameters (verify, cafile etc) to True or the certificate path."
                if lib_name == "httplib2.Http":
                    reporter.manual_check(reporter_output, file_path, usage.lineno)
                else:
                    reporter.fail(reporter_output, file_path, usage.lineno)
            elif (is_local and not is_url_variable) or (find_count != len(check_kwrgs) and variable_count == 0):
                continue
            else:
                reporter_output = "Ensure that the SSL certificate validation for commmunications with outside the Splunk Cloud stack is enabled. This can be done by specifying the relevant parameters (verify, cafile etc) to True or the certificate path."
                reporter.manual_check(reporter_output, file_path, usage.lineno)

    for file_path, ast_info in client.get_all_ast_infos():
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "http.client.HTTPSConnection",
            0,
            "host",
            {"cert_file": None},
        )
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "urllib.request.urlopen",
            0,
            "url",
            {
                "cafile": None,
                "capath": None,
            },
        )
        _report_if_all_kwrgs_found(
            ast_info,
            file_path,
            reporter,
            "httplib2.Http",
            0,
            "uri",
            {"disable_ssl_certificate_validation": True},
        )
        for request_method in (
            "requests.request",
            "requests.get",
            "requests.post",
            "requests.patch",
            "requests.put",
        ):
            param_index = 0
            if request_method == "requests.request":
                param_index = 1
            _report_if_all_kwrgs_found(
                ast_info, file_path, reporter, request_method, param_index, "url", {"verify": False}
            )
