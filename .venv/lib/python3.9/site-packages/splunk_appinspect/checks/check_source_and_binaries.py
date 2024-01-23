# Copyright 2019 Splunk Inc. All rights reserved.

"""
### Source code and binaries standards
"""

# TODO: Provide url link to the criteria here in the docstring
from __future__ import annotations

import logging
import os
import platform
import re
import stat
from pathlib import Path
from typing import TYPE_CHECKING

import magic

import splunk_appinspect
import splunk_appinspect.check_routine as check_routine
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


if platform.system() == "Windows":
    import ntsecuritycon as con  # pylint: disable=E0401
    import win32security  # pylint: disable=E0401

logger = logging.getLogger(__name__)
report_display_order = 5


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.CLOUD, Tags.PRIVATE_APP, Tags.PRIVATE_CLASSIC)
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_bin_files(app: "App", reporter: "Reporter") -> None:
    """Check that files outside of the `bin/` and `appserver/controllers` directory do not have execute
    permissions.
    Splunk Cloud is a Linux-based platform, Splunk recommends 644 for all app files outside of the `bin/` directory, 644 for
    scripts within the `bin/` directory that are invoked using an interpreter (e.g. `python my_script.py`
    or `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are invoked directly
    (e.g. `./my_script.sh` or `./my_script`).
    """
    directories_to_exclude_from_root = ["bin"]
    for dir, filename, ext in app.iterate_files(excluded_dirs=directories_to_exclude_from_root):
        if dir == Path("appserver", "controllers"):
            continue
        current_file_relative_path = Path(dir, filename)
        current_file_full_path = app.get_filename(current_file_relative_path)
        file_statistics = current_file_full_path.stat()
        # Checks the file's permissions against execute flags to see if the file
        # is executable
        if bool(file_statistics.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)):
            reporter.fail(
                "This file has execute permissions for owners, groups, or others. "
                f"File: {current_file_relative_path}",
                current_file_relative_path,
            )


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL, Tags.CLOUD)
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_executable_flag(app: "App", reporter: "Reporter") -> None:
    """Check that files outside of the `bin/` directory do not appear to be
    executable according to the Unix `file` command. From `man file`: files have
    a ``magic number'' stored in a particular place near the beginning of the
    file that tells the UNIX operating system that the file is a binary
    executable."""
    if platform.system() == "Windows":
        # TODO: tests needed
        reporter_output = "Windows file permissions will be inspected during review."
        reporter.manual_check(reporter_output)
    else:
        directories_to_exclude = ["bin"]
        for directory, file, ext in app.iterate_files(excluded_dirs=directories_to_exclude):
            # filter appserver/controllers/ out
            if directory == Path("appserver/controllers"):
                continue
            current_file_relative_path = Path(directory, file)
            current_file_full_path = app.get_filename(current_file_relative_path)
            if current_file_relative_path in app.info_from_file:
                file_output = app.info_from_file[current_file_relative_path]
            else:
                with open(current_file_full_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_output = magic.from_buffer(f.read())
            file_output_regex = re.compile("(.)*executable(.)*", re.DOTALL | re.IGNORECASE | re.MULTILINE)
            if re.match(file_output_regex, file_output):
                if current_file_relative_path.name.endswith((".html", ".htm")):
                    if check_routine.is_mako_template(current_file_full_path):
                        continue
                reporter_output = (
                    "The executable will be inspected during code review: " f"File: {current_file_relative_path}"
                )
                reporter.manual_check(reporter_output, current_file_relative_path)


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.WINDOWS)
@splunk_appinspect.cert_version(min="1.0.0")
def check_for_expansive_permissions(app: "App", reporter: "Reporter") -> None:
    """Check that no files have *nix write permissions for all users
    (xx2, xx6, xx7). Splunk recommends 644 for all app files outside of the
    `bin/` directory, 644 for scripts within the `bin/` directory that are
    invoked using an interpreter (e.g. `python my_script.py` or
    `sh my_script.sh`), and 755 for scripts within the `bin/` directory that are
    invoked directly (e.g. `./my_script.sh` or `./my_script`).
    Since appinspect 1.6.1, check that no files have nt write permissions for all users.
    """
    offending_files = []
    EXCLUDED_USERS_LIST = [
        "Administrators",
        "SYSTEM",
        "Authenticated Users",
        "Administrator",
    ]
    ACCESS_ALLOWED_ACE = 0
    for dir, file, ext in app.iterate_files():
        try:
            if os.name != "nt":
                st = app.get_filename(dir, file).stat()
                if bool(st.st_mode & stat.S_IWOTH):
                    offending_files.append(Path(dir, file))
            else:
                # full path in GetFileSecurity should be
                # the absolute path in Windows
                full_path = Path(app.app_dir, dir, file)
                file_owner = _get_windows_file_owner(full_path)
                for ace_type, user, access in _read_windows_file_ace(full_path):
                    # only need to consider AceType = ACCESS_ALLOWED_ACE
                    # not check users in EXCLUDED_USERS_LIST
                    if (
                        ace_type == ACCESS_ALLOWED_ACE
                        and user not in EXCLUDED_USERS_LIST
                        and user != file_owner
                        and _has_permission(access, con.FILE_GENERIC_WRITE)
                    ):
                        offending_files.append(full_path)
        except Exception:
            pass

    for offending_file in offending_files:
        reporter_output = f"A {os.name} world-writable file was found. File: {offending_file}"
        if os.name == "nt":
            reporter.warn(reporter_output)
        else:
            reporter.fail(reporter_output)


def _read_windows_file_ace(file_path):
    sd = win32security.GetFileSecurity(str(file_path), win32security.DACL_SECURITY_INFORMATION)
    dacl = sd.GetSecurityDescriptorDacl()
    if dacl is None:
        dacl = _new_dacl_with_all_control()
    # get the number of access control entries
    ace_count = dacl.GetAceCount()
    for i in range(ace_count):
        # rev: a tuple of (AceType, AceFlags)
        # access: ACCESS_MASK
        # usersid: SID
        rev, access, usersid = dacl.GetAce(i)
        user, _, _ = win32security.LookupAccountSid("", usersid)
        ace_type = rev[0]
        yield ace_type, user, access


def _has_permission(access, permission):
    return access & permission == permission


def _new_dacl_with_all_control():
    dacl = win32security.ACL()
    everyone, _, _ = win32security.LookupAccountName("", "Everyone")
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, everyone)
    return dacl


def _get_windows_file_owner(file_path):
    sd = win32security.GetFileSecurity(str(file_path), win32security.OWNER_SECURITY_INFORMATION)
    owner_sid = sd.GetSecurityDescriptorOwner()
    user, _, _ = win32security.LookupAccountSid(None, owner_sid)
    return user


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.MANUAL)
@splunk_appinspect.cert_version(min="1.0.0")
def check_platform_specific_binaries(app: "App", reporter: "Reporter") -> None:
    """Check that documentation declares platform-specific binaries."""
    # Can't read the documentation, but we can check for native binaries
    # TODO: we should not be generating manual checks if directories are empty
    bin_directories = [
        bin_directory
        for arch in app.arch_bin_dirs
        if arch != app.DEFAULT_ARCH
        for bin_directory in app.arch_bin_dirs[arch]
    ]
    if app.some_directories_exist(bin_directories):
        reporter_output = "Documentation will be read during code review."
        reporter.manual_check(reporter_output)
    else:
        reporter_output = "No platform-specific binaries found."
        reporter.not_applicable(reporter_output)
