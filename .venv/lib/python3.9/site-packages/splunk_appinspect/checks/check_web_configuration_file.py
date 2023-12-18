# Copyright 2019 Splunk Inc. All rights reserved.
"""
### Web.conf File Standards
Ensure that `web.conf` is safe for cloud deployment and that any exposed
patterns match endpoints defined by the app - apps should not expose endpoints
other than their own.
Including `web.conf` can have adverse impacts for cloud. Allow only
`[endpoint:*]` and `[expose:*]` stanzas, with expose only containing pattern=
and methods= properties.
- [web.conf](https://docs.splunk.com/Documentation/Splunk/latest/Admin/Webconf)
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generator

from splunk_appinspect.check_messages import CheckMessage, FailMessage, NotApplicableMessage, WarningMessage
from splunk_appinspect.checks import Check, CheckConfig
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.configuration_file import ConfigurationProxy


class CheckWebConf(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_web_conf",
                description="Check that `web.conf` only defines [endpoint:*] and [expose:*]"
                "stanzas, with [expose:*] only containing `pattern=` and `methods=`.",
                depends_on_config=("web",),
                cert_min_version="1.5.0",
                tags=(
                    Tags.SPLUNK_APPINSPECT,
                    Tags.CLOUD,
                    Tags.PRIVATE_APP,
                    Tags.PRIVATE_CLASSIC,
                    Tags.PRIVATE_VICTORIA,
                    Tags.MIGRATION_VICTORIA,
                ),
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        filename = config["web"].get_relative_path()
        for section in config["web"].sections():
            lineno = config["web"][section.name].get_line_number()
            if not section.name.startswith("endpoint:") and not section.name.startswith("expose:"):
                yield FailMessage(
                    "Only the [endpoint:*] and [expose:*] stanzas are permitted in web.conf.",
                    file_name=filename,
                    line_number=lineno,
                    remediation=f"Remove this `[{section.name}] stanza.",
                )
            elif section.name.startswith("endpoint:"):
                endpoint_name = section.name.split("endpoint:")[1] or "<NOT_FOUND>"
                script_path = Path("appserver", "controllers", f"{endpoint_name}.py")
                if not app.file_exists(script_path):
                    yield WarningMessage(
                        "`[{section.name}] is defined, but no corresponding Python script was found.",
                        file_name=filename,
                        line_number=lineno,
                        remediation=f"Create script `{script_path}` or remove the "
                        f"[{section.name}] stanza from {filename}.",
                    )
            elif section.name.startswith("expose:"):
                for key, value in iter(section.options.items()):
                    lineno = config["web"][section.name][key].get_line_number()
                    if key not in ("pattern", "methods"):
                        yield FailMessage(
                            "Only the `pattern` and `methods` properties are permitted for [expose:*] stanzas.",
                            file_name=filename,
                            line_number=lineno,
                            remediation=f"Remove `{key}` from the [{section.name}] stanza.",
                        )


def _format_url_pattern(pattern: str) -> str:
    """Format to remove leading/trailing whitespace and ensure that pattern
    starts and ends with "/" or "*".
    Example: _format_url_pattern(" a/b/*/c") => "/a/b/*/c/"."""
    # Remove leading/trailing whitespace
    pattern = pattern.strip()
    # Make sure first char is "/"
    if not pattern:
        return "/"
    if pattern[0] != "/":
        pattern = f"/{pattern}"
    # Make sure last char is "/" or "*"
    if len(pattern) > 1 and pattern[-1] != "/" and pattern[-1] != "*":
        pattern = f"{pattern}/"
    return pattern


class CheckWebConfExposePatternsHaveRestmapMatches(Check):
    def __init__(self) -> None:
        super().__init__(
            config=CheckConfig(
                name="check_web_conf_expose_patterns_have_restmap_matches",
                description="Check that apps only expose web endpoints that are defined by"
                "the Splunk App within `restmap.conf`. Each `web.conf`"
                "[expose:*] stanza should have the property `pattern=` which defines a url"
                "pattern to expose. Each url pattern exposed should correspond to a stanza"
                "within `restmap.conf` with a url pattern defined with the `match=`"
                "property, or for the case of [admin:*] stanzas a combination of `match=` and"
                "`members=` properties.",
                depends_on_config=("web",),
                cert_min_version="1.5.0",
                tags=(Tags.SPLUNK_APPINSPECT,),
                report_display_order=6,
            )
        )

    def check_config(self, app: "App", config: "ConfigurationProxy") -> Generator[CheckMessage, Any, None]:
        file_path = config["web"].get_relative_path()
        restmap_patterns = None
        for section in config["web"].sections():
            if section.name.startswith("expose:"):
                if section.has_option("pattern"):
                    # Format for ease of comparison
                    pattern_to_compare = _format_url_pattern(section.get_option("pattern").value)
                    # Check restmap.conf for stanzas with at least one "match"
                    # that matches this expose pattern including * (wildcards)
                    if restmap_patterns is None:
                        # Gather all patterns from restmap.conf only once
                        restmap_patterns = []
                        if "restmap" in config:
                            unformatted_restmap_patterns = app.get_rest_map(config).all_restmap_patterns()
                            restmap_patterns = [
                                _format_url_pattern(pattern) for pattern in unformatted_restmap_patterns
                            ]
                        else:
                            yield NotApplicableMessage("restmap.conf does not exist")
                    # Use fnmatch to find any pattern matches while respecting
                    # asterisk wildcards (e.g. "1/*/other" will match "1/4/other")
                    # Note: this is overly permissive, we are allowing a match of
                    # "a/b/*/f" with "a/b/c/d/e/f" when "*" should only match a
                    # single path element according to the docs
                    matching_restmaps = fnmatch.filter(restmap_patterns, pattern_to_compare)
                    if matching_restmaps:
                        # This web.conf endpoint's pattern matches at least one
                        # restmap.conf stanza match= property, check passes
                        pass
                    else:
                        lineno = section.get_option("pattern").lineno

                        # Special case: the /data/* endpoint will be exposed
                        # whether or not the app includes it in web.conf and
                        # this is currently exposed in all Add-Ons created by
                        # Add-On builder so only WARN for this case
                        if pattern_to_compare.startswith("/data/"):
                            yield WarningMessage(
                                "web.conf found with a `pattern` exposed that does not correspond to any `match`"
                                " stanza in restmap.conf. Apps should only expose endpoints that they define. Pattern:"
                                f" `{pattern_to_compare}`. Please remove or edit this stanza: [{section.name}]. ",
                                file_name=file_path,
                                line_number=lineno,
                            )
                        else:
                            yield FailMessage(
                                "web.conf found with a `pattern` exposed that does not correspond to any `match`"
                                " stanza in restmap.conf. Apps should only expose endpoints that they define."
                                f" Pattern: `{pattern_to_compare}`. Please remove or edit this stanza: [{section.name}]. ",
                                file_name=file_path,
                                line_number=lineno,
                            )
                else:
                    yield FailMessage(
                        "Found web.conf [expose:] stanza without required `pattern=` property. Please"
                        " add this required property. Stanza:"
                        f" [{section.name}].",
                        file_name=file_path,
                        line_number=section.lineno,
                    )
