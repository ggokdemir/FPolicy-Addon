"""
### README/*.spec file standards

Ensure that the **.spec** files located in the **/README** folder of the app is well formed and valid.
"""
from pathlib import Path
from typing import TYPE_CHECKING

import splunk_appinspect
from splunk_appinspect.constants import Tags
from splunk_appinspect.splunk_defined_conf_file_list import SPLUNK_DEFINED_CONFS

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


@splunk_appinspect.tags(Tags.SPLUNK_APPINSPECT, Tags.SPEC)
@splunk_appinspect.cert_version(min="2.2.0")
def check_no_default_or_value_before_stanzas(app: "App", reporter: "Reporter") -> None:
    """Check that no `[default]` or other values are defined before the first stanza."""
    spec_file_paths = list(app.get_filepaths_of_files(basedir="README", types=[".spec"]))
    if not spec_file_paths:
        reporter_output = "No spec files under README were found."
        reporter.not_applicable(reporter_output)
        return
    for directory, filename, _ in app.iterate_files(basedir="README", types=[".spec"]):
        file_path = Path(directory, filename)
        spec_file = app.get_spec(filename, directory, None)
        filename_without_spec = filename.split(".spec")[0]
        if filename_without_spec not in SPLUNK_DEFINED_CONFS:
            continue
        # Fail this check if:
        #  1) Contains "default" stanza
        #  2) Have key value pairs before first stanza
        # Please note that when parse the configuration files, key/value pairs appeared
        # before first stanza will be assigned to "default" stanza as well.
        if spec_file.has_section("default"):
            default_section = spec_file.get_section("default")
            reporter_output = (
                "Spec files cannot define default stanza. " f"File: {file_path}, Line: {default_section.lineno}."
            )
            reporter.fail(reporter_output, file_path, default_section.lineno)
