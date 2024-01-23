"""
### jQuery vulnerabilities
"""
import os
from pathlib import Path
from typing import TYPE_CHECKING

import splunk_appinspect
import splunk_appinspect.check_routine.util as util
from splunk_appinspect.constants import Tags

if TYPE_CHECKING:
    from splunk_appinspect import App
    from splunk_appinspect.reporter import Reporter


""" This function throws a warning message during app inspect if the dashboards of the app
do not have a version attribute OR have the version attribute set to a value other than 1.1

@param:
app: An app object
reporter: Reporter object """


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.JQUERY,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="2.5.0")
def check_simplexml_standards_version(app: "App", reporter: "Reporter") -> None:
    """Check that the dashboards in your app have a valid version attribute."""

    xml_files = list(app.get_filepaths_of_files(types=[".xml"]))
    for query_node, relative_filepath in util.get_dashboard_nodes(xml_files):
        version = query_node.get("version")
        if version is None:
            message = (
                "Change the version attribute in the root node of your Simple XML dashboard "
                f"{relative_filepath} to `<version=1.1>`. Earlier dashboard versions introduce "
                "security vulnerabilities into your apps and are not permitted in Splunk Cloud"
            )
            reporter.fail(message, relative_filepath)
        elif version.strip() == "2" or version.strip() == "1.1":  # If UDF or simple XML dashboard 1.1, continue
            continue
        else:
            message = (
                f"Version attribute of the dashboard {relative_filepath} is "
                f"set to {version}.Change the version attribute in the root "
                "node of your Simple XML dashboard to `<version=1.1>`. "
                "Earlier dashboard versions introduce security vulnerabilities "
                "into your apps and are not permitted in Splunk Cloud"
            )
            reporter.fail(message, relative_filepath)


""" This function throws a warning message during app inspect if the app's HTML and JS files
have unsupported imports

@param:
app: An app object
reporter: Reporter object """


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.JQUERY,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="2.5.0")
def check_hotlinking_splunk_web_libraries(app: "App", reporter: "Reporter") -> None:
    """Check that the app files are not importing files directly from the
    search head.
    """

    js_files = list(app.get_filepaths_of_files(basedir="appserver/static", types=[".js"]))
    unpacked_js_files = util.unpack_absolute_path(js_files)

    html_dashboard_files = list(
        app.get_filepaths_of_files(
            basedir=["default/data/ui/html", "local/data/ui/html", *app.get_user_paths("local", "data", "ui", "html")],
            types=[".html"],
        )
    )
    unpacked_html_dashboard_files = util.unpack_absolute_path(html_dashboard_files)
    html_template_files = list(app.get_filepaths_of_files(basedir="appserver/templates", types=[".html"]))
    unpacked_html_template_files = util.unpack_absolute_path(html_template_files)
    html_static_template_files = list(app.get_filepaths_of_files(basedir="appserver/static/template", types=[".html"]))
    unpacked_html_static_template_files = util.unpack_absolute_path(html_static_template_files)
    unpacked_html_files = (
        unpacked_html_dashboard_files + unpacked_html_template_files + unpacked_html_static_template_files
    )

    # Get list of files from search head (disallowed_imports.json)
    disallowed_json_path = Path(
        os.path.abspath(Path(__file__, "../../splunk/jquery_checks_data/disallowed_imports.json"))
    )
    # Get list of risky imports from search head (risky_imports.json)
    risky_imports_json_path = Path(
        os.path.abspath(Path(__file__, "../../splunk/jquery_checks_data/risky_imports.json"))
    )

    with open(disallowed_json_path, "r", encoding="utf-8", errors="ignore") as disallowed_modules_file:
        disallowed_modules_imports = util.populate_set_from_json(disallowed_modules_file)
    with open(risky_imports_json_path, "r", encoding="utf-8", errors="ignore") as risky_imports_file:
        risky_modules_imports = util.populate_set_from_json(risky_imports_file)

    # Check for SH imports in all JS files
    file_list = util.validate_imports(
        unpacked_js_files,
        unpacked_html_files,
        disallowed_modules_imports,
        risky_modules_imports,
    )
    util.communicate_bad_import_message(reporter, file_list)


""" This function fails if the app has HTML dashboards

@param:
app: An app object
reporter: Reporter object """


@splunk_appinspect.tags(
    Tags.SPLUNK_APPINSPECT,
    Tags.CLOUD,
    Tags.JQUERY,
    Tags.PRIVATE_APP,
    Tags.PRIVATE_VICTORIA,
    Tags.MIGRATION_VICTORIA,
    Tags.PRIVATE_CLASSIC,
)
@splunk_appinspect.cert_version(min="2.5.0")
def check_html_dashboards(app: "App", reporter: "Reporter") -> None:
    """Check for HTML dashboards, which are deprecated."""

    default_files = list(app.get_filepaths_of_files(basedir="default/data/ui/html", types=[".html"]))
    local_files = list(app.get_filepaths_of_files(basedir="local/data/ui/html", types=[".html"]))
    user_files = list(
        app.get_filepaths_of_files(basedir=app.get_user_paths("local", "data", "ui", "html"), types=[".html"])
    )
    html_dashboard_files = default_files + local_files + user_files
    message = (
        "Your app includes HTML dashboard files in the data/ui/html directory, "
        "which must be removed. For more information about updating dashboards, see "
        "https://dev.splunk.com/enterprise/docs/developapps/visualizedata/updatejquery/"
    )

    for relative_filepath, _ in html_dashboard_files:
        reporter.fail(message, relative_filepath)
