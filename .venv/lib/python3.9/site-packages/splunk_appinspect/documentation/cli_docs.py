"""
Constants for click configuration.
"""

VALIDATION_EPILOG = """Splunk AppInspect uses Python's default `logging` library. If you are familiar with native Python logging, you can extend its capabilities. 
For more information, see the [Python logging module documentation](https://docs.python.org/3/library/logging.html).

\bExamples:

Validate an app using test mode:

    $ splunk-appinspect inspect filepath/app-package.tgz  --mode test

Validate an app using test mode and filters:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode test --included-tags manual --included-tags splunk-appinspect --excluded-tags cloud

Validate an app using test mode with logging:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode test --log-level DEBUG --log-file log_output.log

Validate an app using test mode and output as JSON to a file:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode test --data-format json --output-file results.json

Validate an app using test mode and output as JUnitXML to a file:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode test --data-format junitxml --output-file results.xml

Validate an app using precert mode:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert

Validate an app using precert mode and filters:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert --included-tags manual --included-tags splunk-appinspect --excluded-tags cloud

Validate an app using precert mode with logging:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert --log-level DEBUG --log-file log_output.log

Validate an app using precert mode and output as JSON to a file:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert --data-format json --output-file results.json

Validate an app using precert mode and output as JUnitXML to a file:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert --data-format junitxml --output-file results.xml

Display all results:

    $ splunk-appinspect inspect --max-messages=all splunk-add-on-for-microsoft-windows_483.tgz

Display 100 results:

    $ splunk-appinspect inspect --max-messages=100 splunk-add-on-for-microsoft-windows_483.tgz

Generate feedback for troubleshooting:

    $ splunk-appinspect inspect filepath/app-package.tgz --mode precert --generate-feedback
"""

REPORT_EPILOG = """\bExamples:

List all groups, checks, and tags:

    $ splunk-appinspect list groups checks tags

List all groups and checks:

    $ splunk-appinspect list groups checks

List all tags:

    $ splunk-appinspect list tags

Display the version of the Splunk AppInspect CLI:

    $ splunk-appinspect list version

List only groups and checks with the `splunk-appinspect` tag:

    $ splunk-appinspect list groups checks --included-tags splunk-appinspect

List the checks that are tagged as `manual` and exclude checks tagged as `cloud`. If a check is tagged with both `manual` and `cloud`, the check is still displayed:

    $ splunk-appinspect list checks --included-tags manual --excluded-tags cloud

List checks that are tagged with `manual` and `splunk-appinspect`:

    $ splunk-appinspect list checks --included-tags manual --included-tags splunk-appinspect

List all checks except those that are tagged with `manual` or `splunk-appinspect`:

    $ splunk-appinspect list checks --excluded-tags manual --excluded-tags splunk-appinspect
"""
