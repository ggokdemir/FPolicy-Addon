# Copyright 2019 Splunk Inc. All rights reserved.

"""This is a helper module to encapsulate the functionality that represents
Splunk's rest map feature.
"""


import logging
from pathlib import Path

from . import file_resource, rest_map_configuration_file

logger = logging.getLogger(__name__)


class RestHandler(object):
    """Represents a rest handler."""

    def __init__(
        self,
        section,
        handler_file_name=Path(""),
        handler_module="",
        handler_module_file_name=Path(""),
        handler_actions="",
        hander_type="",
        executable_script_file_name="",
        python_version="",
        scripttype="",
    ):
        self.name = section.name
        self.handler_file_name = handler_file_name
        self.executable_script_file_name = executable_script_file_name
        self.handler_module = handler_module
        self.handler_module_file_name = handler_module_file_name
        self.handler_actions = handler_actions
        self.handler_type = hander_type
        self.python_version = python_version
        self.scripttype = scripttype

    def handler_file(self):
        """Represents the file for a specific file

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        handlerfile=<unique filename>
        * Script to execute.
        * For bin/myAwesomeAppHandler.py, specify only myAwesomeAppHandler.py.
        """
        return file_resource.FileResource(self.handler_file_name)

    def executable_script_file(self):
        """Represents the file for a specific script executable

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        script=<path to a script executable>
        * For scripttype=python this is optional.  It allows you to run a script
          which is *not* derived from 'splunk.rest.BaseRestHandler'.  This is
          rarely used.  Do not use this unless you know what you are doing.
        * For scripttype=persist this is the path with is sent to the driver
          to execute.  In that case, environment variables are substituted..
        """
        return file_resource.FileResource(self.executable_script_file_name)

    def handler(self):
        """Represents the file for a module in a file file

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf

        # handler=<SCRIPT>.<CLASSNAME>
        # * The name and class name of the file to execute.
        # * The file *must* live in an application's bin subdirectory.
        # * For example, $SPLUNK_HOME/etc/apps/<APPNAME>/bin/TestHandler.py has a class
        #   called MyHandler (which, in the case of python must be derived from a base
        #   class called 'splunk.rest.BaseRestHandler'). The tag/value pair for this is:
        #   "handler=TestHandler.MyHandler".

        """
        return file_resource.FileResource(self.handler_module_file_name)


class RestMap(object):
    """Represents a restmap.conf file."""

    def __init__(self, app, config):
        self.app = app
        self.config = config

    def configuration_file_exists(self):
        return "restmap" in self.config

    def get_configuration_file(self):
        return self.config["restmap"]

    def global_handler_file(self):
        """
        The global handler that has a default specifed.

        See http://docs.splunk.com/Documentation/Splunk/latest/Admin/restmapconf
        """
        for section in self.get_configuration_file().section_names():
            if section == "global":
                for key, value, _ in self.get_configuration_file().items(section):
                    if key.lower() == "pythonHandlerPath".lower():
                        file_path = Path(self.app.app_dir, "bin", value)
                        return file_resource.FileResource(file_path)

        file_path = Path(self.app.app_dir, "bin", "rest_handler.py")
        return file_resource.FileResource(file_path)

    @staticmethod
    def is_handler(section_name):
        return section_name.startswith("script:") or section_name.startswith("admin_external:")

    def handlers(self):
        handler_list = []

        rest_map_conf = self.get_configuration_file()

        for section in rest_map_conf.sections():
            # Only check sections that are "script" or "admin_external"
            if not self.is_handler(section.name):
                continue

            handler = RestHandler(section, self.app.app_dir)

            for key, value, _ in rest_map_conf.items(section.name):
                if section.name.startswith("script:"):
                    # From spec file
                    # script=<path to a script executable>
                    # * For scripttype=python this is optional.  It allows you to run a script
                    #   which is *not* derived from 'splunk.rest.BaseRestHandler'.  This is
                    # rarely used.  Do not use this unless you know what you
                    # are doing.

                    if key.lower() == "script":
                        handler.executable_script_file_name = Path(self.app.app_dir, "bin", value)
                    elif key.lower() == "scripttype":
                        handler.scripttype = value
                    elif key.lower() == "handler":
                        handler.handler_file_name = Path(self.app.app_dir, "bin", value)

                        # TODO: Guard against bad conf (e.g. handler=blah instead of
                        # handler=blah.mod)
                        path = value.split(".")[:1][0] + ".py"

                        handler.handler_module_file_name = Path(self.app.app_dir, "bin", path)
                        handler.handler_module = value
                elif section.name.startswith("admin_external:"):
                    if key.lower() == "handlerfile":
                        handler.handler_file_name = Path(self.app.app_dir, "bin", value)
                    elif key.lower() == "handlertype":
                        handler.handler_type = value

                # Post python2 deprecation
                if key.lower() == "python.version":
                    handler.python_version = value

            handler_list.append(handler)

        return handler_list

    def all_admin_patterns(self):
        """
        Gather all endpoint url patterns defined by admin endpoints. Each
        `match=XXXXX` values within [admin:*] stanzas across the conf file
        define the admin prefix, with the "members" defining the individual
        endpoints underneath the admin prefix.

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        patterns = []

        conf_file = self.get_configuration_file()
        for section in conf_file.sections():
            if section.name.startswith("admin:") and section.has_option("match"):
                # Gather the admin root, if match = /my/custom-admin/endpoint
                # then this will expose https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/<each_member>
                admin_root = section.get_option("match").value.strip()
                # Add all members, comma-separated. Each will reside
                # underneath the admin_root defined above, if members = myone,
                # mytwo they will be exposed (using example above) as:
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/myone and
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom-admin/endpoint/mytwo
                if section.has_option("members"):
                    members = section.get_option("members").value.strip().split(",")
                    for member in members:
                        if not member:  # skip ""
                            continue
                        admin_root_strip = admin_root.strip("/")
                        member_strip = member.strip().strip("/")
                        member_match = f"{admin_root_strip}/{member_strip}"
                        patterns.append(member_match)

        return patterns

    def all_non_admin_patterns(self):
        """
        Gather all endpoint url patterns that correspond to custom endpoint that
        are NOT defined using the [admin:XXXX] or [admin_external:XXXX] stanzas.
        This will just be a gathering of all `match = ` properties for non-admin
        stanzas across the conf file.

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        patterns = []

        conf_file = self.get_configuration_file()
        admin_prefix = "admin:"
        admin_ext_prefix = "admin_external:"
        for section in conf_file.sections():
            if (
                not section.name.startswith(admin_prefix)
                and not section.name.startswith(admin_ext_prefix)
                and section.has_option("match")
            ):
                # Grab the value of `match = ` property, add to our url patterns
                # If match = /my/custom/endpoint, then it will be exposed at:
                # https://127.0.0.1:8089/servicesNS/nobody/<appname>/my/custom/endpoint
                patterns.append(section.get_option("match").value.strip())

        return patterns

    def all_restmap_patterns(self):
        """
        Gather all endpoints defined by restmap.conf

        Returns
            (list) of str - each a url pattern (e.g. "/my/custom/endpoint")
        """
        return self.all_non_admin_patterns() + self.all_admin_patterns()
