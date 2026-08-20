#!/usr/bin/env python3
"""Plugin that requires a mandatory option. Exits immediately when the
option is absent - as happens when reckless runs the plugin standalone
outside of a CLN connection."""

import sys

from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    if "required-opt" not in options:
        plugin.log("required option 'required-opt' is not configured")
        sys.exit(1)
    plugin.log("testplugreqopts initialized")


plugin.add_option("required-opt", None, "required option")
plugin.add_option("int-opt", None, "int option", opt_type="int")
plugin.add_option("bool-opt", None, "bool option", opt_type="bool")
plugin.add_flag_option("flag-opt", "flag option")
plugin.run()
