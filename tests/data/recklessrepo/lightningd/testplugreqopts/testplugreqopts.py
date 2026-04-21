#!/usr/bin/env python3
"""Plugin that requires a mandatory option. Exits immediately when the
option is absent - as happens when reckless runs the plugin standalone
outside of a CLN connection."""
import os
import sys

if not os.environ.get('TESTPLUG_REQUIRED_OPT'):
    print("required option 'required-opt' is not configured", file=sys.stderr)
    sys.exit(1)

from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("testplugreqopts initialized")


plugin.run()
