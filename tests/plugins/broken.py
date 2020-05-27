#!/usr/bin/env python3
"""Simple plugin to test that lightningd doesnt crash if it starts a
misbehaving plugin via RPC.
"""

from pyln.client import Plugin
import an_unexistent_module_that_will_make_me_crash

plugin = Plugin(dynamic=False)


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("broken.py initializing {}".format(configuration))
    # We need to actually use the import to pass source checks..
    an_unexistent_module_that_will_make_me_crash.hello()


plugin.run()
