#!/usr/bin/env python3
"""Simple plugin to test that lightningd doesnt crash if it starts a
misbehaving plugin via RPC.
"""
from pyln.client import Plugin
import os
plugin = Plugin()
crash_at = os.environ.get("BROKEN_CRASH", "before_start")


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("broken.py initializing {}".format(configuration))
    assert crash_at == "during_init"
    plugin.does_not_exist()


@plugin.method("test_broken")
def test_broken():
    return {}


if crash_at == "before_start":
    assert False
elif crash_at == "during_getmanifest":
    del plugin.methods['getmanifest']

plugin.run()
