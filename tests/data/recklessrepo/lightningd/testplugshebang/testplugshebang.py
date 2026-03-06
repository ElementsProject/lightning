#!/usr/bin/env -S uv run --script

# /// script
# requires-python = ">=3.9.2"
# dependencies = [
#   "pyln-client>=25.12",
# ]
# ///

from pyln.client import Plugin

plugin = Plugin()

__version__ = 'v1'


@plugin.init()
def init(options, configuration, plugin, **kwargs):
    plugin.log("testplugshebang initialized")


@plugin.method("plugintest")
def plugintest(plugin):
    return ("success")


plugin.run()
