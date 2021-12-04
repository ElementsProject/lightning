#!/usr/bin/env python3
"""Simple plugin to test the dynamic behavior.

A plugin started with dynamic to False cannot be controlled after lightningd
has been started.
"""

from pyln.client import Plugin

plugin = Plugin(dynamic=False)


@plugin.init()
def init(configuration, options, plugin):
    plugin.log("Static plugin initialized.")


@plugin.method('hello')
def reject(plugin):
    """Mark a given node_id as reject for future connections.
    """
    return "Hello, you cannot stop me without stopping lightningd"


plugin.run()
