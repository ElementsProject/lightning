#!/usr/bin/env python3
"""Simple plugin to test the dynamic behavior.

A plugin started with dynamic to False cannot be controlled after lightningd
has been started.
"""

from lightning import Plugin

plugin = Plugin(dynamic=False)


@plugin.init()
def init(configuration, options, plugin):
    plugin.log("init startup={}".format(configuration['startup']))

    # we don't like to be started at run-time
    if not configuration['startup']:
        raise Exception


@plugin.method('static_2')
def reject(plugin):
    """Mark a given node_id as reject for future connections.
    """
    return "World, you cannot stop me without stopping lightningd"


plugin.run()
