#!/usr/bin/env python3
"""This plugin is used to check that warning(unusual/broken level log) calls are working correctly.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    plugin.log("initialized")


@plugin.subscribe("warning")
def notify_warning(plugin, warning, **kwargs):
    plugin.log("Received warning")
    plugin.log("level: {}".format(warning['level']))
    plugin.log("time: {}".format(warning['time']))
    plugin.log("source: {}".format(warning['source']))
    plugin.log("log: {}".format(warning['log']))


@plugin.method("pretendbad")
def pretend_bad(event, level, plugin):
    """Log an specified level entry.
    And in plugin, we use 'warn'/'error' instead of
    'unusual'/'broken'
    """
    plugin.log("{}".format(event), level)


plugin.run()
