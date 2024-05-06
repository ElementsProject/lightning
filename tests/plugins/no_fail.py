#!/usr/bin/env python3
"""Plugin that breaks the node if a fail notification is received.
"""

from pyln.client import Plugin
import os

plugin = Plugin()


@plugin.init()
def init(plugin, options, configuration):
    plugin.log("no_fail initialized")


@plugin.subscribe("sendpay_failure")
def channel_opened(plugin, sendpay_failure, **kwargs):
    os._exit(1)


@plugin.method("nofail")
def nofail(plugin):
    """Checks that the plugin is still running."""
    return {"status": "active"}


plugin.run()
