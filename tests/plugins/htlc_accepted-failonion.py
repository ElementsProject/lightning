#!/usr/bin/env python3
"""A simply plugin that fails HTLCs with a meaningless onion.

"""
from pyln.client import Plugin


plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    print('returning failonion', plugin.failonion)
    return {"result": "fail", "failure_onion": plugin.failonion}


@plugin.method("setfailonion")
def setfailonion(plugin, onion):
    """Sets the failure_onion to return when receiving an incoming HTLC.
    """
    plugin.failonion = onion


@plugin.init()
def on_init(**kwargs):
    plugin.failonion = None


plugin.run()
