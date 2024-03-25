#!/usr/bin/env python3
"""A simply plugin that fails HTLCs with a configurable failcode.

"""
from pyln.client import Plugin


plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    res = {"result": "fail"}

    if plugin.failmsg is not None:
        res['failure_message'] = plugin.failmsg

    return res


@plugin.method('setfailmsg')
def setfailcode(plugin, msg):
    """Sets the failmessage to return when receiving an incoming HTLC.
    """
    plugin.failmsg = msg


@plugin.init()
def on_init(**kwargs):
    plugin.failmsg = None


plugin.run()
