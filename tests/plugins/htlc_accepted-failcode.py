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

    if plugin.failcode is not None:
        res['failure_code'] = plugin.failcode

    return res


@plugin.method('setfailcode')
def setfailcode(plugin, code=None, msg=None):
    """Sets the failcode to return when receiving an incoming HTLC.
    """
    plugin.failcode = code
    plugin.failmsg = msg


@plugin.init()
def on_init(**kwargs):
    plugin.failcode = None
    plugin.failmsg = None


plugin.run()
