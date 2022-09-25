#!/usr/bin/env python3
"""A plugin that tells us to forward HTLCs to a specific channel.

"""
from pyln.client import Plugin


plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    if plugin.fwdto is None:
        return {"result": "continue"}

    return {"result": "continue", "forward_to": plugin.fwdto}


@plugin.method("setfwdto")
def setfailonion(plugin, fwdto):
    """Sets the channel_id to forward to when receiving an incoming HTLC.
    """
    plugin.fwdto = fwdto


@plugin.init()
def on_init(**kwargs):
    plugin.fwdto = None


plugin.run()
