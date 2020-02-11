#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    plugin.log("Failing htlc on purpose")
    plugin.log("onion: %r" % (onion))
    # WIRE_TEMPORARY_NODE_FAILURE = 0x2002
    return {"result": "fail", "failure_message": "2002"}


plugin.run()
