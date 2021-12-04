#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    plugin.log("Failing htlc on purpose with invalid onion failure")
    plugin.log("onion: %r" % (onion))
    # WIRE_TEMPORARY_CHANNEL_FAILURE = 0x1007
    # This failure code should be followed by a
    # `channel_update`; we deliberately return
    # a 0-length `channel_update` to trigger
    # issue #3757 reported by @sumBTC.
    return {"result": "fail", "failure_message": "10070000"}


plugin.run()
