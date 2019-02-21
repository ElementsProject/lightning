#!/usr/bin/env python3

from lightning import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin):
    plugin.log("Failing htlc on purpose")
    plugin.log("onion: %r" % (onion))
    return {"result": "fail"}


plugin.run()
