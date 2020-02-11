#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, plugin, **kwargs):
    return {"result": "resolve", "payment_key": "00" * 32}


plugin.run()
