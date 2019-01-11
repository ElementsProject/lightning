#!/usr/bin/env python3

from lightning import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, htlc, plugin):
    return {"result": "resolve", "payment_key": "00" * 32}


plugin.run()
