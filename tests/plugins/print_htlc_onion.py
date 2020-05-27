#!/usr/bin/env python3
"""Plugin that prints out HTLC onions.

We use this to check whether they're TLV or not

"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    plugin.log("Got onion {}".format(onion))
    return {'result': 'continue'}


plugin.run()
