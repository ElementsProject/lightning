#!/usr/bin/env python3

""" We get an onionmessage_forward_fail notification, and open a connection
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.subscribe("onionmessage_forward_fail")
def on_onionmessage_forward_fail(onionmessage_forward_fail, **kwargs):
    plugin.log(f"Received onionmessage_forward_fail {onionmessage_forward_fail}")

    plugin.rpc.connect(onionmessage_forward_fail['next_node_id'])
    # injectonionmessage expects to unwrap, so hand it *incoming*
    plugin.rpc.injectonionmessage(onionmessage_forward_fail['path_key'],
                                  onionmessage_forward_fail['incoming'])


plugin.run()
