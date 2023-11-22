#!/usr/bin/env python3

""" This plugin is used to test that notifications
are send to plug-ins that subscribe to custom msgs
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.subscribe("custommsg")
def on_custommsg(custommsg, **_):
    plugin.log(f"Received a custommsg with data msg={custommsg}")

    peer_id = custommsg["peer_id"]
    payload = custommsg["payload"]
    plugin.log(f"peer_id={peer_id}")
    plugin.log(f"payload={payload}")


plugin.run()
