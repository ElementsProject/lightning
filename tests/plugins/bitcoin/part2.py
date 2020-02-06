#!/usr/bin/env python3
"""
This registers part of the Bitcoin backend methods.
We only use it for testing startup and we don't care about the actual values.
"""
import time

from pyln.client import Plugin


plugin = Plugin()


@plugin.method("sendrawtransaction")
def sendtx(plugin, **kwargs):
    time.sleep(1)
    return {}


@plugin.method("getutxout")
def gettxout(plugin, **kwargs):
    time.sleep(1)
    return {}


plugin.run()
