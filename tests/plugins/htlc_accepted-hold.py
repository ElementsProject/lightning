#!/usr/bin/env python3
"""Plugin which holds the first incoming HTLC, and fails every other one.

The held HTLC stays unresolved until `releasehtlc` is called with its
preimage, which lets a test choose exactly when we learn it.
"""
from pyln.client import Plugin


plugin = Plugin()


@plugin.async_hook('htlc_accepted')
def on_htlc_accepted(htlc, request, plugin, **kwargs):
    if plugin.held is None:
        plugin.held = request
        plugin.log("holding htlc {}".format(htlc['payment_hash']))
        return

    plugin.log("failing htlc {}".format(htlc['payment_hash']))
    request.set_result({'result': 'fail', 'failure_message': '2002'})


@plugin.method('releasehtlc')
def releasehtlc(plugin, preimage):
    """Resolve the HTLC we're holding with this preimage."""
    request = plugin.held
    plugin.held = None
    request.set_result({'result': 'resolve', 'payment_key': preimage})
    return {}


@plugin.init()
def init(**kwargs):
    plugin.held = None


plugin.run()
