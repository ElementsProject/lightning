#!/usr/bin/env python3
"""Settle HTLCs which carry payment_metadata, using a preimage we were told.

lightningd itself rejects any payment_metadata ("Unexpected payment_metadata"),
so this lets a test check that an onion with a large final payload arrives
intact.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("setmetadatapreimage")
def setmetadatapreimage(plugin, preimage, metadata):
    """Settle HTLCs carrying {metadata} with {preimage}."""
    plugin.expect = (preimage, metadata)
    return {}


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    if plugin.expect is None or 'payment_metadata' not in onion:
        return {'result': 'continue'}
    preimage, metadata = plugin.expect
    if onion['payment_metadata'] != metadata:
        plugin.log(f"Unexpected metadata {onion['payment_metadata']}", level='broken')
        return {'result': 'continue'}
    return {'result': 'resolve', 'payment_key': preimage}


plugin.expect = None
plugin.run()
