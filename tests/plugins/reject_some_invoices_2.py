#!/usr/bin/env python3
"""Simple plugin to test the invoice_payment hook chaining during shutdown.

A payment should never be accepted without passing through this plugin.
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('invoice_payment', after=['reject_some_invoices.py'])
def on_payment(payment, plugin, **kwargs):
    if payment['preimage'].endswith('1'):
        # WIRE_TEMPORARY_CHANNEL_FAILURE = 0x1007
        return {'failure_message': "1007"}

    return {'result': 'continue'}


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    """
    Subscribe shutdown because we consider this plugin important and don't want
    to miss payments that happen just before or during shutdown.
    """


plugin.run()
