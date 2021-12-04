#!/usr/bin/env python3
"""Simple plugin to test the invoice_payment_hook.

We just refuse to let them pay invoices with preimages divisible by 16.
"""

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('invoice_payment')
def on_payment(payment, plugin, **kwargs):
    print("label={}".format(payment['label']))
    print("msat={}".format(payment['msat']))
    print("preimage={}".format(payment['preimage']))

    if payment['preimage'].endswith('0'):
        # WIRE_TEMPORARY_NODE_FAILURE = 0x2002
        return {'failure_message': "2002"}

    return {'result': 'continue'}


plugin.run()
