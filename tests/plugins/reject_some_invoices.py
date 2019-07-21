#!/usr/bin/env python3
"""Simple plugin to test the invoice_payment_hook.

We just refuse to let them pay invoices with preimages divisible by 16.
"""

from lightning import Plugin

plugin = Plugin()


@plugin.hook('invoice_payment')
def on_payment(invoice_payment, plugin):
    print("label={}".format(invoice_payment['label']))
    print("msat={}".format(invoice_payment['msat']))
    print("preimage={}".format(invoice_payment['preimage']))

    if invoice_payment['preimage'].endswith('0'):
        # FIXME: Define this!
        WIRE_TEMPORARY_NODE_FAILURE = 0x2002
        return {'failure_code': WIRE_TEMPORARY_NODE_FAILURE}

    return {}


plugin.run()
