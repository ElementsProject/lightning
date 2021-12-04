#!/usr/bin/env python3
from pyln.client import Plugin
from hashlib import sha256
from binascii import hexlify

"""A simple plugin that accepts invoices with "BB"*32 preimages
"""
plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(htlc, plugin, **kwargs):
    preimage = b"\xBB" * 32
    payment_hash = sha256(preimage).hexdigest()
    preimage = hexlify(preimage).decode('ASCII')
    print("htlc_accepted called for payment_hash {}".format(htlc['payment_hash']))

    if htlc['payment_hash'] == payment_hash:
        return {'result': 'resolve', 'payment_key': preimage}
    else:
        return {'result': 'continue'}


plugin.run()
