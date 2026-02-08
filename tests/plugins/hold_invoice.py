#!/usr/bin/env python3
"""Simple plugin to allow testing while closing of HTLC is delayed.
"""

from pyln.client import Plugin
import os
import time

plugin = Plugin()


@plugin.hook('invoice_payment')
def on_payment(payment, plugin, **kwargs):
    # Block until file appears
    while not os.path.exists("unhold"):
        time.sleep(0.25)
    return {'result': 'continue'}


plugin.run()
