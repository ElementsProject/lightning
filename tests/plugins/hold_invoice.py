#!/usr/bin/env python3
"""Simple plugin to allow testing while closing of HTLC is delayed.
"""

from pyln.client import Plugin
import time

plugin = Plugin()


@plugin.hook('invoice_payment')
def on_payment(payment, plugin, **kwargs):
    time.sleep(float(plugin.get_option('holdtime')))
    return {'result': 'continue'}


plugin.add_option('holdtime', '10', 'The time to hold invoice for.')
plugin.run()
