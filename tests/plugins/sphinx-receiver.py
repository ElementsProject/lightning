#!/usr/bin/env python3
from pyln.client import Plugin


plugin = Plugin()


@plugin.hook('invoice_payment')
def on_invoice_payment(**kwargs):
    """
    """
    plugin.log("invoice_payment kwargs {a}".format(a=kwargs))
    return {'result': 'continue'}


plugin.run()
