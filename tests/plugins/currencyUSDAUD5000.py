#!/usr/bin/env python3
"""
This plugin is used to test the currency command
"""
from pyln.client import Plugin, Millisatoshi

plugin = Plugin()


@plugin.method("currencyconvert")
def currencyconvert(plugin, amount, currency):
    """Converts currency using given APIs."""
    if currency in ('USD', 'AUD'):
        return {"msat": Millisatoshi(round(amount * 5000))}
    raise Exception("No values available for currency {}".format(currency.upper()))


plugin.run()
