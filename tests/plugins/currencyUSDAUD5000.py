#!/usr/bin/env python3
"""
This plugin is used to test the currency command
"""
from pyln.client import Plugin, Millisatoshi

plugin = Plugin()
_rate = 5000  # msat per unit


@plugin.method("currencyconvert")
def currencyconvert(plugin, amount, currency):
    """Converts currency using given APIs."""
    if currency in ('USD', 'AUD'):
        return {"msat": Millisatoshi(round(amount * _rate))}
    raise Exception("No values available for currency {}".format(currency.upper()))


@plugin.method("setcurrencyrate")
def setcurrencyrate(plugin, msat_per_unit):
    """Change the msat-per-unit rate (for testing)."""
    global _rate
    _rate = msat_per_unit
    return {"msat_per_unit": _rate}


plugin.run()
