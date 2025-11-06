#!/usr/bin/env python3
"""A plugin that overrides the amount of the invoice that belongs to an HTLC."""

from pyln.client import Plugin


plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    res = {"result": "continue"}
    if plugin.invoice_msat:
        res["invoice_msat"] = plugin.invoice_msat
    return res


@plugin.method("setinvoicemsat")
def setinvoicemsat(plugin, msat: int):
    """Sets invoice_msat for the htlc_accepted response."""
    plugin.invoice_msat = msat


@plugin.init()
def on_init(**kwargs):
    plugin.invoice_msat = None


plugin.run()
