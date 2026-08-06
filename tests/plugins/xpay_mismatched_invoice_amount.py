#!/usr/bin/env python3
"""Plugin which makes fetchinvoice hand back a mismatched invoice.

Stands in for a payee which sets invoice_amount to something other than the
amount our invoice_request asked for.  The invoice is validly signed;
fetchinvoice reports the difference in `changes.amount_msat`.

Call `setinvoiceamount` to arm it; until then fetchinvoice behaves normally.
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.method("setinvoiceamount")
def setinvoiceamount(plugin, invoice, amount_msat):
    plugin.mismatched = {"invoice": invoice,
                         "changes": {"amount_msat": amount_msat}}
    return {}


@plugin.hook("rpc_command")
def on_rpc_command(plugin, rpc_command, **kwargs):
    if rpc_command["method"] != "fetchinvoice" or plugin.mismatched is None:
        return {"result": "continue"}
    return {"return": {"result": plugin.mismatched}}


plugin.mismatched = None
plugin.run()
