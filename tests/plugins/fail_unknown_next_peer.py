#!/usr/bin/env python3
"""Fail payment forwards with unknown_next_peer. Leave local invoices alone.

Used by test_xpay_unknown_next_peer_excludes_node (issue 9590).
"""
from pyln.client import Plugin

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    # Forwards carry forward_msat. Local invoices and funding HTLCs do not.
    if not isinstance(onion, dict) or onion.get("forward_msat") is None:
        return {"result": "continue"}
    plugin.log("failing forward with unknown_next_peer")
    # WIRE_UNKNOWN_NEXT_PEER = PERM | 10 = 0x400a
    return {"result": "fail", "failure_message": "400a"}


plugin.run()
