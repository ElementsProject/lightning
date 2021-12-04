#!/usr/bin/env python3

from pyln.client import Plugin
import sys


plugin = Plugin()


@plugin.async_method('hold-rpc-call')
def hold_rpc_call(plugin, request):
    """Simply never return, it should still get an error when the plugin crashes
    """


@plugin.hook('htlc_accepted')
def on_htlc_accepted(plugin, htlc, onion, **kwargs):
    """We die silently, i.e., without returning a response

    `lightningd` should detect that and recover.
    """
    plugin.log("Plugin is about to crash...")
    sys.exit(1)


plugin.run()
