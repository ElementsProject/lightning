#!/usr/bin/env python3

from pyln.client import Plugin
import sys


plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(plugin, htlc, onion, **kwargs):
    """We die silently, i.e., without returning a response

    `lightningd` should detect that and recover.
    """
    plugin.log("Plugin is about to crash...")
    sys.exit(1)


plugin.run()
