#!/usr/bin/env python3

from pyln.client import Plugin
from time import sleep
import sys

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(onion, plugin, **kwargs):
    delay = int(plugin.get_option('htlc_accepted_hook_delay'))
    plugin.log("delay htlc_accepted with {}".format(delay))
    sleep(delay)
    plugin.log("Failing htlc on purpose")
    plugin.log("onion: %r" % (onion))
    # WIRE_TEMPORARY_NODE_FAILURE = 0x2002
    return {"result": "fail", "failure_message": "2002"}


@plugin.subscribe("shutdown")
def shutdown(plugin, **kwargs):
    """Only to not get killed while handling the hook"""
    sys.exit(0)


plugin.add_option('htlc_accepted_hook_delay', 0, '', opt_type='int')
plugin.run()
