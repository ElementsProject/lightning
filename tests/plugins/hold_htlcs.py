#!/usr/bin/env python3
"""Plugin that holds on to HTLCs for 10 seconds.

Used to test restarts / crashes while HTLCs were accepted, but not yet
settled/forwarded/

"""


from lightning import Plugin
import time


plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin):
    plugin.log("Holding onto an incoming htlc for 10 seconds")
    time.sleep(10)

    # Give the tester something to look for
    plugin.log("htlc_accepted hook called")
    return {'result': 'continue'}


plugin.run()
