#!/usr/bin/env python3
"""Plugin that holds on to HTLCs for 10 seconds.

Used to test restarts / crashes while HTLCs were accepted, but not yet
settled/forwarded/

"""


from pyln.client import Plugin
import json
import os
import tempfile
import time

plugin = Plugin()


@plugin.hook("htlc_accepted")
def on_htlc_accepted(htlc, onion, plugin, **kwargs):
    # Stash the onion so the test can check it
    fname = os.path.join(tempfile.mkdtemp(), "onion.json")
    with open(fname, 'w') as f:
        f.write(json.dumps(onion))

    plugin.log("Holding onto an incoming htlc for 10 seconds")

    time.sleep(10)

    print("Onion written to {}".format(fname))

    # Give the tester something to look for
    plugin.log("htlc_accepted hook called")
    return {'result': 'continue'}


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("hold_htlcs.py initializing")


plugin.run()
