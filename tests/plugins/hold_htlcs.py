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

    plugin.log("Holding onto an incoming htlc for {hold_time} seconds".format(
        hold_time=plugin.hold_time
    ))

    time.sleep(plugin.hold_time)

    print("Onion written to {}".format(fname))

    # Give the tester something to look for
    plugin.log("htlc_accepted hook called")
    return {'result': plugin.hold_result}


plugin.add_option(
    'hold-time', 10,
    'How long should we hold on to HTLCs?',
    opt_type='int'
)
plugin.add_option(
    'hold-result',
    'continue', 'How should we continue after holding?',
)


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("hold_htlcs.py initializing")
    plugin.hold_time = options['hold-time']
    plugin.hold_result = options['hold-result']


plugin.run()
