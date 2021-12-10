#!/usr/bin/env python3

from pyln.client import Plugin

import json
import os.path


plugin = Plugin()


@plugin.subscribe("balance_snapshot")
def notify_balance_snapshot(plugin, balance_snapshot, **kwargs):
    # we save to disk so that we don't get borked if the node restarts
    # assumes notification calls are synchronous (not thread safe)
    with open('snaps.json', 'a') as f:
        f.write(json.dumps(balance_snapshot) + ',')


@plugin.method('listsnapshots')
def return_moves(plugin):
    result = []
    if os.path.exists('snaps.json'):
        with open('snaps.json', 'r') as f:
            jd = f.read()
        result = json.loads('[' + jd[:-1] + ']')
    return {'balance_snapshots': result}


plugin.run()
