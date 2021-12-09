#!/usr/bin/env python3

from pyln.client import Plugin

import json
import os.path


plugin = Plugin()


@plugin.subscribe("coin_movement")
def notify_coin_movement(plugin, coin_movement, **kwargs):
    plugin.log("coin movement: {}".format(coin_movement))

    # we save to disk so that we don't get borked if the node restarts
    # assumes notification calls are synchronous (not thread safe)
    with open('moves.json', 'a') as f:
        f.write(json.dumps(coin_movement) + ',')


@plugin.method('listcoinmoves_plugin')
def return_moves(plugin):
    result = []
    if os.path.exists('moves.json'):
        with open('moves.json', 'r') as f:
            jd = f.read()
        result = json.loads('[' + jd[:-1] + ']')
    return {'coin_moves': result}


plugin.run()
