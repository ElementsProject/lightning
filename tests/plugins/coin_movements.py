#!/usr/bin/env python3

from pyln.client import Plugin

import json
import os.path


plugin = Plugin()


@plugin.init()
def init(configuration, options, plugin):
    if os.path.exists('moves.json'):
        jd = {}
        with open('moves.json', 'r') as f:
            jd = f.read()
        plugin.coin_moves = json.loads(jd)
    else:
        plugin.coin_moves = []


@plugin.subscribe("coin_movement")
def notify_coin_movement(plugin, coin_movement, **kwargs):
    plugin.log("coin movement: {}".format(coin_movement))
    plugin.coin_moves.append(coin_movement)

    # we save to disk so that we don't get borked if the node restarts
    # assumes notification calls are synchronous (not thread safe)
    with open('moves.json', 'w') as f:
        f.write(json.dumps(plugin.coin_moves))


@plugin.method('listcoinmoves_plugin')
def return_moves(plugin):
    result = []
    if os.path.exists('moves.json'):
        jd = {}
        with open('moves.json', 'r') as f:
            jd = f.read()
        result = json.loads(jd)
    return {'coin_moves': result}


plugin.run()
