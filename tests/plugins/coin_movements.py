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
    idx = coin_movement['movement_idx']
    plugin.log("{} coins movement version: {}".format(idx, coin_movement['version']))
    plugin.log("{} coins node: {}".format(idx, coin_movement['node_id']))
    plugin.log("{} coins mvt_type: {}".format(idx, coin_movement['type']))
    plugin.log("{} coins account: {}".format(idx, coin_movement['account_id']))
    plugin.log("{} coins credit: {}".format(idx, coin_movement['credit']))
    plugin.log("{} coins debit: {}".format(idx, coin_movement['debit']))
    plugin.log("{} coins tag: {}".format(idx, coin_movement['tag']))
    plugin.log("{} coins timestamp: {}".format(idx, coin_movement['timestamp']))
    plugin.log("{} coins coin_type: {}".format(idx, coin_movement['coin_type']))

    for f in ['payment_hash', 'utxo_txid', 'vout', 'txid', 'part_id', 'blockheight']:
        if f in coin_movement:
            plugin.log("{} coins {}: {}".format(idx, f, coin_movement[f]))

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
