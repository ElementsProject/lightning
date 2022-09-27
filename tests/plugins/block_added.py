#!/usr/bin/env python3

from pyln.client import Plugin


plugin = Plugin()

blocks_catched = []


@plugin.subscribe("block_added")
def notify_block_added(plugin, block, **kwargs):
    global blocks_catched
    blocks_catched.append(block["height"])


@plugin.method("blockscatched")
def return_moves(plugin):
    return blocks_catched


plugin.run()
