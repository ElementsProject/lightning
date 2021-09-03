#!/usr/bin/env python3

from pyln.client import Plugin

plugin = Plugin()


@plugin.hook('commitment_revocation')
def on_commitment_revocation(commitment_txid, penalty_tx, channel_id, commitnum, plugin, **kwargs):
    with open('watchtower.csv', 'a') as f:
        f.write("{}, {}, {}, {}\n".format(commitment_txid, penalty_tx, channel_id, commitnum))


plugin.run()
