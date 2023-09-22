#!/usr/bin/env python3
import json
import subprocess
import os

from pyln.client import Plugin


plugin = Plugin()


network = os.environ.get("TEST_NETWORK", "regtest")
cli = "bitcoin-cli" if network == "regtest" else "elements-cli"


def bcli(plugin, cmd):
    ret = subprocess.run([cli,
                          '-datadir={}'.format(plugin.get_option("bitcoin-datadir")),
                          '-rpcuser={}'.format(plugin.get_option("bitcoin-rpcuser")),
                          '-rpcpassword={}'.format(plugin.get_option("bitcoin-rpcpassword")),
                          '-rpcport={}'.format(plugin.get_option("bitcoin-rpcport"))]
                         + cmd, stdout=subprocess.PIPE)
    if ret.returncode != 0:
        return None
    return ret.stdout.decode('utf-8')


@plugin.method("estimatefees")
def estimatefees(plugin, **kwargs):
    if plugin.get_option("badestimate-badorder"):
        return {"feerate_floor": 1000,
                "feerates": [{"blocks": 6,
                              "feerate": 1240000000},
                             {"blocks": 12,
                              "feerate": 1350000000},
                             {"blocks": 100,
                              "feerate": 3610000000},
                             {"blocks": 2,
                              "feerate": 1270000000}]}
    else:
        return {"feerate_floor": 1000,
                "feerates": [{"blocks": 2,
                              "feerate": 1270000000},
                             {"blocks": 6,
                              "feerate": 1240000000},
                             {"blocks": 12,
                              "feerate": 1350000000},
                             {"blocks": 100,
                              "feerate": 3610000000}]}


@plugin.method("getrawblockbyheight")
def getrawblockbyheight(plugin, height, **kwargs):
    bhash = bcli(plugin, ["getblockhash", str(height)])
    if bhash is None:
        return {"blockhash": None,
                "block": None}
    bhash = bhash.strip()
    block = bcli(plugin, ["getblock", bhash, "0"]).strip()
    return {"blockhash": bhash,
            "block": block}


@plugin.method("getchaininfo")
def getchaininfo(plugin, **kwargs):
    info = json.loads(bcli(plugin, ["getblockchaininfo"]))
    return {"chain": info['chain'],
            "headercount": info['headers'],
            "blockcount": info['blocks'],
            "ibd": info['initialblockdownload']}


@plugin.method("sendrawtransaction")
def sendrawtransaction(plugin, tx, allowhighfees=False, **kwargs):
    bcli(plugin, ["sendrawtransaction", tx])
    return {'success': True}


@plugin.method("getutxout")
def getutxout(plugin, txid, vout, *kwargs):
    txoutstr = bcli(plugin, ["gettxout", txid, vout]).strip()
    if txoutstr == "":
        return {"amount": None, "script": None}
    txout = json.loads(txoutstr)
    return {"amount": txout['value'],
            "script": txout['scriptPubKey']['hex']}


plugin.add_option("bitcoin-rpcuser", '', '')
plugin.add_option("bitcoin-rpcpassword", '', '')
plugin.add_option("bitcoin-datadir", '', '')
plugin.add_option("bitcoin-rpcport", '', '')
plugin.add_option("badestimate-badorder", False, 'Send out-of-order estimates', opt_type='bool')

plugin.run()
