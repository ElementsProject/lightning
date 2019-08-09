#!/usr/bin/env python3
"""This plugin is used to supply `getclientversion` internal method
   and check if internal rpcmethod interface is working correctly.
"""
import bitcoin
from bitcoin.rpc import JSONRPCError, Proxy
from lightning import Plugin
import os

plugin = Plugin()


BITCOIND_CONFIG = {
    "regtest": 1,
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
}


def write_config(filename, opts, regtest_opts=None):
    with open(filename, 'w') as f:
        for k, v in opts.items():
            f.write("{}={}\n".format(k, v))
        if regtest_opts:
            f.write("[regtest]\n")
            for k, v in regtest_opts.items():
                f.write("{}={}\n".format(k, v))


@plugin.method("getclientversion", internal=True)
def get_bitcoind_version(plugin):
    plugin.log("Receive getclientversion internal rpcmethod request")
    brpc = Proxy(btc_conf_file=plugin.bitcoin_conf_file)
    try:
        info = brpc._call('getnetworkinfo')
    except JSONRPCError as e:
        code = e.error['code']
        return {'exitstatus': code}
    return {'client': 'bitcoind', 'version': info['version']}


@plugin.init()
def init(configuration, options, plugin):
    bitcoin.SelectParams('regtest')
    dir = "/tmp/bitcoind-test"
    if not os.path.exists(dir):
            os.makedirs(dir)
    conf_file = os.path.join(dir, 'bitcoin.conf')
    regtestdir = os.path.join(dir, 'regtest')
    if not os.path.exists(regtestdir):
            os.makedirs(regtestdir)

    rpcport = plugin.rpc.listconfigs()['bitcoin-rpcport']
    BITCOIND_CONFIG['rpcport'] = rpcport
    BITCOIND_REGTEST = {'rpcport': rpcport}
    write_config(conf_file, BITCOIND_CONFIG, BITCOIND_REGTEST)
    plugin.bitcoin_conf_file = conf_file


plugin.run()
