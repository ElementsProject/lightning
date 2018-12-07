#!/usr/bin/env python3
""" This plugin gives you a nicer overview of the funds that you own.

Instead of calling listfunds and adding all outputs and channels
this plugin does that for you.

Author: Rene Pickhardt (https://ln.rene-pickhardt.de)

"""

import json
import sys

from lightning.lightning import LightningRpc
from os.path import join

rpc_interface = None


def json_get_funds(request, unit="s"):

    switcher = {
        "bitcoin": "BTC",
        "btc": "BTC",
        "satoshi": "sat",
        "satoshis": "sat",
        "bit": "bit",
        "bits": "bit",
        "milli": "mBTC",
        "mbtc": "mBTC",
        "millibtc": "mBTC",
        "B": "BTC",
        "s": "sat",
        "m": "mBTC",
        "b": "bit",
    }

    if unit != "B":
        unit = switcher.get(unit.lower(), "sat")
    else:
        unit = "BTC"

    switcher = {
        "sat": 1,
        "bit": 100,
        "mBTC": 100*1000,
        "BTC": 100*1000*1000,
    }

    div = switcher.get(unit, 1)

    funds = rpc_interface.listfunds()

    onchain_value = sum([int(x["value"]) for x in funds["outputs"]])
    offchain_value = sum([int(x["channel_sat"]) for x in funds["channels"]])

    total_funds = onchain_value + offchain_value

    return {
        'total_'+unit: total_funds//div,
        'onchain_'+unit: onchain_value//div,
        'offchain_'+unit: offchain_value//div,
    }


def json_getmanifest(request):

    verbose = """Lists the total funds the lightning node owns off- and onchain in {unit}.

{unit} can take the following values:
s, satoshi, satoshis to depict satoshis
b, bit, bits to depict bits
m, milli, btc to depict milliBitcoin
B, bitcoin, btc to depict Bitcoins

When not using Satoshis (default) the comma values are rounded off."""

    return {
        "options": [
        ],
        "rpcmethods": [
            {
                "name": "funds",
                "description": "Lists the total funds the lightning node owns off- and onchain in {unit}",
                "long_description": verbose
            },
        ]
    }


def json_init(request, options, configuration):
    """The main daemon is telling us the relevant cli options
    """
    global rpc_interface

    basedir = request['params']['configuration']['lightning-dir']
    rpc_filename = request['params']['configuration']['rpc-filename']
    path = join(basedir, rpc_filename)

    rpc_interface = LightningRpc(path)

    return "ok"


methods = {
    'getmanifest': json_getmanifest,
    'init': json_init,
    'funds': json_get_funds,
}


partial = ""
for l in sys.stdin:
    try:
        partial += l
        request = json.loads(partial)
    except Exception:
        continue

    result = None
    method = methods[request['method']]
    params = request['params']
    try:
        if isinstance(params, dict):
            result = method(request, **params)
        else:
            result = method(request, *params)
        result = {
            "jsonrpc": "2.0",
            "result": result,
            "id": request['id']
        }
    except Exception as e:
        result = {
            "jsonrpc": "2.0",
            "error": "Error while processing {}".format(request['method']),
            "id": request['id']
        }

    json.dump(result, fp=sys.stdout)
    sys.stdout.write('\n')
    sys.stdout.flush()
    partial = ""
