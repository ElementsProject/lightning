#!/usr/bin/env python3
""" This plugin gives you a nicer overview of the funds that you own.

Instead of calling listfunds and adding all outputs and channels
this plugin does that for you.

Activate the plugin with: 
`lightningd --plugin=PATH/TO/LIGHTNING/contrib/plugins/funds/funds.py`

Call the plugin with: 
`lightning-cli funds`

The standard unit to depict the funds is set to satoshis. 
The unit can be changed by and arguments after `lightning-cli funds` 
for each call. It is also possible to change the standard unit when 
starting lightningd just pass `--funds_display_unit={unit}` where
unit can be s for satoshi, b for bits, m for milliBitcoin and B for BTC.


Author: Rene Pickhardt (https://ln.rene-pickhardt.de)
Development of the plugin was sponsored by fulmo.org
"""

import json

from lightning.lightning import LightningRpc
from lightning.plugin import Plugin
from os.path import join

rpc_interface = None
plugin = Plugin(autopatch=True)

unit_aliases = {
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

unit_divisor = {
    "sat": 1,
    "bit": 100,
    "mBTC": 100*1000,
    "BTC": 100*1000*1000,
}


@plugin.method("funds")
def funds(unit=None, plugin=None):
    """Lists the total funds the lightning node owns off- and onchain in {unit}.

    {unit} can take the following values:
    s, satoshi, satoshis to depict satoshis
    b, bit, bits to depict bits
    m, milli, btc to depict milliBitcoin
    B, bitcoin, btc to depict Bitcoins

    When not using Satoshis (default) the comma values are rounded off."""

    plugin.log("call with unit: {}".format(unit), level="debug")
    if unit is None:
        unit = plugin.get_option("funds_display_unit")

    if unit != "B":
        unit = unit_aliases.get(unit.lower(), "sat")
    else:
        unit = "BTC"

    div = unit_divisor.get(unit, 1)

    funds = rpc_interface.listfunds()

    onchain_value = sum([int(x["value"]) for x in funds["outputs"]])
    offchain_value = sum([int(x["channel_sat"]) for x in funds["channels"]])

    total_funds = onchain_value + offchain_value

    return {
        'total_'+unit: total_funds//div,
        'onchain_'+unit: onchain_value//div,
        'offchain_'+unit: offchain_value//div,
    }


@plugin.method("init")
def init(options, configuration, plugin):
    global rpc_interface
    plugin.log("start initialization of the funds plugin", level="debug")
    basedir = configuration['lightning-dir']
    rpc_filename = configuration['rpc-file']
    path = join(basedir, rpc_filename)
    plugin.log("rpc interface located at {}".format(path))
    rpc_interface = LightningRpc(path)
    plugin.log("Funds Plugin successfully initialezed")
    plugin.log("standard unit is set to {}".format(
        plugin.get_option("funds_display_unit")), level="debug")


# set the standard display unit to satoshis
plugin.add_option('funds_display_unit', 's',
                  'pass the unit which should be used by default for the simple funds overview plugin')
plugin.run()
