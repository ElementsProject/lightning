#!/usr/bin/env python3
"""Simple plugin to test the openchannel_hook.

We just refuse to let them open channels with an odd amount of millisatoshis.
"""

from pyln.client import Plugin, Millisatoshi
from pyln.testing.utils import env

plugin = Plugin()


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"


def run_check(funding_amt_str):
    if Millisatoshi(funding_amt_str).to_satoshi() % 2 == 1:
        return {'result': 'reject', 'error_message': "I don't like odd amounts"}

    return {'result': 'continue'}


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    print("{} VARS".format(len(openchannel.keys())))
    for k in sorted(openchannel.keys()):
        print("{}={}".format(k, openchannel[k]))
    return run_check(openchannel['funding_satoshis'])


if EXPERIMENTAL_FEATURES:
    @plugin.hook('openchannel2')
    def on_openchannel2(openchannel2, plugin, **kwargs):
        print("{} VARS".format(len(openchannel2.keys())))
        for k in sorted(openchannel2.keys()):
            print("{}={}".format(k, openchannel2[k]))

        return run_check(openchannel2['their_funding'])


plugin.run()
