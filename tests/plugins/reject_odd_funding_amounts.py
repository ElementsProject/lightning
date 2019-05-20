#!/usr/bin/env python3
"""Simple plugin to test the openchannel_hook.

We just refuse to let them open channels with an odd amount of millisatoshis.
"""

from lightning import Plugin, Millisatoshi

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin):
    print("{} VARS".format(len(openchannel.keys())))
    for k in sorted(openchannel.keys()):
        print("{}={}".format(k, openchannel[k]))

    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() % 2 == 1:
        return {'result': 'reject', 'error_message': "I don't like odd amounts"}

    return {'result': 'continue'}


plugin.run()
