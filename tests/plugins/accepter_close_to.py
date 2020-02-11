#!/usr/bin/env python3
"""Simple plugin to test the openchannel_hook's
   'close_to' address functionality.

   If the funding amount is:
      - a multiple of 11: we send back a valid address (regtest)
      - a multiple of 7: we send back an empty address
      - a multiple of 5: we send back an address for the wrong chain (mainnet)
      - otherwise: we don't include the close_to
"""

from pyln.client import Plugin, Millisatoshi

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    # - a multiple of 11: we send back a valid address (regtest)
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() % 11 == 0:
        return {'result': 'continue', 'close_to': 'bcrt1q7gtnxmlaly9vklvmfj06amfdef3rtnrdazdsvw'}

    # - a multiple of 7: we send back an empty address
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() % 7 == 0:
        return {'result': 'continue', 'close_to': ''}

    # - a multiple of 5: we send back an address for the wrong chain (mainnet)
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() % 5 == 0:
        return {'result': 'continue', 'close_to': 'bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2'}

    # - otherwise: we don't include the close_to
    return {'result': 'continue'}


plugin.run()
