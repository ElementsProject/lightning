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


def extract_opening_amount(openchannel):
    key = 'opener_satoshis' if 'version' in openchannel and openchannel['version'] == 2 else 'funding_satoshis'
    return Millisatoshi(openchannel[key])


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    ret = {'result': 'continue'}
    amt_msat = extract_opening_amount(openchannel)
    amt = amt_msat.to_satoshi()

    if openchannel['version'] == 2:
        # We match their funds. Always.
        ret['funding_sats'] = amt_msat.to_satoshi_str()

    # - a multiple of 11: we send back a valid address (regtest)
    if amt % 11 == 0:
        ret['close_to'] = 'bcrt1q7gtnxmlaly9vklvmfj06amfdef3rtnrdazdsvw'
        return ret

    # - a multiple of 7: we send back an empty address
    if amt % 7 == 0:
        ret['close_to'] = ''
        return ret

    # - a multiple of 5: we send back an address for the wrong chain (mainnet)
    if amt % 5 == 0:
        ret['close_to'] = 'bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2'
        return ret

    # - otherwise: we don't include the close_to
    return ret


plugin.run()
