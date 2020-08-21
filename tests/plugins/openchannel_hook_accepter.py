#!/usr/bin/env python3
"""Simple plugin to test the openchannel_hook's
   'close_to' address functionality.

   If the funding amount is:
      - 100005sat: we reject correctly w/o close_to
      - 100004sat: we reject invalid by setting a close_to
      - 100003sat: we send back a valid address (regtest)
      - 100002sat: we send back an empty address
      - 100001sat: we send back an address for the wrong chain (mainnet)
      - otherwise: we don't include the close_to
"""

from pyln.client import Plugin, Millisatoshi

plugin = Plugin()


@plugin.hook('openchannel')
def on_openchannel(openchannel, plugin, **kwargs):
    # - 100005sat: we reject correctly w/o close_to
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() == 100005:
        msg = "reject for a reason"
        plugin.log(msg)
        return {'result': 'reject', 'error_message': msg}

    # - 100004sat: we reject invalid by setting a close_to
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() == 100004:
        msg = "I am a broken plugin"
        plugin.log(msg)
        return {'result': 'reject', 'error_message': msg,
                'close_to': "bcrt1q7gtnxmlaly9vklvmfj06amfdef3rtnrdazdsvw"}

    # - 100003sat: we send back a valid address (regtest)
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() == 100003:
        return {'result': 'continue', 'close_to': 'bcrt1q7gtnxmlaly9vklvmfj06amfdef3rtnrdazdsvw'}

    # - 100002sat: we send back an empty address
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() == 100002:
        return {'result': 'continue', 'close_to': ''}

    # - 100001sat: we send back an address for the wrong chain (mainnet)
    if Millisatoshi(openchannel['funding_satoshis']).to_satoshi() == 100001:
        return {'result': 'continue', 'close_to': 'bc1qlq8srqnz64wgklmqvurv7qnr4rvtq2u96hhfg2'}

    # - otherwise: accept and don't include the close_to
    plugin.log("accept by design")
    return {'result': 'continue'}


plugin.run()
