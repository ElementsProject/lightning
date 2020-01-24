#!/usr/bin/env python3
"""This plugin is used for an accepter to dual fund a channel.

   If the funding is even, we send back the same amount that they
   asked for, ignoring our own limits.

   If funding is odd, we send back our max amount, ignoring what
   they've requested.
"""

from pyln.client import Plugin, Millisatoshi

plugin = Plugin()


@plugin.hook("openchannel")
def on_openchannel(openchannel, plugin, **kwargs):
    if openchannel['version'] == 1:
        raise ValueError("Not to be used with v1")

    their_funds = Millisatoshi(openchannel['opener_satoshis'])
    # We send back our maximum available funds
    if their_funds.to_satoshi() % 2 == 1:
        our_funds = Millisatoshi(openchannel['available_funds'])
        return {'result': 'continue', 'funding_sats': our_funds.to_satoshi_str()}
    else:
        return {'result': 'continue', 'funding_sats': their_funds.to_satoshi_str()}


plugin.run()
