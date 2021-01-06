#!/usr/bin/env python3
"""Simple plugin to cause a waitblockheight that times out.

We report an error with a future blockheight, which causes the sender
to wait, and ultimately retry, excluding us because we misbehaved.

"""


from pyln.client import Plugin
plugin = Plugin()


@plugin.hook('htlc_accepted')
def on_htlc_accepted(onion, htlc, **kwargs):
    return {
        'result': "fail",
        "failure_message": "400f00000000000000007fffffff",  # Bogus error with INT32_MAX as blockheight
    }


plugin.run()
