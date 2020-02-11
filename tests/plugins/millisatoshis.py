#!/usr/bin/env python3
from pyln.client import Plugin, Millisatoshi


plugin = Plugin(autopatch=True)


@plugin.method("echo")
def echo(plugin, msat: Millisatoshi, not_an_msat):
    plugin.log("got echo for {} {} (types {} and {})"
               .format(msat, not_an_msat, type(msat), type(not_an_msat)))
    if not isinstance(msat, Millisatoshi):
        raise TypeError("msat must be Millisatoshi not {}".format(type(msat)))
    if isinstance(not_an_msat, Millisatoshi):
        raise TypeError("not_an_msat must not be Millisatoshi")
    plugin.log("got echo for {} (type {})".format(msat, type(msat)))
    if not isinstance(msat, Millisatoshi):
        raise TypeError("msat must be Millisatoshi not {}".format(type(msat)))
    plugin.log("Returning {}".format(msat))
    return {'echo_msat': msat}


plugin.run()
