#!/usr/bin/env python3
from pyln.client import Plugin, Millisatoshi


plugin = Plugin()


@plugin.method("helpme")
def helpme(plugin, msat: Millisatoshi):
    """This is a message which consumes multiple lines and thus should
    be well-formatted by lightning-cli help

    """
    return {'help': msat}


plugin.run()
