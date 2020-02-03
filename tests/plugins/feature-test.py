#!/usr/bin/env python3

from pyln.client import Plugin

# Register a different set feature of feature bits for each location so we can
# later check that they are being passed correctly.
plugin = Plugin(
    dynamic=False,
    init_features=1 << 101,
    node_features=1 << 103,
    invoice_features=1 << 105,
)


plugin.run()
