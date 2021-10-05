# pylightning: A python client library for lightningd

This package implements the Unix socket based JSON-RPC protocol that
`lightningd` exposes to the rest of the world. It can be used to call
arbitrary functions on the RPC interface, and serves as a basis for plugins
written in python.

If you are writing a new plugin you should use [pyln-client](https://github.com/ElementsProject/lightning/tree/master/contrib/pyln-client)
(the renamed, updated version of pylightning) instead as pylightning is
currently an empty shell around pyln-client.

## Installation

pylightning is available on `pip`:

```
pip install pylightning
```

Alternatively you can also install the development version to get access to
currently unreleased features by checking out the c-lightning source code and
installing into your python3 environment:

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pylightning
python3 setup.py develop
```

This will add links to the library into your environment so changing the
checked out source code will also result in the environment picking up these
changes. Notice however that unreleased versions may change API without
warning, so test thoroughly with the released version.

## Examples


### Using the JSON-RPC client
```py
"""
Generate invoice on one daemon and pay it on the other
"""
from lightning import LightningRpc
import random

# Create two instances of the LightningRpc object using two different c-lightning daemons on your computer
l1 = LightningRpc("/tmp/lightning1/lightning-rpc")
l5 = LightningRpc("/tmp/lightning5/lightning-rpc")

info5 = l5.getinfo()
print(info5)

# Create invoice for test payment
invoice = l5.invoice(100, "lbl{}".format(random.random()), "testpayment")
print(invoice)

# Get route to l1
route = l1.getroute(info5['id'], 100, 1)
print(route)

# Pay invoice
print(l1.sendpay(route['route'], invoice['payment_hash']))
```

### Writing a plugin

Plugins are programs that `lightningd` can be configured to execute alongside
the main daemon. They allow advanced interactions with and customizations to
the daemon.

```python
#!/usr/bin/env python3
from lightning import Plugin

plugin = Plugin()

@plugin.method("hello")
def hello(plugin, name="world"):
    """This is the documentation string for the hello-function.

    It gets reported as the description when registering the function
    as a method with `lightningd`.

    """
    greeting = plugin.get_option('greeting')
    s = '{} {}'.format(greeting, name)
    plugin.log(s)
    return s


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("Plugin helloworld.py initialized")


@plugin.subscribe("connect")
def on_connect(plugin, id, address):
    plugin.log("Received connect event for peer {}".format(id))


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()

```
