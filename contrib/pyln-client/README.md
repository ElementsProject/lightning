# pyln-client: A python client library for lightningd

This package implements the Unix socket based JSON-RPC protocol that
`lightningd` exposes to the rest of the world. It can be used to call
arbitrary functions on the RPC interface, and serves as a basis for plugins
written in python.


## Installation

`pyln-client` is available on `pip`:

```
pip install pyln-client
```

Alternatively you can also install the development version to get access to
currently unreleased features by checking out the c-lightning source code and
installing into your python3 environment:

```bash
git clone https://github.com/ElementsProject/lightning.git
cd lightning/contrib/pyln-client
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
from pyln.client import LightningRpc
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
from pyln.client import Plugin

plugin = Plugin()

@plugin.method("hello")
def hello(plugin, name="world"):
    """This is the documentation string for the hello-function.

    It gets reported as the description when registering the function
    as a method with `lightningd`.

    If this returns (a dict), that's the JSON "result" returned.  If
    it raises an exception, that causes a JSON "error" return (raising
    pyln.client.RpcException allows finer control over the return).
    """
    greeting = plugin.get_option('greeting')
    s = '{} {}'.format(greeting, name)
    plugin.log(s)
    return s


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("Plugin helloworld.py initialized")
    # This can also return {'disabled': <reason>} to self-disable,
	# but normally it returns None.


@plugin.subscribe("connect")
def on_connect(plugin, id, address):
    plugin.log("Received connect event for peer {}".format(id))


plugin.add_option('greeting', 'Hello', 'The greeting I should use.')
plugin.run()

```
