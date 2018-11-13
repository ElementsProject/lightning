# pylightning: A python client library for lightningd

### Installation

Note: With Python 2 you need to have the futures python library installed to be able to use pylightning:

```
pip install futures
```

pylightning is available on pip 

```
pip install pylightning
```

### Examples

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

Also see the included [lightning-pay](./lightning-pay) script, which uses the client library to pay invoices

```sh
lightning-pay <bolt11 invoice>
# or explicitly with
lightning-pay <destination_id> <amount in millisatoshi> <payment_hash> <min_final_cltv_expiry>
```
