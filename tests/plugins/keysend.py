#!/usr/bin/env python3
"""Temporary keysend plugin until we implement it in C

This plugin is just used to test the ability to receive keysend payments until
we implement it in `plugins/keysend.c`. Most of this code is borrowed from the
noise plugin.

"""

from pyln.client import Plugin, RpcError
from pyln.proto.onion import TlvPayload, Tu32Field, Tu64Field
from binascii import hexlify
import os
import hashlib
import struct


plugin = Plugin()
TLV_KEYSEND_PREIMAGE = 5482373484


def serialize_payload(n, blockheight):
    """Serialize a legacy payload.
    """
    block, tx, out = n['channel'].split('x')
    payload = hexlify(struct.pack(
        "!cQQL", b'\x00',
        int(block) << 40 | int(tx) << 16 | int(out),
        int(n['amount_msat']),
        blockheight + n['delay'])).decode('ASCII')
    payload += "00" * 12
    return payload


def buildpath(plugin, node_id, payload, amt, exclusions):
    blockheight = plugin.rpc.getinfo()['blockheight']
    route = plugin.rpc.getroute(node_id, amt, 10, exclude=exclusions)['route']
    first_hop = route[0]
    # Need to shift the parameters by one hop
    hops = []
    for h, n in zip(route[:-1], route[1:]):
        # We tell the node h about the parameters to use for n (a.k.a. h + 1)
        hops.append({
            "type": "legacy",
            "pubkey": h['id'],
            "payload": serialize_payload(n, blockheight)
        })

    pl = TlvPayload()
    pl.fields.append(Tu64Field(2, amt))
    pl.fields.append(Tu32Field(4, route[-1]['delay']))

    for f in payload.fields:
        pl.add_field(f.typenum, f.value)

    # The last hop has a special payload:
    hops.append({
        "type": "tlv",
        "pubkey": route[-1]['id'],
        "payload": hexlify(pl.to_bytes()).decode('ASCII'),
    })
    print(f"Keysend payload {hexlify(pl.to_bytes())}")
    return first_hop, hops, route


def deliver(node_id, payload, amt, payment_hash, max_attempts=5):
    """Do your best to deliver `payload` to `node_id`.
    """
    exclusions = []
    payment_hash = hexlify(payment_hash).decode('ASCII')

    for attempt in range(max_attempts):
        plugin.log("Starting attempt {} to deliver message to {}".format(attempt, node_id))

        first_hop, hops, route = buildpath(plugin, node_id, payload, amt, exclusions)
        onion = plugin.rpc.createonion(hops=hops, assocdata=payment_hash)

        plugin.rpc.sendonion(
            onion=onion['onion'],
            first_hop=first_hop,
            payment_hash=payment_hash,
            shared_secrets=onion['shared_secrets'],
        )
        try:
            plugin.rpc.waitsendpay(payment_hash=payment_hash)
            return {'route': route, 'payment_hash': payment_hash, 'attempt': attempt}
        except RpcError as e:
            failcode = e.error['data']['failcode']
            failingidx = e.error['data']['erring_index']
            if failcode == 16399 or failingidx == len(hops):
                return {
                    'route': route,
                    'payment_hash': payment_hash,
                    'attempt': attempt + 1
                }

            plugin.log("Retrying delivery.")

            # TODO Store the failing channel in the exclusions
    raise ValueError('Could not reach destination {node_id}'.format(node_id=node_id))


@plugin.method('keysend')
def keysend(node_id, amount, plugin):
    payload = TlvPayload()
    payment_key = os.urandom(32)
    payment_hash = hashlib.sha256(payment_key).digest()
    payload.add_field(TLV_KEYSEND_PREIMAGE, payment_key)
    res = deliver(
        node_id,
        payload,
        amt=amount,
        payment_hash=payment_hash
    )
    return res


plugin.run()
