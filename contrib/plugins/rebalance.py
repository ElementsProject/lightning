#!/usr/bin/env python3
from lightning import Plugin, RpcError
import time
import uuid

plugin = Plugin()


def setup_routing_fees(plugin, route, msatoshi):
    delay = int(plugin.get_option('cltv-final'))
    for r in reversed(route):
        r['msatoshi'] = msatoshi
        r['amount_msat'] = str(msatoshi) + "msat"
        r['delay'] = delay
        channels = plugin.rpc.listchannels(r['channel'])
        for ch in channels.get('channels'):
            if ch['destination'] == r['id']:
                fee = ch['base_fee_millisatoshi']
                fee += msatoshi * ch['fee_per_millionth'] // 1000000
                msatoshi += fee
                delay += ch['delay']


def peer2channel(plugin, channel_id, my_node_id, payload):
    channels = plugin.rpc.listchannels(channel_id).get('channels')
    for ch in channels:
        if ch['source'] == my_node_id:
            return ch['destination']
    raise RpcError("rebalance", payload, {'message': 'Cannot find peer for channel: ' + channel_id})


def find_worst_channel(route):
    if len(route) < 4:
        return None
    start_id = 2
    worst = route[start_id]['channel']
    worst_val = route[start_id - 1]['msatoshi'] - route[start_id]['msatoshi']
    for i in range(start_id + 1, len(route) - 1):
        val = route[i - 1]['msatoshi'] - route[i]['msatoshi']
        if val > worst_val:
            worst = route[i]['channel']
            worst_val = val
    return worst


def rebalance_fail(plugin, label, payload, success_msg, error=None):
    try:
        plugin.rpc.delinvoice(label, 'unpaid')
    except RpcError as e:
        # race condition: waitsendpay timed out, but invoice get paid
        if 'status is paid' in e.error.get('message', ""):
            return success_msg
    if error is None:
        error = RpcError("rebalance", payload, {'message': 'Rebalance failed'})
    raise error


@plugin.method("rebalance")
def rebalance(plugin, outgoing_channel_id, incoming_channel_id, msatoshi, maxfeepercent="0.5",
              retry_for="60", exemptfee="5000"):
    """Rebalancing channel liquidity with circular payments.

    This tool helps to move some msatoshis between your channels.

    """
    payload = {
        "outgoing_channel_id": outgoing_channel_id,
        "incoming_channel_id": incoming_channel_id,
        "msatoshi": msatoshi,
        "maxfeepercent": maxfeepercent,
        "retry_for": retry_for,
        "exemptfee": exemptfee
    }
    my_node_id = plugin.rpc.getinfo().get('id')
    outgoing_node_id = peer2channel(plugin, outgoing_channel_id, my_node_id, payload)
    incoming_node_id = peer2channel(plugin, incoming_channel_id, my_node_id, payload)
    plugin.log("Outgoing node: %s, channel: %s" % (outgoing_node_id, outgoing_channel_id))
    plugin.log("Incoming node: %s, channel: %s" % (incoming_node_id, incoming_channel_id))

    route_out = {'id': outgoing_node_id, 'channel': outgoing_channel_id}
    route_in = {'id': my_node_id, 'channel': incoming_channel_id}
    start_ts = int(time.time())
    label = "Rebalance-" + str(uuid.uuid4())
    description = "%s to %s" % (outgoing_channel_id, incoming_channel_id)
    invoice = plugin.rpc.invoice(msatoshi, label, description, int(retry_for) + 60)
    payment_hash = invoice['payment_hash']
    plugin.log("Invoice payment_hash: %s" % payment_hash)
    success_msg = ""
    try:
        excludes = [outgoing_channel_id + "/0", incoming_channel_id + "/0"]
        while int(time.time()) - start_ts < int(retry_for):
            r = plugin.rpc.getroute(incoming_node_id, msatoshi, riskfactor=1, cltv=9, fromid=outgoing_node_id,
                                    exclude=excludes)
            route_mid = r['route']
            route = [route_out] + route_mid + [route_in]
            setup_routing_fees(plugin, route, msatoshi)
            fees = route[0]['msatoshi'] - route[-1]['msatoshi']
            if fees > int(exemptfee) and fees > msatoshi * float(maxfeepercent) / 100:
                worst_channel_id = find_worst_channel(route)
                if worst_channel_id is None:
                    raise RpcError("rebalance", payload, {'message': 'Insufficient fee'})
                excludes += [worst_channel_id + '/0', worst_channel_id + '/1']
                continue
            try:
                plugin.log("Sending %dmsat over %d hops to rebalance %dmsat" % (msatoshi + fees, len(route), msatoshi))
                for r in route:
                    plugin.log("Node: %s, channel: %13s, %d msat" % (r['id'], r['channel'], r['msatoshi']))
                success_msg = "%d msat sent over %d hops to rebalance %d msat" % (msatoshi + fees, len(route), msatoshi)
                plugin.rpc.sendpay(route, payment_hash)
                plugin.rpc.waitsendpay(payment_hash, int(retry_for) + start_ts - int(time.time()))
                return success_msg
            except RpcError as e:
                plugin.log("RpcError: " + str(e))
                erring_channel = e.error.get('data', {}).get('erring_channel')
                if erring_channel == incoming_channel_id:
                    raise RpcError("rebalance", payload, {'message': 'Error with incoming channel'})
                if erring_channel == outgoing_channel_id:
                    raise RpcError("rebalance", payload, {'message': 'Error with outgoing channel'})
                erring_direction = e.error.get('data', {}).get('erring_direction')
                if erring_channel is not None and erring_direction is not None:
                    excludes.append(erring_channel + '/' + str(erring_direction))
    except Exception as e:
        plugin.log("Exception: " + str(e))
        return rebalance_fail(plugin, label, payload, success_msg, e)
    return rebalance_fail(plugin, label, payload, success_msg)


@plugin.init()
def init(options, configuration, plugin):
    plugin.options['cltv-final']['value'] = plugin.rpc.listconfigs().get('cltv-final')
    plugin.log("Plugin rebalance.py initialized")


plugin.add_option('cltv-final', 10, 'Number of blocks for final CheckLockTimeVerify expiry')
plugin.run()
