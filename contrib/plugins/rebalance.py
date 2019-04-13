#!/usr/bin/env python3
from lightning import Plugin, RpcError
import time

plugin = Plugin(autopatch=True)


def setup_routing_fees(plugin, route, msatoshi):
    delay = 9
    for r in reversed(route):
        r['msatoshi'] = msatoshi
        r['amount_msat'] = str(msatoshi) + "msat"
        r['delay'] = delay
        channels = plugin.rpc.listchannels(r['channel'])
        for ch in channels.get('channels'):
            if ch['destination'] == r['id']:
                fee = ch['base_fee_millisatoshi']
                fee += msatoshi * ch['fee_per_millionth'] / 1000000
                msatoshi += round(fee)
                delay += ch['delay']


def peer2channel(plugin, channel_id, my_node_id):
    channels = plugin.rpc.listchannels(channel_id).get('channels')
    for ch in channels:
        if ch['source'] == my_node_id:
            return ch['destination']
    raise ValueError('Cannot find peer for channel: ' + channel_id)


@plugin.method("rebalance")
def rebalance(plugin, outgoing_channel_id, incoming_channel_id, msatoshi, maxfeepercent="0.5",
              retry_for="60", exemptfee="5000"):
    """Rebalancing channel liquidity with circular payments.

    This tool helps to move some msatoshis between your channels.

    """
    my_node_id = plugin.rpc.getinfo().get('id')
    outgoing_node_id = peer2channel(plugin, outgoing_channel_id, my_node_id)
    incoming_node_id = peer2channel(plugin, incoming_channel_id, my_node_id)
    plugin.log("Outgoing node: %s, channel: %s" % (outgoing_node_id, outgoing_channel_id))
    plugin.log("Incoming node: %s, channel: %s" % (incoming_node_id, incoming_channel_id))

    route_out = {'id': outgoing_node_id, 'channel': outgoing_channel_id}
    route_in = {'id': my_node_id, 'channel': incoming_channel_id}
    start_ts = int(time.time())
    label = "Rebalance" + str(start_ts)
    invoice = plugin.rpc.invoice(msatoshi, label, "Rebalance", int(retry_for) + 60)
    payment_hash = invoice['payment_hash']
    plugin.log("Invoice payment_hash: %s" % payment_hash)
    try:
        error_logs = ""
        erring_channel_msg = "\'erring_channel\': \'%s\'"
        while int(time.time()) - start_ts < int(retry_for):
            try:
                r = plugin.rpc.getroute(incoming_node_id, msatoshi, riskfactor=1, cltv=9, fromid=outgoing_node_id)
                route_mid = r['route']
            except RpcError:
                # sometimes there is a route, but getroute raises 'Could not find a route' exception
                continue
            if any(r['id'] == my_node_id for r in route_mid):
                continue
            if any(erring_channel_msg % r['channel'] in error_logs for r in route_mid):
                continue
            route = [route_out] + route_mid + [route_in]
            setup_routing_fees(plugin, route, msatoshi)
            fees = route[0]['msatoshi'] - route[-1]['msatoshi']
            if fees > int(exemptfee) and fees > msatoshi * float(maxfeepercent) / 100:
                continue
            try:
                plugin.log("Sending %dmsat over %d hops to rebalance %dmsat" % (msatoshi + fees, len(route), msatoshi))
                for r in route:
                    plugin.log("Node: %s, channel: %13s, %d msat" % (r['id'], r['channel'], r['msatoshi']))
                plugin.rpc.sendpay(route, payment_hash)
                plugin.rpc.waitsendpay(payment_hash, int(retry_for) + start_ts - int(time.time()))
                return "%d msat sent over %d hops to rebalance %d msat" % (msatoshi + fees, len(route), msatoshi)
            except RpcError as e:
                plugin.log("RpcError: " + str(e))
                error_logs += str(e)
                if erring_channel_msg % incoming_channel_id in str(e):
                    return "Error with incoming channel"
                if erring_channel_msg % outgoing_channel_id in str(e):
                    return "Error with outgoing channel"
    except Exception as e:
        plugin.log("Exception: " + str(e))
    plugin.rpc.delinvoice(label, "unpaid")
    msg = "Rebalance failed"
    plugin.log(msg)
    return msg


@plugin.init()
def init(options, configuration, plugin):
    plugin.log("Plugin rebalance.py initialized")


plugin.run()
