from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import (
    only_one, first_scid, GenChannel, generate_gossip_store,
    sync_blockheight, wait_for
)
import pytest
import time


def test_layers(node_factory):
    """Test manipulating information in layers"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    assert l2.rpc.askrene_listlayers() == {'layers': []}
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': []}

    expect = {'layer': 'test_layers',
              'disabled_nodes': [],
              'created_channels': [],
              'constraints': []}
    l2.rpc.askrene_disable_node('test_layers', l1.info['id'])
    expect['disabled_nodes'].append(l1.info['id'])
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}
    assert l2.rpc.askrene_listlayers() == {'layers': [expect]}
    assert l2.rpc.askrene_listlayers('test_layers2') == {'layers': []}

    # Tell it l3 connects to l1!
    l2.rpc.askrene_create_channel('test_layers',
                                  l3.info['id'],
                                  l1.info['id'],
                                  '0x0x1',
                                  '1000000sat',
                                  100, '900000sat',
                                  1, 2, 18)
    expect['created_channels'].append({'source': l3.info['id'],
                                       'destination': l1.info['id'],
                                       'short_channel_id': '0x0x1',
                                       'capacity_msat': 1000000000,
                                       'htlc_minimum_msat': 100,
                                       'htlc_maximum_msat': 900000000,
                                       'fee_base_msat': 1,
                                       'fee_proportional_millionths': 2,
                                       'delay': 18})
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}

    # We can tell it about made up channels...
    first_timestamp = int(time.time())
    l2.rpc.askrene_inform_channel('test_layers',
                                  '0x0x1',
                                  1,
                                  100000)
    last_timestamp = int(time.time()) + 1
    expect['constraints'].append({'short_channel_id': '0x0x1',
                                  'direction': 1,
                                  'minimum_msat': 100000})
    # Check timestamp first.
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    ts1 = only_one(only_one(listlayers['layers'])['constraints'])['timestamp']
    assert first_timestamp <= ts1 <= last_timestamp
    expect['constraints'][0]['timestamp'] = ts1
    assert listlayers == {'layers': [expect]}

    # Make sure timestamps differ!
    time.sleep(2)

    # We can tell it about existing channels...
    scid12 = first_scid(l1, l2)
    first_timestamp = int(time.time())
    l2.rpc.askrene_inform_channel(layer='test_layers',
                                  short_channel_id=scid12,
                                  # This is l2 -> l1
                                  direction=0,
                                  maximum_msat=12341234)
    last_timestamp = int(time.time()) + 1
    expect['constraints'].append({'short_channel_id': scid12,
                                  'direction': 0,
                                  'timestamp': first_timestamp,
                                  'maximum_msat': 12341234})
    # Check timestamp first.
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    ts2 = only_one([c['timestamp'] for c in only_one(listlayers['layers'])['constraints'] if c['short_channel_id'] == scid12])
    assert first_timestamp <= ts2 <= last_timestamp
    expect['constraints'][1]['timestamp'] = ts2

    # Could be either order!
    actual = expect.copy()
    if only_one(listlayers['layers'])['constraints'][0]['short_channel_id'] == scid12:
        actual['constraints'] = [expect['constraints'][1], expect['constraints'][0]]
    assert listlayers == {'layers': [actual]}

    # Now test aging: ts1 does nothing.
    assert l2.rpc.askrene_age('test_layers', ts1) == {'layer': 'test_layers', 'num_removed': 0}
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [actual]}

    # ts1+1 removes first inform
    assert l2.rpc.askrene_age('test_layers', ts1 + 1) == {'layer': 'test_layers', 'num_removed': 1}
    del expect['constraints'][0]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    # ts2+1 removes other.
    assert l2.rpc.askrene_age('test_layers', ts2 + 1) == {'layer': 'test_layers', 'num_removed': 1}
    del expect['constraints'][0]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}


def check_route_as_expected(routes, paths):
    """Make sure all fields in paths are match those in routes"""
    def dict_subset_eq(a, b):
        """Is every key in B is the same in A?"""
        return all(a.get(key) == b[key] for key in b)

    for path in paths:
        found = False
        for i in range(len(routes)):
            route = routes[i]
            if len(route['path']) != len(path):
                continue
            if all(dict_subset_eq(route['path'][i], path[i]) for i in range(len(path))):
                del routes[i]
                found = True
                break
        if not found:
            raise ValueError("Could not find path {} in paths {}".format(path, routes))

    if routes != []:
        raise ValueError("Did not expect paths {}".format(routes))


def check_getroute_paths(node,
                         source,
                         destination,
                         amount_msat,
                         paths,
                         layers=[],
                         maxfee_msat=1000,
                         final_cltv=99):
    """Check that routes are as expected in result"""
    getroutes = node.rpc.getroutes(source=source,
                                   destination=destination,
                                   amount_msat=amount_msat,
                                   layers=layers,
                                   maxfee_msat=maxfee_msat,
                                   final_cltv=final_cltv)

    assert getroutes['probability_ppm'] <= 1000000
    # Total delivered should be amount we told it to send.
    assert amount_msat == sum([r['amount_msat'] for r in getroutes['routes']])

    check_route_as_expected(getroutes['routes'], paths)


def test_getroutes(node_factory):
    """Test getroutes call"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=9000),
                                             GenChannel(1, 3, forward=GenChannel.Half(propfee=20000)),
                                             GenChannel(0, 2, capacity_sats=10000),
                                             GenChannel(2, 4, forward=GenChannel.Half(delay=2000))])

    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Start easy
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999999,
                                               'routes': [{'probability_ppm': 999999,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000,
                                                           'path': [{'short_channel_id': '0x1x0',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1010,
                                                                     'delay': 99 + 6}]}]}
    # Two hop, still easy.
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[3],
                            amount_msat=100000,
                            layers=[],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 999798,
                                               'routes': [{'probability_ppm': 999798,
                                                           'final_cltv': 99,
                                                           'amount_msat': 100000,
                                                           'path': [{'short_channel_id': '0x1x0',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 103020,
                                                                     'delay': 99 + 6 + 6},
                                                                    {'short_channel_id': '1x3x2',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[3],
                                                                     'amount_msat': 102000,
                                                                     'delay': 99 + 6}
                                                                    ]}]}

    # Too expensive
    with pytest.raises(RpcError, match="Could not find route without excessive cost"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[3],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         final_cltv=99)

    # Too much delay (if final delay too great!)
    l1.rpc.getroutes(source=nodemap[0],
                     destination=nodemap[4],
                     amount_msat=100000,
                     layers=[],
                     maxfee_msat=100,
                     final_cltv=6)
    with pytest.raises(RpcError, match="Could not find route without excessive delays"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[4],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         final_cltv=99)

    # Two choices, but for <= 1000 sats we choose the larger.
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[2],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 900000,
                                               'routes': [{'probability_ppm': 900000,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000000,
                                                           'path': [{'short_channel_id': '0x2x3',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[2],
                                                                     'amount_msat': 1000001,
                                                                     'delay': 99 + 6}]}]}

    # For 10000 sats, we will split.
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[2],
                         10000000,
                         [[{'short_channel_id': '0x2x1',
                            'next_node_id': nodemap[2],
                            'amount_msat': 500000,
                            'delay': 99 + 6}],
                          [{'short_channel_id': '0x2x3',
                            'next_node_id': nodemap[2],
                            'amount_msat': 9500009,
                            'delay': 99 + 6}]])


def test_getroutes_fee_fallback(node_factory):
    """Test getroutes call takes into account fees, if excessive"""

    # 0 -> 1 -> 3: high capacity, high fee (1%)
    # 0 -> 2 -> 3: low capacity, low fee.
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1,
                                                        capacity_sats=20000,
                                                        forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2,
                                                        capacity_sats=10000),
                                             GenChannel(1, 3,
                                                        capacity_sats=20000,
                                                        forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(2, 3,
                                                        capacity_sats=10000)])
    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Don't hit maxfee?  Go easy path.
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[3],
                         10000,
                         maxfee_msat=201,
                         paths=[[{'short_channel_id': '0x1x0'},
                                 {'short_channel_id': '1x3x2'}]])

    # maxfee exceeded?  lower prob path.
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[3],
                         10000,
                         maxfee_msat=200,
                         paths=[[{'short_channel_id': '0x2x1'},
                                 {'short_channel_id': '2x3x3'}]])


def test_getroutes_auto_sourcefree(node_factory):
    """Test getroutes call with auto.sourcefree layer"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=9000),
                                             GenChannel(1, 3, forward=GenChannel.Half(propfee=20000)),
                                             GenChannel(0, 2, capacity_sats=10000),
                                             GenChannel(2, 4, forward=GenChannel.Half(delay=2000))])

    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Start easy
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=['auto.sourcefree'],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999999,
                                               'routes': [{'probability_ppm': 999999,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000,
                                                           'path': [{'short_channel_id': '0x1x0',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1000,
                                                                     'delay': 99}]}]}
    # Two hop, still easy.
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[3],
                            amount_msat=100000,
                            layers=['auto.sourcefree'],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 999798,
                                               'routes': [{'probability_ppm': 999798,
                                                           'final_cltv': 99,
                                                           'amount_msat': 100000,
                                                           'path': [{'short_channel_id': '0x1x0',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 102000,
                                                                     'delay': 99 + 6},
                                                                    {'short_channel_id': '1x3x2',
                                                                     'direction': 1,
                                                                     'next_node_id': nodemap[3],
                                                                     'amount_msat': 102000,
                                                                     'delay': 99 + 6}
                                                                    ]}]}

    # Too expensive
    with pytest.raises(RpcError, match="Could not find route without excessive cost"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[3],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         final_cltv=99)

    # Too much delay (if final delay too great!)
    l1.rpc.getroutes(source=nodemap[0],
                     destination=nodemap[4],
                     amount_msat=100000,
                     layers=[],
                     maxfee_msat=100,
                     final_cltv=6)
    with pytest.raises(RpcError, match="Could not find route without excessive delays"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[4],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         final_cltv=99)


def test_getroutes_auto_localchans(node_factory):
    """Test getroutes call with auto.localchans layer"""
    l1 = node_factory.get_node()
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(1, 2, forward=GenChannel.Half(propfee=10000))],
                                            nodemap={0: l1.info['id']})

    # We get bad signature warnings, since our gossip is made up!
    l2 = node_factory.get_node(allow_warning=True, gossip_store_file=gsfile.name)

    # Now l2 believes l1 has an entire network behind it.
    scid12, _ = l2.fundchannel(l1, 10**6, announce_channel=False)

    # Cannot find a route unless we use local hints.
    with pytest.raises(RpcError, match="Unknown source node {}".format(l2.info['id'])):
        l2.rpc.getroutes(source=l2.info['id'],
                         destination=nodemap[2],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100000,
                         final_cltv=99)

    # This should work
    check_getroute_paths(l2,
                         l2.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans'],
                         paths=[[{'short_channel_id': scid12, 'amount_msat': 102012, 'delay': 99 + 6 + 6 + 6},
                                 {'short_channel_id': '0x1x0', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '1x2x1', 'amount_msat': 101000, 'delay': 99 + 6}]])

    # This should get self-discount correct
    check_getroute_paths(l2,
                         l2.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans', 'auto.sourcefree'],
                         paths=[[{'short_channel_id': scid12, 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '0x1x0', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '1x2x1', 'amount_msat': 101000, 'delay': 99 + 6}]])


def test_fees_dont_exceed_constraints(node_factory):
    msat = 100000000
    max_msat = int(msat * 0.45)
    # 0 has to use two paths (1 and 2) to reach 3.  But we tell it 0->1 has limited capacity.
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(1, 3, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(2, 3, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000))])

    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    chan = only_one([c for c in l1.rpc.listchannels(source=nodemap[0])['channels'] if c['destination'] == nodemap[1]])
    l1.rpc.askrene_inform_channel(layer='test_layers',
                                  short_channel_id=chan['short_channel_id'],
                                  direction=chan['direction'],
                                  maximum_msat=max_msat)

    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=nodemap[3],
                              amount_msat=msat,
                              layers=['test_layers'],
                              maxfee_msat=msat,
                              final_cltv=99)['routes']
    assert len(routes) == 2
    for hop in routes[0]['path'] + routes[1]['path']:
        if hop['short_channel_id'] == chan['short_channel_id']:
            amount = hop['amount_msat']
    assert amount <= max_msat


def test_sourcefree_on_mods(node_factory, bitcoind):
    """auto.sourcefree should also apply to layer-created channels"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, forward=GenChannel.Half(propfee=10000))])

    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Add a local channel from 0->l1 (we just needed a nodeid).
    l1.rpc.askrene_create_channel('test_layers',
                                  nodemap[0],
                                  l1.info['id'],
                                  '0x3x3',
                                  '1000000sat',
                                  100, '900000sat',
                                  1000, 2000, 18)
    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=l1.info['id'],
                              amount_msat=1000000,
                              layers=['test_layers', 'auto.sourcefree'],
                              maxfee_msat=100000,
                              final_cltv=99)['routes']
    # Expect no fee.
    check_route_as_expected(routes, [[{'short_channel_id': '0x3x3',
                                       'amount_msat': 1000000, 'delay': 99}]])

    # Same if we specify layers in the other order!
    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=l1.info['id'],
                              amount_msat=1000000,
                              layers=['auto.sourcefree', 'test_layers'],
                              maxfee_msat=100000,
                              final_cltv=99)['routes']
    # Expect no fee.
    check_route_as_expected(routes, [[{'short_channel_id': '0x3x3',
                                       'amount_msat': 1000000, 'delay': 99}]])


def test_live_spendable(node_factory, bitcoind):
    """Test we don't exceed spendable limits on a real network on nodes"""
    l1, l2, l3 = node_factory.get_nodes(3)
    l1.fundwallet(10_000_000)
    l2.fundwallet(10_000_000)
    l1.rpc.connect(l2.info['id'], 'localhost', port=l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', port=l3.port)

    capacities = (100_000, 100_000, 200_000, 300_000, 400_000)
    for capacity in capacities:
        l1.rpc.fundchannel(l2.info["id"], capacity, mindepth=1)
        l2.rpc.fundchannel(l3.info["id"], capacity, mindepth=1)

        bitcoind.generate_block(1, wait_for_mempool=2)
        sync_blockheight(bitcoind, [l1, l2])

    bitcoind.generate_block(5)
    wait_for(lambda: len(l1.rpc.listchannels()["channels"]) == 2 * 2 * len(capacities))

    routes = l1.rpc.getroutes(
        source=l1.info["id"],
        destination=l3.info["id"],
        amount_msat=800_000_001,
        layers=["auto.localchans", "auto.sourcefree"],
        maxfee_msat=50_000_000,
        final_cltv=10,
    )

    # Don't exceed spendable_msat
    maxes = {}
    for chan in l1.rpc.listpeerchannels()["channels"]:
        maxes["{}/{}".format(chan["short_channel_id"], chan["direction"])] = chan[
            "spendable_msat"
        ]

    path_total = {}
    num_htlcs = {}
    for r in routes["routes"]:
        key = "{}/{}".format(
            r["path"][0]["short_channel_id"], r["path"][0]["direction"]
        )
        path_total[key] = path_total.get(key, 0) + r["path"][0]["amount_msat"]
        num_htlcs[key] = num_htlcs.get(key, 0) + 1

    # Take into account 645000msat (3750 feerate x 172 weight) per-HTLC reduction in capacity.
    for k in path_total.keys():
        if k in maxes:
            maxes[k] -= (3750 * 172) * (num_htlcs[k] - 1)

    exceeded = {}
    for scidd in maxes.keys():
        if scidd in path_total:
            if path_total[scidd] > maxes[scidd]:
                exceeded[scidd] = f"Path total {path_total[scidd]} > spendable {maxes[scidd]}"

    assert exceeded == {}

    # No duplicate paths!
    for i in range(0, len(routes["routes"])):
        path_i = [(p['short_channel_id'], p['direction']) for p in routes["routes"][i]['path']]
        for j in range(i + 1, len(routes["routes"])):
            path_j = [(p['short_channel_id'], p['direction']) for p in routes["routes"][j]['path']]
            assert path_i != path_j

    # Must deliver exact amount.
    assert sum(r['amount_msat'] for r in routes["routes"]) == 800_000_001


def test_limits_fake_gossmap(node_factory, bitcoind):
    """Like test_live_spendable, but using a generated gossmap not real nodes"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=100_000),
                                             GenChannel(0, 1, capacity_sats=100_000),
                                             GenChannel(0, 1, capacity_sats=200_000),
                                             GenChannel(0, 1, capacity_sats=300_000),
                                             GenChannel(0, 1, capacity_sats=400_000),
                                             GenChannel(1, 2, capacity_sats=100_000),
                                             GenChannel(1, 2, capacity_sats=100_000),
                                             GenChannel(1, 2, capacity_sats=200_000),
                                             GenChannel(1, 2, capacity_sats=300_000),
                                             GenChannel(1, 2, capacity_sats=400_000)])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Create a layer like auto.localchans would from "spendable"
    spendable = {'0x1x0/1': 87718000,
                 '0x1x1/1': 87718000,
                 '0x1x2/1': 186718000,
                 '0x1x3/1': 285718000,
                 '0x1x4/1': 384718000}

    # Sanity check that these exist!
    for scidd in spendable:
        assert scidd in [f"{c['short_channel_id']}/{c['direction']}" for c in l1.rpc.listchannels(source=nodemap[0])['channels']]

    for scidd, amount in spendable.items():
        chan, direction = scidd.split('/')
        l1.rpc.askrene_inform_channel(layer='localchans',
                                      short_channel_id=chan, direction=int(direction),
                                      minimum_msat=amount)
        l1.rpc.askrene_inform_channel(layer='localchans',
                                      short_channel_id=chan, direction=int(direction),
                                      maximum_msat=amount)

    routes = l1.rpc.getroutes(
        source=nodemap[0],
        destination=nodemap[2],
        amount_msat=800_000_001,
        layers=["localchans", "auto.sourcefree"],
        maxfee_msat=50_000_000,
        final_cltv=10,
    )

    path_total = {}
    for r in routes["routes"]:
        key = "{}/{}".format(
            r["path"][0]["short_channel_id"], r["path"][0]["direction"]
        )
        path_total[key] = path_total.get(key, 0) + r["path"][0]["amount_msat"]

    exceeded = {}
    for scidd in spendable.keys():
        if scidd in path_total:
            if path_total[scidd] > spendable[scidd]:
                exceeded[scidd] = f"Path total {path_total[scidd]} > spendable {spendable[scidd]}"

    assert exceeded == {}

    # No duplicate paths!
    for i in range(0, len(routes["routes"])):
        path_i = [(p['short_channel_id'], p['direction']) for p in routes["routes"][i]['path']]
        for j in range(i + 1, len(routes["routes"])):
            path_j = [(p['short_channel_id'], p['direction']) for p in routes["routes"][j]['path']]
            assert path_i != path_j

    # Must deliver exact amount.
    assert sum(r['amount_msat'] for r in routes["routes"]) == 800_000_001


def test_max_htlc(node_factory, bitcoind):
    """A route which looks good isn't actually, because of max htlc limits"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=500_000,
                                                        forward=GenChannel.Half(htlc_max=1_000_000)),
                                             GenChannel(0, 1, capacity_sats=20_000)])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=nodemap[1],
                              amount_msat=20_000_000,
                              layers=[],
                              maxfee_msat=20_000_000,
                              final_cltv=10)

    check_route_as_expected(routes['routes'],
                            [[{'short_channel_id': '0x1x0', 'amount_msat': 1_000_001, 'delay': 10 + 6}],
                             [{'short_channel_id': '0x1x1', 'amount_msat': 19_000_019, 'delay': 10 + 6}]])

    # If we can't use channel 2, we fail.
    l1.rpc.askrene_inform_channel(layer='removechan2',
                                  short_channel_id='0x1x1', direction=1,
                                  maximum_msat=0)

    # FIXME: Better diag!
    with pytest.raises(RpcError, match="Could not find route"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=20_000_000,
                         layers=['removechan2'],
                         maxfee_msat=20_000_000,
                         final_cltv=10)


def test_min_htlc(node_factory, bitcoind):
    """A route which looks good isn't actually, because of min htlc limits"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=500_000,
                                                        forward=GenChannel.Half(htlc_min=2_000)),
                                             GenChannel(0, 1, capacity_sats=20_000)])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    with pytest.raises(RpcError, match="Amount 1000msat below minimum across 0x1x0/1"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=1000,
                         layers=[],
                         maxfee_msat=20_000_000,
                         final_cltv=10)


def test_min_htlc_after_excess(node_factory, bitcoind):
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=500_000,
                                                        forward=GenChannel.Half(htlc_min=2_000))])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    with pytest.raises(RpcError, match=r"ending 1999msat across 0x1x0/1 would violate htlc_min \(~2000msat\)"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=1999,
                         layers=[],
                         maxfee_msat=20_000_000,
                         final_cltv=10)


def test_reserve(node_factory):
    """Test reserves"""
    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node()
    expected = {
        "short_channel_id": "1x1x1",
        "direction": 0,
        "num_htlcs": 0,
        "amount_msat": 0,
    }

    assert l1.rpc.askrene_query_reserve("1x1x1", 0) == expected

    l1.rpc.askrene_reserve(
        [{"short_channel_id": "1x1x1", "direction": 0, "amount_msat": 105}]
    )
    expected["num_htlcs"] += 1
    expected["amount_msat"] += 105

    assert l1.rpc.askrene_query_reserve("1x1x1", 0) == expected

    l1.rpc.askrene_reserve(
        [{"short_channel_id": "1x1x1", "direction": 0, "amount_msat": 900}]
    )
    expected["num_htlcs"] += 1
    expected["amount_msat"] += 900

    assert l1.rpc.askrene_query_reserve("1x1x1", 0) == expected

    l1.rpc.askrene_unreserve(
        [{"short_channel_id": "1x1x1", "direction": 0, "amount_msat": 105}]
    )
    expected["num_htlcs"] -= 1
    expected["amount_msat"] -= 105

    assert l1.rpc.askrene_query_reserve("1x1x1", 0) == expected

    l1.rpc.askrene_unreserve(
        [{"short_channel_id": "1x1x1", "direction": 0, "amount_msat": 900}]
    )
    expected["num_htlcs"] -= 1
    expected["amount_msat"] -= 900

    assert l1.rpc.askrene_query_reserve("1x1x1", 0) == expected
