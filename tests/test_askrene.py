from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import (
    only_one, first_scid, GenChannel, generate_gossip_store,
    TEST_NETWORK, sync_blockheight, wait_for
)
import os
import pytest
import time
import shutil


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
    l2.rpc.askrene_create_channels(
        "test_layers",
        [
            {
                "source": l3.info["id"],
                "destination": l1.info["id"],
                "short_channel_id": "0x0x1",
                "capacity_msat": "1000000sat",
                "htlc_minimum_msat": 100,
                "htlc_maximum_msat": "900000sat",
                "fee_base_msat": 1,
                "fee_proportional_millionths": 2,
                "delay": 18,
            }
        ],
    )
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

    def dict_subset_eq(a, b):
        """Is every key in B is the same in A?"""
        return all(a.get(key) == b[key] for key in b)

    for expected_path in paths:
        found = False
        for i in range(len(getroutes['routes'])):
            route = getroutes['routes'][i]
            if len(route['path']) != len(expected_path):
                continue
            if all(dict_subset_eq(route['path'][i], expected_path[i]) for i in range(len(expected_path))):
                del getroutes['routes'][i]
                found = True
                break
        if not found:
            raise ValueError("Could not find expected_path {} in paths {}".format(expected_path, getroutes['routes']))

    if getroutes['routes'] != []:
        raise ValueError("Did not expect paths {}".format(getroutes['routes']))


def test_getroutes(node_factory):
    """Test getroutes call"""
    l1 = node_factory.get_node(start=False)
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=9000),
                                             GenChannel(1, 3, forward=GenChannel.Half(propfee=20000)),
                                             GenChannel(0, 2, capacity_sats=10000),
                                             GenChannel(2, 4, forward=GenChannel.Half(delay=2000))])

    # Set up l1 with this as the gossip_store
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

    # Start easy
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999998,
                                               'routes': [{'probability_ppm': 999998,
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
                            final_cltv=99) == {'probability_ppm': 999797,
                                               'routes': [{'probability_ppm': 999797,
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
                            'amount_msat': 505000,
                            'delay': 99 + 6}],
                          [{'short_channel_id': '0x2x3',
                            'next_node_id': nodemap[2],
                            'amount_msat': 9495009,
                            'delay': 99 + 6}]])


def test_getroutes_fee_fallback(node_factory):
    """Test getroutes call takes into account fees, if excessive"""

    l1 = node_factory.get_node(start=False)
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
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

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
    l1 = node_factory.get_node(start=False)
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=9000),
                                             GenChannel(1, 3, forward=GenChannel.Half(propfee=20000)),
                                             GenChannel(0, 2, capacity_sats=10000),
                                             GenChannel(2, 4, forward=GenChannel.Half(delay=2000))])

    # Set up l1 with this as the gossip_store
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

    # Start easy
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=['auto.sourcefree'],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999998,
                                               'routes': [{'probability_ppm': 999998,
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
                            final_cltv=99) == {'probability_ppm': 999797,
                                               'routes': [{'probability_ppm': 999797,
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
    # We get bad signature warnings, since our gossip is made up!
    l1, l2 = node_factory.get_nodes(2, opts={'allow_warning': True})
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(1, 2, forward=GenChannel.Half(propfee=10000))],
                                            nodeids=[l2.info['id']])

    # Set up l1 with this as the gossip_store
    l1.stop()
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

    # Now l1 beleives l2 has an entire network behind it.
    scid12, _ = l1.fundchannel(l2, 10**6, announce_channel=False)

    # Cannot find a route unless we use local hints.
    with pytest.raises(RpcError, match="Unknown source node {}".format(l1.info['id'])):
        l1.rpc.getroutes(source=l1.info['id'],
                         destination=nodemap[2],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100000,
                         final_cltv=99)

    # This should work
    check_getroute_paths(l1,
                         l1.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans'],
                         paths=[[{'short_channel_id': scid12, 'amount_msat': 102012, 'delay': 99 + 6 + 6 + 6},
                                 {'short_channel_id': '0x1x0', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '1x2x1', 'amount_msat': 101000, 'delay': 99 + 6}]])

    # This should get self-discount correct
    check_getroute_paths(l1,
                         l1.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans', 'auto.sourcefree'],
                         paths=[[{'short_channel_id': scid12, 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '0x1x0', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id': '1x2x1', 'amount_msat': 101000, 'delay': 99 + 6}]])


def test_fees_dont_exceed_constraints(node_factory):
    l1 = node_factory.get_node(start=False)

    msat = 100000000
    max_msat = int(msat * 0.45)
    # 0 has to use two paths (1 and 2) to reach 3.  But we tell it 0->1 has limited capacity.
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(1, 3, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(2, 3, capacity_sats=msat // 1000, forward=GenChannel.Half(propfee=10000))])

    # Set up l1 with this as the gossip_store
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

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
        amount_msat=800_000_000,
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
    for r in routes["routes"]:
        key = "{}/{}".format(
            r["path"][0]["short_channel_id"], r["path"][0]["direction"]
        )
        path_total[key] = path_total.get(key, 0) + r["path"][0]["amount_msat"]

    exceeded = {}
    for scidd in maxes.keys():
        if scidd in path_total:
            if path_total[scidd] > maxes[scidd]:
                exceeded[scidd] = f"Path total {path_total[scidd]} > spendable {maxes[scidd]}"

    assert exceeded == {}
