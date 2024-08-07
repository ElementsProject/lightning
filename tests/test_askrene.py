from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError
from utils import (
    only_one, first_scid, GenChannel, generate_gossip_store,
    TEST_NETWORK
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


def check_getroute_paths(node,
                         source,
                         destination,
                         amount_msat,
                         paths,
                         layers=[],
                         maxfee_msat=1000,
                         finalcltv=99):
    """Check that routes are as expected in result"""
    getroutes = node.rpc.getroutes(source=source,
                                   destination=destination,
                                   amount_msat=amount_msat,
                                   layers=layers,
                                   maxfee_msat=maxfee_msat,
                                   finalcltv=finalcltv)

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
                            finalcltv=99) == {'probability_ppm': 999999,
                                              'routes': [{'probability_ppm': 999999,
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
                            finalcltv=99) == {'probability_ppm': 999798,
                                              'routes': [{'probability_ppm': 999798,
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
                         finalcltv=99)

    # Too much delay (if final delay too great!)
    l1.rpc.getroutes(source=nodemap[0],
                     destination=nodemap[4],
                     amount_msat=100000,
                     layers=[],
                     maxfee_msat=100,
                     finalcltv=6)
    with pytest.raises(RpcError, match="Could not find route without excessive delays"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[4],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         finalcltv=99)

    # Two choices, but for <= 1000 sats we choose the larger.
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[2],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=5000,
                            finalcltv=99) == {'probability_ppm': 900000,
                                              'routes': [{'probability_ppm': 900000,
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
                            finalcltv=99) == {'probability_ppm': 999999,
                                              'routes': [{'probability_ppm': 999999,
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
                            finalcltv=99) == {'probability_ppm': 999798,
                                              'routes': [{'probability_ppm': 999798,
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
                         finalcltv=99)

    # Too much delay (if final delay too great!)
    l1.rpc.getroutes(source=nodemap[0],
                     destination=nodemap[4],
                     amount_msat=100000,
                     layers=[],
                     maxfee_msat=100,
                     finalcltv=6)
    with pytest.raises(RpcError, match="Could not find route without excessive delays"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[4],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         finalcltv=99)
