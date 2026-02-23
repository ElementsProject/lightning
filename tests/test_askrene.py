from fixtures import *  # noqa: F401,F403
from hashlib import sha256
from pyln.client import RpcError
from pyln.testing.utils import SLOW_MACHINE
from utils import (
    only_one, first_scid, first_scidd, GenChannel, generate_gossip_store,
    sync_blockheight, wait_for, TEST_NETWORK, TIMEOUT, mine_funding_to_announce
)
import os
import pytest
import subprocess
import time
import tempfile
import unittest


def direction(src, dst):
    """BOLT 7 direction: 0 means from lesser encoded id"""
    if src < dst:
        return 0
    return 1


def scid_dir(nodemap, node1_idx, node2_idx, chan_idx):
    """Get short_channel_id_dir for a channel in generate_gossip_store format"""
    dir_val = direction(nodemap[node1_idx], nodemap[node2_idx])
    return f"{node1_idx}x{node2_idx}x{chan_idx}/{dir_val}"


def test_reserve(node_factory):
    """Test reserving channels"""
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    assert l1.rpc.askrene_listreservations() == {'reservations': []}
    scid12 = first_scid(l1, l2)
    scid23 = first_scid(l2, l3)
    scid12dir = f"{scid12}/{direction(l1.info['id'], l2.info['id'])}"
    scid23dir = f"{scid23}/{direction(l2.info['id'], l3.info['id'])}"

    initial_prob = l1.rpc.getroutes(source=l1.info['id'],
                                    destination=l3.info['id'],
                                    amount_msat=1000000,
                                    layers=[],
                                    maxfee_msat=100000,
                                    final_cltv=0)['probability_ppm']

    # Reserve 1000 sats on path.  This should reduce probability!
    l1.rpc.askrene_reserve(path=[{'short_channel_id_dir': scid12dir,
                                  'amount_msat': 1000_000},
                                 {'short_channel_id_dir': scid23dir,
                                  'amount_msat': 1000_001}])
    listres = l1.rpc.askrene_listreservations()['reservations']
    if listres[0]['short_channel_id_dir'] == scid12dir:
        assert listres[0]['amount_msat'] == 1000_000
        assert listres[1]['short_channel_id_dir'] == scid23dir
        assert listres[1]['amount_msat'] == 1000_001
    else:
        assert listres[0]['short_channel_id_dir'] == scid23dir
        assert listres[0]['amount_msat'] == 1000_001
        assert listres[1]['short_channel_id_dir'] == scid12dir
        assert listres[1]['amount_msat'] == 1000_000
    assert len(listres) == 2

    assert l1.rpc.getroutes(source=l1.info['id'],
                            destination=l3.info['id'],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=100000,
                            final_cltv=0)['probability_ppm'] < initial_prob

    # Now reserve so much there's nothing left.
    l1.rpc.askrene_reserve(path=[{'short_channel_id_dir': scid12dir,
                                  'amount_msat': 1000_000_000_000},
                                 {'short_channel_id_dir': scid23dir,
                                  'amount_msat': 1000_000_000_000}])

    # Keep it consistent: the below will mention a time if >= 1 seconds old,
    # which might happen without the sleep on slow machines.
    time.sleep(2)

    # Reservations can be in either order.
    with pytest.raises(RpcError, match=rf'We could not find a usable set of paths.  The shortest path is {scid12}->{scid23}, but {scid12dir} already reserved 10000000*msat by command ".*" \([0-9]* seconds ago\), 10000000*msat by command ".*" \([0-9]* seconds ago\)'):
        l1.rpc.getroutes(source=l1.info['id'],
                         destination=l3.info['id'],
                         amount_msat=1000000,
                         layers=[],
                         maxfee_msat=100000,
                         final_cltv=0)['probability_ppm']

    # Can't remove wrong amounts: that's user error
    with pytest.raises(RpcError, match="Unknown reservation"):
        l1.rpc.askrene_unreserve(path=[{'short_channel_id_dir': scid12dir,
                                        'amount_msat': 1000_001},
                                       {'short_channel_id_dir': scid23dir,
                                        'amount_msat': 1000_000}])

    # Remove, it's all ok.
    l1.rpc.askrene_unreserve(path=[{'short_channel_id_dir': scid12dir,
                                    'amount_msat': 1000_000},
                                   {'short_channel_id_dir': scid23dir,
                                    'amount_msat': 1000_001}])
    l1.rpc.askrene_unreserve(path=[{'short_channel_id_dir': scid12dir,
                                    'amount_msat': 1000_000_000_000},
                                   {'short_channel_id_dir': scid23dir,
                                    'amount_msat': 1000_000_000_000}])
    assert l1.rpc.askrene_listreservations() == {'reservations': []}
    assert l1.rpc.getroutes(source=l1.info['id'],
                            destination=l3.info['id'],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=100000,
                            final_cltv=0)['probability_ppm'] == initial_prob

    # Reserving in reverse makes no difference!
    scid12rev = f"{first_scid(l1, l2)}/{direction(l2.info['id'], l1.info['id'])}"
    scid23rev = f"{first_scid(l2, l3)}/{direction(l3.info['id'], l2.info['id'])}"
    l1.rpc.askrene_reserve(path=[{'short_channel_id_dir': scid12rev,
                                  'amount_msat': 1000_000_000_000},
                                 {'short_channel_id_dir': scid23rev,
                                  'amount_msat': 1000_000_000_000}])
    assert l1.rpc.getroutes(source=l1.info['id'],
                            destination=l3.info['id'],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=100000,
                            final_cltv=0)['probability_ppm'] == initial_prob


def test_layers(node_factory):
    """Test manipulating information in layers"""
    # remove xpay, since it creates a layer!
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True,
                                         opts={'disable-plugin': 'cln-xpay'})

    assert l2.rpc.askrene_listlayers() == {'layers': []}
    with pytest.raises(RpcError, match="Unknown layer"):
        l2.rpc.askrene_listlayers('test_layers')

    expect = {'layer': 'test_layers',
              'persistent': False,
              'disabled_nodes': [],
              'created_channels': [],
              'channel_updates': [],
              'constraints': [],
              'biases': [],
              'node_biases': []}
    l2.rpc.askrene_create_layer('test_layers')
    l2.rpc.askrene_disable_node('test_layers', l1.info['id'])
    expect['disabled_nodes'].append(l1.info['id'])
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}
    assert l2.rpc.askrene_listlayers() == {'layers': [expect]}
    with pytest.raises(RpcError, match="Unknown layer"):
        l2.rpc.askrene_listlayers('test_layers2')

    l2.rpc.askrene_update_channel('test_layers', "0x0x1/0", False)
    expect['channel_updates'].append({'short_channel_id_dir': "0x0x1/0",
                                      'enabled': False})
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}
    with pytest.raises(RpcError, match="Layer already exists"):
        l2.rpc.askrene_create_layer('test_layers')

    # Tell it l3 connects to l1!
    l2.rpc.askrene_create_channel('test_layers',
                                  l3.info['id'],
                                  l1.info['id'],
                                  '0x0x1',
                                  '1000000sat')
    # src/dst gets turned into BOLT 7 order
    expect['created_channels'].append({'source': l1.info['id'],
                                       'destination': l3.info['id'],
                                       'short_channel_id': '0x0x1',
                                       'capacity_msat': 1000000000})
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}

    # And give details.
    l2.rpc.askrene_update_channel(layer='test_layers',
                                  short_channel_id_dir='0x0x1/0',
                                  htlc_minimum_msat=100,
                                  htlc_maximum_msat=900000000,
                                  fee_base_msat=1,
                                  fee_proportional_millionths=2,
                                  cltv_expiry_delta=18)
    # This is *still* disabled, since we disabled it above!
    expect['channel_updates'] = [{'short_channel_id_dir': '0x0x1/0',
                                  'enabled': False,
                                  'htlc_minimum_msat': 100,
                                  'htlc_maximum_msat': 900000000,
                                  'fee_base_msat': 1,
                                  'fee_proportional_millionths': 2,
                                  'cltv_expiry_delta': 18}]
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}

    # Now enable (and change another value for good measure!
    l2.rpc.askrene_update_channel(layer='test_layers',
                                  short_channel_id_dir='0x0x1/0',
                                  enabled=True,
                                  cltv_expiry_delta=19)
    expect['channel_updates'] = [{'short_channel_id_dir': '0x0x1/0',
                                  'enabled': True,
                                  'htlc_minimum_msat': 100,
                                  'htlc_maximum_msat': 900000000,
                                  'fee_base_msat': 1,
                                  'fee_proportional_millionths': 2,
                                  'cltv_expiry_delta': 19}]
    assert l2.rpc.askrene_listlayers('test_layers') == {'layers': [expect]}

    # We can tell it about made up channels...
    first_timestamp = int(time.time())
    l2.rpc.askrene_inform_channel('test_layers',
                                  '0x0x1/1',
                                  100000,
                                  'unconstrained')
    last_timestamp = int(time.time()) + 1
    expect['constraints'].append({'short_channel_id_dir': '0x0x1/1',
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
    scid12dir = f"{scid12}/{direction(l2.info['id'], l1.info['id'])}"
    l2.rpc.askrene_inform_channel(layer='test_layers',
                                  short_channel_id_dir=scid12dir,
                                  amount_msat=12341235,
                                  inform='constrained')
    last_timestamp = int(time.time()) + 1
    expect['constraints'].append({'short_channel_id_dir': scid12dir,
                                  'timestamp': first_timestamp,
                                  'maximum_msat': 12341234})
    # Check timestamp first.
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    ts2 = only_one([c['timestamp'] for c in only_one(listlayers['layers'])['constraints'] if c['short_channel_id_dir'] == scid12dir])
    assert first_timestamp <= ts2 <= last_timestamp
    expect['constraints'][1]['timestamp'] = ts2

    # Could be either order!
    actual = expect.copy()
    if only_one(listlayers['layers'])['constraints'][0]['short_channel_id_dir'] == scid12dir:
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

    with pytest.raises(RpcError, match="Unknown layer"):
        l2.rpc.askrene_remove_layer('test_layers_unknown')

    # Add biases.
    r = l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', 1)
    expect['biases'] = [{'short_channel_id_dir': '1x1x1/1', 'bias': 1,
                         'timestamp': r['biases'][0]['timestamp']}]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    # Works with description.
    r = l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', -5, "bigger bias")
    expect['biases'] = [{'short_channel_id_dir': '1x1x1/1', 'bias': -5,
                         'description': "bigger bias",
                         'timestamp': r['biases'][0]['timestamp']}]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    with pytest.raises(RpcError, match="bias: should be a number between -100 and 100"):
        l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', -101)

    with pytest.raises(RpcError, match="bias: should be a number between -100 and 100"):
        l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', 101, "bigger bias")

    # We can make them relative.
    r = l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', 1, 'adding bias', True)
    expect['biases'] = [{'short_channel_id_dir': '1x1x1/1', 'bias': -4,
                         'description': "adding bias",
                         'timestamp': r['biases'][0]['timestamp']}]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    r = l2.rpc.askrene_bias_channel(layer='test_layers', short_channel_id_dir='1x1x1/1', bias=-1, relative=True)
    expect['biases'] = [{'short_channel_id_dir': '1x1x1/1', 'bias': -5,
                         'timestamp': r['biases'][0]['timestamp']}]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    # They truncate on +/- 100 though:
    r = l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', -99, None, True)
    expect['biases'] = [{'short_channel_id_dir': '1x1x1/1', 'bias': -100,
                         'timestamp': r['biases'][0]['timestamp']}]
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    # We can remove them.
    l2.rpc.askrene_bias_channel('test_layers', '1x1x1/1', 0)
    expect['biases'] = []
    listlayers = l2.rpc.askrene_listlayers('test_layers')
    assert listlayers == {'layers': [expect]}

    assert l2.rpc.askrene_remove_layer('test_layers') == {}
    assert l2.rpc.askrene_listlayers() == {'layers': []}

    # This layer is not persistent.
    l2.rpc.askrene_create_layer('test_layers')
    l2.restart()
    assert l2.rpc.askrene_listlayers() == {'layers': []}


def test_node_bias_rpc(node_factory):
    """Test manipulating node bias in layers."""
    # remove xpay, since it creates a layer!
    l1, l2 = node_factory.line_graph(
        2, wait_for_announce=True, opts={"disable-plugin": "cln-xpay"}
    )

    # Simply test the presence of 'node_biases'
    expect = {
        "layer": "test_layers",
        "persistent": False,
        "disabled_nodes": [],
        "created_channels": [],
        "channel_updates": [],
        "constraints": [],
        "biases": [],
        "node_biases": [],
    }
    l1.rpc.askrene_create_layer("test_layers")
    assert l1.rpc.askrene_listlayers("test_layers") == {"layers": [expect]}

    # Adding a node bias in the out direction
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="out",
        bias=3,
        relative=False,
    )
    # Adding a node bias in the in direction
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="in",
        bias=-3,
        relative=False,
    )
    expect["node_biases"] = [
        {
            "node": l2.info["id"],
            "in_bias": -3,
            "out_bias": 3,
            "timestamp": r["node_biases"][0]["timestamp"],
        }
    ]
    listlayers = l1.rpc.askrene_listlayers("test_layers")
    assert listlayers == {"layers": [expect]}

    # Testing relative bias and descriptions
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="in",
        bias=-3,
        relative=True,
        description="testing node bias",
    )
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="out",
        bias=-1,
        relative=True,
        description="testing node bias",
    )
    expect["node_biases"] = [
        {
            "node": l2.info["id"],
            "in_bias": -6,
            "out_bias": 2,
            "timestamp": r["node_biases"][0]["timestamp"],
            "description": "testing node bias",
        }
    ]
    listlayers = l1.rpc.askrene_listlayers("test_layers")
    assert listlayers == {"layers": [expect]}

    # Setting one direction bias, still the other remains
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="in",
        bias=0,
        relative=False,
    )
    expect["node_biases"] = [
        {
            "node": l2.info["id"],
            "in_bias": 0,
            "out_bias": 2,
            "timestamp": r["node_biases"][0]["timestamp"],
        }
    ]
    listlayers = l1.rpc.askrene_listlayers("test_layers")
    assert listlayers == {"layers": [expect]}

    # If the bias in both direction is zero the entry is removed
    r = l1.rpc.askrene_bias_node(
        layer="test_layers",
        node=l2.info["id"],
        direction="out",
        bias=0,
        relative=False,
    )
    expect["node_biases"] = []
    listlayers = l1.rpc.askrene_listlayers("test_layers")
    assert listlayers == {"layers": [expect]}


def test_node_bias_persistence(node_factory):
    """Test node bias persistence."""
    # remove xpay, since it creates a layer!
    l1, l2 = node_factory.line_graph(
        2, wait_for_announce=True, opts={"disable-plugin": "cln-xpay"}
    )

    expect = {
        "layer": "mylayer",
        "persistent": True,
        "disabled_nodes": [],
        "created_channels": [],
        "channel_updates": [],
        "constraints": [],
        "biases": [],
        "node_biases": [],
    }
    l1.rpc.askrene_create_layer(layer="mylayer", persistent=True)
    r = l1.rpc.askrene_bias_node(
        layer="mylayer", node=l2.info["id"], direction="out", bias=14, relative=False
    )
    expect["node_biases"] = [
        {
            "node": l2.info["id"],
            "in_bias": 0,
            "out_bias": 14,
            "timestamp": r["node_biases"][0]["timestamp"],
        }
    ]
    assert l1.rpc.askrene_listlayers("mylayer") == {"layers": [expect]}
    # restarting the node we see the same data again
    l2.restart()
    assert l1.rpc.askrene_listlayers("mylayer") == {"layers": [expect]}

    r = l1.rpc.askrene_bias_node(
        layer="mylayer",
        node=l2.info["id"],
        direction="in",
        bias=11,
        relative=False,
        description="Some description",
    )
    expect["node_biases"] = [
        {
            "node": l2.info["id"],
            "in_bias": 11,
            "out_bias": 14,
            "timestamp": r["node_biases"][0]["timestamp"],
            "description": "Some description",
        }
    ]
    assert l1.rpc.askrene_listlayers("mylayer") == {"layers": [expect]}

    # restarting the node we see the same data again
    l2.restart()
    assert l1.rpc.askrene_listlayers("mylayer") == {"layers": [expect]}


def test_node_bias_routes(node_factory):
    """Test getroutes with biased nodes."""
    # There are many cheap routes that go through node 2:
    #   0->2->x->1
    # And a very expensive route that go through node 3:
    #   0->3->1
    gsfile, nodemap = generate_gossip_store(
        [
            GenChannel(0, 2, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 11, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 12, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 13, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 14, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 15, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 16, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 17, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 18, forward=GenChannel.Half(propfee=10)),
            GenChannel(2, 19, forward=GenChannel.Half(propfee=10)),
            GenChannel(11, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(12, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(13, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(14, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(15, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(16, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(17, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(18, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(19, 1, forward=GenChannel.Half(propfee=10)),
            GenChannel(0, 3, forward=GenChannel.Half(propfee=1000)),
            GenChannel(3, 1, forward=GenChannel.Half(propfee=1000)),
        ]
    )
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)
    l1.rpc.askrene_create_layer(layer="mylayer")
    l1.rpc.askrene_bias_node(layer="mylayer", node=nodemap[2], direction="out", bias=-50)

    # by default the best route goes through node 2
    r = l1.rpc.getroutes(
        source=nodemap[0],
        destination=nodemap[1],
        amount_msat=10000000,
        layers=[],
        maxfee_msat=1000000,
        final_cltv=99,
    )
    assert len(r["routes"]) == 1
    assert len(r["routes"][0]["path"]) == 3
    assert r["routes"][0]["path"][0]["next_node_id"] == nodemap[2]
    assert r["routes"][0]["path"][2]["next_node_id"] == nodemap[1]

    # by using the layer that penalizes node 2, we end up routing through node 3
    r = l1.rpc.getroutes(
        source=nodemap[0],
        destination=nodemap[1],
        amount_msat=10000000,
        layers=["mylayer"],
        maxfee_msat=1000000,
        final_cltv=99,
    )
    assert len(r["routes"]) == 1
    assert len(r["routes"][0]["path"]) == 2
    assert r["routes"][0]["path"][0]["next_node_id"] == nodemap[3]
    assert r["routes"][0]["path"][1]["next_node_id"] == nodemap[1]


def test_layer_persistence(node_factory):
    """Test persistence of layers across restart"""
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True,
                                     opts={'disable-plugin': 'cln-xpay'})

    assert l1.rpc.askrene_listlayers() == {'layers': []}
    with pytest.raises(RpcError, match="Unknown layer"):
        l1.rpc.askrene_listlayers('test_layer_persistence')

    l1.rpc.askrene_create_layer(layer='test_layer_persistence', persistent=True)
    expect = {'layer': 'test_layer_persistence',
              'persistent': True,
              'disabled_nodes': [],
              'created_channels': [],
              'channel_updates': [],
              'constraints': [],
              'biases': [],
              'node_biases': []}
    assert l1.rpc.askrene_listlayers('test_layer_persistence') == {'layers': [expect]}

    # Restart, (empty layer) should still be there.
    l1.restart()

    assert l1.rpc.askrene_listlayers('test_layer_persistence') == {'layers': [expect]}

    # Re-creation of persistent layer is a noop.
    l1.rpc.askrene_create_layer(layer='test_layer_persistence', persistent=True)

    # Populate it.
    l1.rpc.askrene_disable_node('test_layer_persistence', l1.info['id'])
    l1.rpc.askrene_update_channel('test_layer_persistence', "0x0x1/0", False)
    l1.rpc.askrene_create_channel('test_layer_persistence',
                                  l2.info['id'],
                                  l1.info['id'],
                                  '0x0x1',
                                  '1000000sat')
    l1.rpc.askrene_update_channel(layer='test_layer_persistence',
                                  short_channel_id_dir='0x0x1/0',
                                  htlc_minimum_msat=100,
                                  htlc_maximum_msat=900000000,
                                  fee_base_msat=1,
                                  fee_proportional_millionths=2,
                                  cltv_expiry_delta=18)
    l1.rpc.askrene_update_channel(layer='test_layer_persistence',
                                  short_channel_id_dir='0x0x1/0',
                                  enabled=True,
                                  cltv_expiry_delta=19)
    l1.rpc.askrene_inform_channel('test_layer_persistence',
                                  '0x0x1/1',
                                  100000,
                                  'unconstrained')
    scid12 = first_scid(l1, l2)
    scid12dir = f"{scid12}/{direction(l1.info['id'], l2.info['id'])}"
    l1.rpc.askrene_inform_channel(layer='test_layer_persistence',
                                  short_channel_id_dir=scid12dir,
                                  amount_msat=12341235,
                                  inform='constrained')

    expect = l1.rpc.askrene_listlayers('test_layer_persistence')

    l1.restart()
    assert l1.rpc.askrene_listlayers('test_layer_persistence') == expect

    # Aging will cause a rewrite.
    assert l1.rpc.askrene_age('test_layer_persistence', 1) == {'layer': 'test_layer_persistence', 'num_removed': 0}
    assert l1.rpc.askrene_listlayers('test_layer_persistence') == expect
    l1.restart()
    assert l1.rpc.askrene_listlayers('test_layer_persistence') == expect

    # Delete layer, it won't reappear.
    assert l1.rpc.askrene_remove_layer('test_layer_persistence') == {}
    assert l1.rpc.askrene_listlayers() == {'layers': []}
    l1.restart()
    assert l1.rpc.askrene_listlayers() == {'layers': []}


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

    # Too much should give a decent explanation.
    dir01 = direction(nodemap[0], nodemap[1])
    with pytest.raises(RpcError, match=rf"We could not find a usable set of paths\.  The shortest path is 0x1x0, but 0x1x0/{dir01} isn't big enough to carry 1000000001msat\."):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=1000000001,
                         layers=[],
                         maxfee_msat=100000000,
                         final_cltv=99)

    # This should tell us source doesn't have enough.
    with pytest.raises(RpcError, match=r"We could not find a usable set of paths\.  Total source capacity is only 1019000000msat \(in 3 channels\)\."):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=2000000001,
                         layers=[],
                         maxfee_msat=20000000,
                         final_cltv=99)

    # This should tell us dest doesn't have enough.
    with pytest.raises(RpcError, match=r"We could not find a usable set of paths\.  Total destination capacity is only 1000000000msat \(in 1 channels\)\."):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[4],
                         amount_msat=1000000001,
                         layers=[],
                         maxfee_msat=30000000,
                         final_cltv=99)

    # Disabling channels makes getroutes fail
    dir01 = direction(nodemap[0], nodemap[1])
    l1.rpc.askrene_create_layer('chans_disabled')
    l1.rpc.askrene_update_channel(layer="chans_disabled",
                                  short_channel_id_dir=f'0x1x0/{dir01}',
                                  enabled=False)
    with pytest.raises(RpcError, match=rf"We could not find a usable set of paths\.  The shortest path is 0x1x0, but 0x1x0/{dir01} marked disabled by layer chans_disabled\."):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=1000,
                         layers=["chans_disabled"],
                         maxfee_msat=1000,
                         final_cltv=99)

    # Start easy
    dir01 = direction(nodemap[0], nodemap[1])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999999,
                                               'routes': [{'probability_ppm': 999999,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000,
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1010,
                                                                     'delay': 99 + 6}]}]}
    # Two hop, still easy.
    dir13 = direction(nodemap[1], nodemap[3])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[3],
                            amount_msat=100000,
                            layers=[],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 999798,
                                               'routes': [{'probability_ppm': 999798,
                                                           'final_cltv': 99,
                                                           'amount_msat': 100000,
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 103020,
                                                                     'delay': 99 + 6 + 6},
                                                                    {'short_channel_id_dir': f'3x3x2/{dir13}',
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
    dir02 = direction(nodemap[0], nodemap[2])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[2],
                            amount_msat=1000000,
                            layers=[],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 900000,
                                               'routes': [{'probability_ppm': 900000,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000000,
                                                           'path': [{'short_channel_id_dir': f'3x2x3/{dir02}',
                                                                     'next_node_id': nodemap[2],
                                                                     'amount_msat': 1000001,
                                                                     'delay': 99 + 6}]}]}

    # For 10000 sats, we will split.
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[2],
                         10000000,
                         [[{'short_channel_id_dir': f'1x2x1/{dir02}',
                            'next_node_id': nodemap[2],
                            'amount_msat': 4500004,
                            'delay': 99 + 6}],
                          [{'short_channel_id_dir': f'3x2x3/{dir02}',
                            'next_node_id': nodemap[2],
                            'amount_msat': 5500005,
                            'delay': 99 + 6}]])


def test_getroutes_single_path(node_factory):
    """Test getroutes generating single path payments"""
    gsfile, nodemap = generate_gossip_store(
        [
            GenChannel(0, 1),
            GenChannel(1, 2, capacity_sats=9000),
            GenChannel(1, 2, capacity_sats=10000),
        ]
    )
    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # To be able to route this amount two parts are needed, therefore a single
    # pay search will fail.
    # FIXME: the explanation for the failure is wrong
    with pytest.raises(RpcError):
        l1.rpc.getroutes(
            source=nodemap[1],
            destination=nodemap[2],
            amount_msat=10000001,
            layers=["auto.no_mpp_support"],
            maxfee_msat=1000,
            final_cltv=99,
        )

    # For this amount, only one solution is possible
    check_getroute_paths(
        l1,
        nodemap[1],
        nodemap[2],
        10000000,
        [
            [
                {
                    "short_channel_id_dir": "3x2x2/1",
                    "next_node_id": nodemap[2],
                    "amount_msat": 10000010,
                    "delay": 99 + 6,
                }
            ]
        ],
        layers=["auto.no_mpp_support"],
    )

    # To be able to route this amount two parts are needed, therefore a single
    # pay search will fail.
    # FIXME: the explanation for the failure is wrong
    with pytest.raises(RpcError):
        l1.rpc.getroutes(
            source=nodemap[0],
            destination=nodemap[2],
            amount_msat=10000001,
            layers=["auto.no_mpp_support"],
            maxfee_msat=1000,
            final_cltv=99,
        )

    # For this amount, only one solution is possible
    check_getroute_paths(
        l1,
        nodemap[0],
        nodemap[2],
        10000000,
        [
            [
                {
                    "short_channel_id_dir": "0x1x0/1",
                    "next_node_id": nodemap[1],
                    "amount_msat": 10000020,
                    "delay": 99 + 6 + 6,
                },
                {
                    "short_channel_id_dir": "3x2x2/1",
                    "next_node_id": nodemap[2],
                    "amount_msat": 10000010,
                    "delay": 99 + 6,
                },
            ]
        ],
        layers=["auto.no_mpp_support"],
    )


def test_getroutes_fee_fallback(node_factory):
    """Test getroutes call takes into account fees, if excessive"""

    # 0 -> 1 -> 3: high capacity, high fee (1%)
    # 0 -> 2 -> 3: low capacity, low fee.
    # (We disable reverse, since it breaks median calc!)
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1,
                                                        capacity_sats=20000,
                                                        forward=GenChannel.Half(propfee=10000),
                                                        reverse=GenChannel.Half(enabled=False)),
                                             GenChannel(0, 2,
                                                        capacity_sats=10000,
                                                        reverse=GenChannel.Half(enabled=False)),
                                             GenChannel(1, 3,
                                                        capacity_sats=20000,
                                                        forward=GenChannel.Half(propfee=10000),
                                                        reverse=GenChannel.Half(enabled=False)),
                                             GenChannel(2, 3,
                                                        capacity_sats=10000,
                                                        reverse=GenChannel.Half(enabled=False))])
    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Don't hit maxfee?  Go easy path.
    dir01 = direction(nodemap[0], nodemap[1])
    dir13 = direction(nodemap[1], nodemap[3])
    dir02 = direction(nodemap[0], nodemap[2])
    dir23 = direction(nodemap[2], nodemap[3])
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[3],
                         10000,
                         maxfee_msat=201,
                         paths=[[{'short_channel_id_dir': f'0x1x0/{dir01}'},
                                 {'short_channel_id_dir': f'3x3x2/{dir13}'}]])

    # maxfee exceeded?  lower prob path.
    check_getroute_paths(l1,
                         nodemap[0],
                         nodemap[3],
                         10000,
                         maxfee_msat=200,
                         paths=[[{'short_channel_id_dir': f'1x2x1/{dir02}'},
                                 {'short_channel_id_dir': f'5x3x3/{dir23}'}]])


def test_getroutes_auto_sourcefree(node_factory):
    """Test getroutes call with auto.sourcefree layer"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, capacity_sats=9000),
                                             GenChannel(1, 3, forward=GenChannel.Half(propfee=20000)),
                                             GenChannel(0, 2, capacity_sats=10000),
                                             GenChannel(2, 4, forward=GenChannel.Half(delay=2000))])

    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Without sourcefree:
    dir01 = direction(nodemap[0], nodemap[1])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999999,
                                               'routes': [{'probability_ppm': 999999,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000,
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1010,
                                                                     'delay': 105}]}]}

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
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1000,
                                                                     'delay': 99}]}]}
    # Two hop, still easy.
    dir13 = direction(nodemap[1], nodemap[3])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[3],
                            amount_msat=100000,
                            layers=['auto.sourcefree'],
                            maxfee_msat=5000,
                            final_cltv=99) == {'probability_ppm': 999798,
                                               'routes': [{'probability_ppm': 999798,
                                                           'final_cltv': 99,
                                                           'amount_msat': 100000,
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 102000,
                                                                     'delay': 99 + 6},
                                                                    {'short_channel_id_dir': f'3x3x2/{dir13}',
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


def test_getroutes_maxdelay(node_factory):
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000, delay=80)),
                                             GenChannel(0, 1, forward=GenChannel.Half(propfee=20000, delay=40))])

    # Set up l1 with this as the gossip_store
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Should prefer the cheaper channel
    dir01 = direction(nodemap[0], nodemap[1])
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=1000,
                            final_cltv=99) == {'probability_ppm': 999999,
                                               'routes': [{'probability_ppm': 999999,
                                                           'final_cltv': 99,
                                                           'amount_msat': 1000,
                                                           'path': [{'short_channel_id_dir': f'0x1x0/{dir01}',
                                                                     'next_node_id': nodemap[1],
                                                                     'amount_msat': 1010,
                                                                     'delay': 179}]}]}

    # But use the channel with lower delay when needed
    assert l1.rpc.getroutes(source=nodemap[0],
                            destination=nodemap[1],
                            amount_msat=1000,
                            layers=[],
                            maxfee_msat=2000,
                            final_cltv=99,
                            maxdelay=170) == {'probability_ppm': 999999,
                                              'routes': [{'probability_ppm': 999999,
                                                          'final_cltv': 99,
                                                          'amount_msat': 1000,
                                                          'path': [{'short_channel_id_dir': f'1x1x1/{dir01}',
                                                                    'next_node_id': nodemap[1],
                                                                    'amount_msat': 1020,
                                                                    'delay': 139}]}]}

    # Excessive maxdelay parameter
    with pytest.raises(RpcError, match="maximum delay allowed is 2016"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=100000,
                         layers=[],
                         maxfee_msat=100,
                         final_cltv=99,
                         maxdelay=2017)


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
    scid21dir = f"{scid12}/{direction(l2.info['id'], l1.info['id'])}"
    # Calculate directions dynamically based on node IDs
    dir01 = direction(nodemap[0], nodemap[1])
    dir12 = direction(nodemap[1], nodemap[2])
    check_getroute_paths(l2,
                         l2.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans'],
                         paths=[[{'short_channel_id_dir': scid21dir, 'amount_msat': 102012, 'delay': 99 + 6 + 6 + 6},
                                 {'short_channel_id_dir': f'0x1x0/{dir01}', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id_dir': f'2x2x1/{dir12}', 'amount_msat': 101000, 'delay': 99 + 6}]])

    # This should get self-discount correct
    check_getroute_paths(l2,
                         l2.info['id'],
                         nodemap[2],
                         100000,
                         maxfee_msat=100000,
                         layers=['auto.localchans', 'auto.sourcefree'],
                         paths=[[{'short_channel_id_dir': scid21dir, 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id_dir': f'0x1x0/{dir01}', 'amount_msat': 102010, 'delay': 99 + 6 + 6},
                                 {'short_channel_id_dir': f'2x2x1/{dir12}', 'amount_msat': 101000, 'delay': 99 + 6}]])


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
    l1.rpc.askrene_create_layer('test_layers')
    l1.rpc.askrene_inform_channel(layer='test_layers',
                                  short_channel_id_dir=f"{chan['short_channel_id']}/{chan['direction']}",
                                  amount_msat=max_msat + 1,
                                  inform='constrained')

    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=nodemap[3],
                              amount_msat=msat,
                              layers=['test_layers'],
                              maxfee_msat=msat,
                              final_cltv=99)['routes']
    assert len(routes) == 2
    for hop in routes[0]['path'] + routes[1]['path']:
        if hop['short_channel_id_dir'] == f"{chan['short_channel_id']}/{chan['direction']}":
            amount = hop['amount_msat']
    assert amount <= max_msat


def test_sourcefree_on_mods(node_factory, bitcoind):
    """auto.sourcefree should also apply to layer-created channels"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, forward=GenChannel.Half(propfee=10000)),
                                             GenChannel(0, 2, forward=GenChannel.Half(propfee=10000))])

    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Add a local channel from 0->l1 (we just needed a nodeid).
    l1.rpc.askrene_create_layer('test_layers')
    l1.rpc.askrene_create_channel('test_layers',
                                  nodemap[0],
                                  l1.info['id'],
                                  '0x3x3',
                                  '1000000sat')
    l1.rpc.askrene_update_channel(layer='test_layers',
                                  short_channel_id_dir=f'0x3x3/{direction(nodemap[0], l1.info["id"])}',
                                  enabled=True,
                                  htlc_minimum_msat=100,
                                  htlc_maximum_msat='900000sat',
                                  fee_base_msat=1000,
                                  fee_proportional_millionths=2000,
                                  cltv_expiry_delta=18)
    dir03 = direction(nodemap[0], l1.info['id'])
    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=l1.info['id'],
                              amount_msat=1000000,
                              layers=['test_layers', 'auto.sourcefree'],
                              maxfee_msat=100000,
                              final_cltv=99)['routes']
    # Expect no fee.
    check_route_as_expected(routes, [[{'short_channel_id_dir': f'0x3x3/{dir03}',
                                       'amount_msat': 1000000, 'delay': 99}]])

    # NOT if we specify layers in the other order!
    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=l1.info['id'],
                              amount_msat=1000000,
                              layers=['auto.sourcefree', 'test_layers'],
                              maxfee_msat=100000,
                              final_cltv=99)['routes']
    # Expect no fee.
    check_route_as_expected(routes, [[{'short_channel_id_dir': f'0x3x3/{dir03}',
                                       'amount_msat': 1003000, 'delay': 117}]])


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
        key = r["path"][0]["short_channel_id_dir"]
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
        path_i = [p['short_channel_id_dir'] for p in routes["routes"][i]['path']]
        for j in range(i + 1, len(routes["routes"])):
            path_j = [p['short_channel_id_dir'] for p in routes["routes"][j]['path']]
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
    dir01 = direction(nodemap[0], nodemap[1])
    spendable = {f'0x1x0/{dir01}': 87718000,
                 f'1x1x1/{dir01}': 87718000,
                 f'2x1x2/{dir01}': 186718000,
                 f'3x1x3/{dir01}': 285718000,
                 f'4x1x4/{dir01}': 384718000}

    # Sanity check that these exist!
    for scidd in spendable:
        assert scidd in [f"{c['short_channel_id']}/{c['direction']}" for c in l1.rpc.listchannels(source=nodemap[0])['channels']]

    # We tell it we could get through amount, but not amount + 1.
    # This makes min == max, just like we do for auto.localchans spendable.
    l1.rpc.askrene_create_layer('localchans')
    for scidd, amount in spendable.items():
        l1.rpc.askrene_inform_channel(layer='localchans',
                                      short_channel_id_dir=scidd,
                                      amount_msat=amount,
                                      inform='unconstrained')
        l1.rpc.askrene_inform_channel(layer='localchans',
                                      short_channel_id_dir=scidd,
                                      amount_msat=amount + 1,
                                      inform='constrained')

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
        key = r["path"][0]["short_channel_id_dir"]
        path_total[key] = path_total.get(key, 0) + r["path"][0]["amount_msat"]

    exceeded = {}
    for scidd in spendable.keys():
        if scidd in path_total:
            if path_total[scidd] > spendable[scidd]:
                exceeded[scidd] = f"Path total {path_total[scidd]} > spendable {spendable[scidd]}"

    assert exceeded == {}

    # No duplicate paths!
    for i in range(0, len(routes["routes"])):
        path_i = [p['short_channel_id_dir'] for p in routes["routes"][i]['path']]
        for j in range(i + 1, len(routes["routes"])):
            path_j = [p['short_channel_id_dir'] for p in routes["routes"][j]['path']]
            assert path_i != path_j

    # Must deliver exact amount.
    assert sum(r['amount_msat'] for r in routes["routes"]) == 800_000_001

    # Won't evaluate route for 0msat.
    with pytest.raises(RpcError, match="amount must be non-zero"):
        l1.rpc.getroutes(
            source=nodemap[0],
            destination=nodemap[2],
            amount_msat=0,
            layers=["localchans", "auto.sourcefree"],
            maxfee_msat=50_000_000,
            final_cltv=10,
        )


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

    dir01 = direction(nodemap[0], nodemap[1])
    check_route_as_expected(routes['routes'],
                            [[{'short_channel_id_dir': f'0x1x0/{dir01}', 'amount_msat': 1_000_001, 'delay': 10 + 6}],
                             [{'short_channel_id_dir': f'1x1x1/{dir01}', 'amount_msat': 19_000_019, 'delay': 10 + 6}]])

    # If we can't use channel 2, we fail.
    l1.rpc.askrene_create_layer('removechan2')
    l1.rpc.askrene_inform_channel(layer='removechan2',
                                  short_channel_id_dir=f'1x1x1/{dir01}',
                                  amount_msat=1,
                                  inform='constrained')

    with pytest.raises(RpcError, match=rf"We could not find a usable set of paths.  The shortest path is 0x1x0, but 0x1x0/{dir01} exceeds htlc_maximum_msat ~1000448msat"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=20_000_000,
                         layers=['removechan2'],
                         maxfee_msat=20_000_000,
                         final_cltv=10)


def test_min_htlc(node_factory, bitcoind):
    """A route which looks good isn't actually, because of min htlc limits.  Should fall back!"""
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=500_000,
                                                        forward=GenChannel.Half(htlc_min=2_000)),
                                             GenChannel(0, 1, capacity_sats=20_000)])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    routes = l1.rpc.getroutes(source=nodemap[0],
                              destination=nodemap[1],
                              amount_msat=1000,
                              layers=[],
                              maxfee_msat=20_000_000,
                              final_cltv=10)

    dir01 = direction(nodemap[0], nodemap[1])
    check_route_as_expected(routes['routes'],
                            [[{'short_channel_id_dir': f'1x1x1/{dir01}', 'amount_msat': 1_000, 'delay': 10 + 6}]])


def test_min_htlc_after_excess(node_factory, bitcoind):
    gsfile, nodemap = generate_gossip_store([GenChannel(0, 1, capacity_sats=500_000,
                                                        forward=GenChannel.Half(htlc_min=2_000))])
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    dir01 = direction(nodemap[0], nodemap[1])
    with pytest.raises(RpcError, match=rf"We could not find a usable set of paths.  The shortest path is 0x1x0, but 0x1x0/{dir01} below htlc_minumum_msat ~2000msat"):
        l1.rpc.getroutes(source=nodemap[0],
                         destination=nodemap[1],
                         amount_msat=1999,
                         layers=[],
                         maxfee_msat=20_000_000,
                         final_cltv=10)


# These were obviously having a bad day at the time of the snapshot:
canned_gossmap_badnodes = {
    19: "We could not find a usable set of paths.  The shortest path is 103x1x0->0x2134x0->988x333x988->16188x333x16169, but 0x2134x0/0 exceeds htlc_maximum_msat ~1000448msat",
    53: "We could not find a usable set of paths.  The destination has disabled 177 of 177 channels, leaving capacity only 0msat of 4003677000msat.",
    69: "We could not find a usable set of paths.  The destination has disabled 151 of 151 channels, leaving capacity only 0msat of 9092303000msat.",
    72: "We could not find a usable set of paths.  The destination has disabled 146 of 146 channels, leaving capacity only 0msat of 1996000000msat.",
    86: "We could not find a usable set of paths.  The destination has disabled 131 of 131 channels, leaving capacity only 0msat of 162000000msat.",
}


@pytest.mark.slow_test
def test_real_data(node_factory, bitcoind, executor):
    # Route from Rusty's node to the top nodes
    # From tests/data/gossip-store-2026-02-03-node-map.xz:
    # Me: 2134:024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605:BLUEIRON
    # So we make l2 node 2134.
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       '--node-map=2134=033845802d25b4e074ccfd7cd8b339a41dc75bf9978a034800444b51d42b07799a',
                                       'tests/data/gossip-store-2026-02-03.compressed',
                                       outfile.name]).decode('utf-8').splitlines()

    # This is in msat, but is also the size of channel we create.
    AMOUNT = 100000000

    # l2 complains being given bad gossip from l1, throttle to reduce
    # the sheer amount of log noise.
    l1, l2 = node_factory.line_graph(2, fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None,
                                            # This can be slow!
                                            'askrene-timeout': TIMEOUT},
                                           {'allow_warning': True}])

    # CI, it's slow.
    if SLOW_MACHINE:
        limit = 25
        expected = (9, 24, 1935647, 219066, 89)
    else:
        limit = 100
        expected = (11, 95, 8026484, 925406, 89)

    # 0.5% is the norm
    MAX_FEE = AMOUNT // 200

    # Do these in parallel.
    futs = {}
    for n in range(0, limit):
        futs[n] = executor.submit(l1.rpc.getroutes,
                                  source=l1.info['id'],
                                  destination=nodeids[n],
                                  amount_msat=AMOUNT,
                                  layers=['auto.sourcefree', 'auto.localchans'],
                                  maxfee_msat=MAX_FEE,
                                  final_cltv=18)

    fees = {}
    prevs = {}
    for n in range(0, limit):
        fees[n] = []
        if n in canned_gossmap_badnodes:
            with pytest.raises(RpcError, match=canned_gossmap_badnodes[n]):
                futs[n].result(TIMEOUT)
            continue

        prevs[n] = futs[n].result(TIMEOUT)

    # Stress it by asking harder for each one which succeeded
    while prevs != {}:
        futs = {}
        for n, prev in prevs.items():
            # Record fees
            fees[n].append(sum([r['path'][0]['amount_msat'] for r in prev['routes']]) - AMOUNT)
            # Now stress it, by asking it to spend 1msat less!
            futs[n] = executor.submit(l1.rpc.getroutes,
                                      source=l1.info['id'],
                                      destination=nodeids[n],
                                      amount_msat=AMOUNT,
                                      layers=['auto.sourcefree', 'auto.localchans'],
                                      maxfee_msat=fees[n][-1] - 1,
                                      final_cltv=18)

        for n, fut in futs.items():
            try:
                routes = fut.result(TIMEOUT)
            except RpcError:
                # Too much, this one is one.
                del prevs[n]
                continue

            fee = sum([r['path'][0]['amount_msat'] for r in routes['routes']]) - AMOUNT
            # Should get less expensive
            assert fee < fees[n][-1]

            # Should get less likely (Note!  This is violated because once we care
            # about fees, the total is reduced, leading to better prob!).
#            assert routes['probability_ppm'] < prevs[n]['probability_ppm']
            prevs[n] = routes

    # Which succeeded in improving
    improved = [n for n in fees if len(fees[n]) > 1]
    total_first_fee = sum([fees[n][0] for n in improved])
    total_final_fee = sum([fees[n][-1] for n in improved])

    if total_first_fee != 0:
        percent_fee_reduction = 100 - int(total_final_fee * 100 / total_first_fee)
    else:
        percent_fee_reduction = 0

    best = 0
    for n in fees:
        if len(fees[n]) > len(fees[best]):
            best = n

    assert (len(fees[best]), len(improved), total_first_fee, total_final_fee, percent_fee_reduction) == expected
    # askrene will have restricted how many we run
    assert l1.daemon.is_in_log(r"Too many running at once \(4 vs 4\): waiting")


@pytest.mark.slow_test
def test_real_biases(node_factory, bitcoind, executor):
    # Route from Rusty's node to the top 100.
    # From tests/data/gossip-store-2026-02-03-node-map.xz:
    # Me: 2134:024b9a1fa8e006f1e3937f65f66c408e6da8e1ca728ea43222a7381df1cc449605:BLUEIRON
    # So we make l2 node 2134.
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       '--node-map=2134=033845802d25b4e074ccfd7cd8b339a41dc75bf9978a034800444b51d42b07799a',
                                       'tests/data/gossip-store-2026-02-03.compressed',
                                       outfile.name]).decode('utf-8').splitlines()

    # This is in msat, but is also the size of channel we create.
    AMOUNT = 100000000

    # l2 complains being given bad gossip from l1, throttle to reduce
    # the sheer amount of log noise.
    l1, l2 = node_factory.line_graph(2, fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None},
                                           {'allow_warning': True}])

    # CI, it's slow.
    if SLOW_MACHINE:
        limit = 25
        expected = ({1: 6, 2: 7, 4: 12, 8: 13, 16: 18, 32: 23, 64: 24, 100: 24}, 0)
    else:
        limit = 100
        expected = ({1: 26, 2: 33, 4: 48, 8: 57, 16: 77, 32: 90, 64: 95, 100: 95}, 0)

    l1.rpc.askrene_create_layer('biases')
    num_changed = {}
    bias_ineffective = 0

    # 0.5% is the norm
    MAX_FEE = AMOUNT // 200

    # To exercise parallelism, do bases all at once.
    futures = {}
    for n in range(0, limit):
        if n in canned_gossmap_badnodes:
            continue
        futures[n] = executor.submit(l1.rpc.getroutes,
                                     source=l1.info['id'],
                                     destination=nodeids[n],
                                     amount_msat=AMOUNT,
                                     layers=['auto.sourcefree', 'auto.localchans'],
                                     maxfee_msat=MAX_FEE,
                                     final_cltv=18)

    base_routes = {}
    for n in range(0, limit):
        if n in canned_gossmap_badnodes:
            continue
        base_routes[n] = futures[n].result(TIMEOUT)

    for bias in (1, 2, 4, 8, 16, 32, 64, 100):
        num_changed[bias] = 0
        for n in range(0, limit):
            if n in canned_gossmap_badnodes:
                continue
            route = base_routes[n]
            # Now add bias against final channel, see if it changes.
            chan = route['routes'][0]['path'][-1]['short_channel_id_dir']

            def amount_through_chan(chan, routes):
                total = 0
                for r in routes:
                    for p in r['path']:
                        if p['short_channel_id_dir'] == chan:
                            total += p['amount_msat']
                return total
            amount_before = amount_through_chan(chan, route['routes'])

            l1.rpc.askrene_bias_channel('biases', chan, -bias)
            route2 = l1.rpc.getroutes(source=l1.info['id'],
                                      destination=nodeids[n],
                                      amount_msat=AMOUNT,
                                      layers=['auto.sourcefree', 'auto.localchans', 'biases'],
                                      maxfee_msat=MAX_FEE,
                                      final_cltv=18)
            if route2 != route:
                # It should have avoided biassed channel
                amount_after = amount_through_chan(chan, route2['routes'])
                if amount_after < amount_before:
                    num_changed[bias] += 1

            # Undo bias
            l1.rpc.askrene_bias_channel(layer='biases', short_channel_id_dir=chan, bias=0)

            # If it didn't change, try eliminating channel.
            if route2 == route and bias == 100:
                l1.rpc.askrene_update_channel(layer='biases',
                                              short_channel_id_dir=chan,
                                              enabled=False)
                try:
                    l1.rpc.getroutes(source=l1.info['id'],
                                     destination=nodeids[n],
                                     amount_msat=AMOUNT,
                                     layers=['auto.sourcefree', 'auto.localchans', 'biases'],
                                     maxfee_msat=MAX_FEE,
                                     final_cltv=18)
                    bias_ineffective += 1
                except RpcError:
                    pass
                l1.rpc.askrene_update_channel(layer='biases',
                                              short_channel_id_dir=chan,
                                              enabled=True)

    # With e^(-bias / (100/ln(30))):
    assert (num_changed, bias_ineffective) == expected


@pytest.mark.slow_test
def test_askrene_fake_channeld(node_factory, bitcoind):
    outfile = tempfile.NamedTemporaryFile(prefix='gossip-store-')
    nodeids = subprocess.check_output(['devtools/gossmap-compress',
                                       'decompress',
                                       '--node-map=2134=033845802d25b4e074ccfd7cd8b339a41dc75bf9978a034800444b51d42b07799a',
                                       'tests/data/gossip-store-2026-02-03.compressed',
                                       outfile.name]).decode('utf-8').splitlines()
    AMOUNT = 100_000_000

    # l2 will warn l1 about its invalid gossip: ignore.
    # We throttle l1's gossip to avoid massive log spam.
    l1, l2 = node_factory.line_graph(2,
                                     # This is in sats, so 1000x amount we send.
                                     fundamount=AMOUNT,
                                     opts=[{'gossip_store_file': outfile.name,
                                            'subdaemon': 'channeld:../tests/plugins/channeld_fakenet',
                                            'allow_warning': True,
                                            'dev-throttle-gossip': None},
                                           {'allow_bad_gossip': True}])

    # l1 needs to know l2's shaseed for the channel so it can make revocations
    hsmfile = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, "hsm_secret")
    # Needs peer node id and channel dbid (1, it's the first channel), prints out:
    # "shaseed: xxxxxxx\n"
    shaseed = subprocess.check_output(["tools/lightning-hsmtool", "dumpcommitments", l1.info['id'], "1", "0", hsmfile]).decode('utf-8').strip().partition(": ")[2]
    l1.rpc.dev_peer_shachain(l2.info['id'], shaseed)

    TEMPORARY_CHANNEL_FAILURE = 0x1007
    MPP_TIMEOUT = 0x17

    l1.rpc.askrene_create_layer('test_askrene_fake_channeld')
    for n in range(0, 100):
        if n in canned_gossmap_badnodes:
            continue

        print(f"PAYING Node #{n}")
        success = False
        while not success:
            routes = l1.rpc.getroutes(source=l1.info['id'],
                                      destination=nodeids[n],
                                      amount_msat=AMOUNT,
                                      layers=['auto.sourcefree', 'auto.localchans'],
                                      maxfee_msat=AMOUNT,
                                      final_cltv=18)

            preimage_hex = f'{n:02}' + '00' * 31
            hash_hex = sha256(bytes.fromhex(preimage_hex)).hexdigest()

            paths = {}
            # Sendpay wants a different format, so we convert.
            for i, r in enumerate(routes['routes']):
                paths[i] = [{'id': h['next_node_id'],
                             'channel': h['short_channel_id_dir'].split('/')[0],
                             'direction': int(h['short_channel_id_dir'].split('/')[1])}
                            for h in r['path']]

                # delay and amount_msat for sendpay are amounts at *end* of hop, not start!
                with_end = r['path'] + [{'amount_msat': r['amount_msat'], 'delay': r['final_cltv']}]
                for n, h in enumerate(paths[i]):
                    h['delay'] = with_end[n + 1]['delay']
                    h['amount_msat'] = with_end[n + 1]['amount_msat']

                l1.rpc.sendpay(paths[i], hash_hex,
                               amount_msat=AMOUNT,
                               payment_secret='00' * 32,
                               partid=i + 1, groupid=1)

            for i, p in paths.items():
                # Worst-case timeout is 1 second per hop, + 60 seconds if MPP timeout!
                try:
                    if l1.rpc.waitsendpay(hash_hex, timeout=TIMEOUT + len(p) + 60, partid=i + 1, groupid=1):
                        success = True
                except RpcError as err:
                    # Timeout means this one succeeded!
                    if err.error['data']['failcode'] == MPP_TIMEOUT:
                        for h in p:
                            l1.rpc.askrene_inform_channel('test_askrene_fake_channeld',
                                                          f"{h['channel']}/{h['direction']}",
                                                          h['amount_msat'],
                                                          'unconstrained')
                    elif err.error['data']['failcode'] == TEMPORARY_CHANNEL_FAILURE:
                        # We succeeded up to here
                        failpoint = err.error['data']['erring_index']
                        for h in p[:failpoint]:
                            l1.rpc.askrene_inform_channel('test_askrene_fake_channeld',
                                                          f"{h['channel']}/{h['direction']}",
                                                          h['amount_msat'],
                                                          'unconstrained')
                        h = p[failpoint]
                        l1.rpc.askrene_inform_channel('test_askrene_fake_channeld',
                                                      f"{h['channel']}/{h['direction']}",
                                                      h['amount_msat'],
                                                      'constrained')
                    else:
                        raise err


def test_simple_dummy_channel(node_factory):
    """Test if askrene can resolve a route with dummy channels, ie. channels
    that we might set artificially to resolve blinded paths and self payments,
    they have unlimited capacities and possibly zero fees."""
    ALOT = "2100000000000000sat"
    node1 = "020000000000000000000000000000000000000000000000000000000000000001"
    node2 = "020000000000000000000000000000000000000000000000000000000000000002"
    l1 = node_factory.get_node()
    l1.rpc.askrene_create_layer("mylayer")
    l1.rpc.askrene_create_channel(
        layer="mylayer",
        source=node1,
        destination=node2,
        short_channel_id="0x0x0",
        capacity_msat=ALOT,
    )
    l1.rpc.askrene_update_channel(
        layer="mylayer",
        short_channel_id_dir="0x0x0/0",
        enabled=True,
        htlc_minimum_msat=0,
        htlc_maximum_msat=ALOT,
        fee_base_msat=0,
        fee_proportional_millionths=0,
        cltv_expiry_delta=5,
    )
    l1.rpc.getroutes(
        source=node1,
        destination=node2,
        amount_msat=100,
        maxfee_msat=5000,
        final_cltv=5,
        layers=["mylayer"],
    )


def test_maxparts_infloop(node_factory, bitcoind):
    # Three paths from l1 -> l5.
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5)

    for intermediate in (l2, l3, l4):
        node_factory.join_nodes([l1, intermediate, l5])

    # We create exorbitant fees into l3.
    for n in (l2, l3, l4):
        n.rpc.setchannel(l5.info['id'], feeppm=100000)

    mine_funding_to_announce(bitcoind, (l1, l2, l3, l4, l5))
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 12)

    amount = 1_400_000_000
    # You can do this one
    route = l1.rpc.getroutes(source=l1.info['id'],
                             destination=l5.info['id'],
                             amount_msat=amount,
                             layers=[],
                             maxfee_msat=amount,
                             final_cltv=5)
    assert len(route['routes']) == 3

    route = l1.rpc.getroutes(source=l1.info['id'],
                             destination=l5.info['id'],
                             amount_msat=amount,
                             layers=[],
                             maxfee_msat=amount,
                             final_cltv=5,
                             maxparts=2)
    assert len(route['routes']) == 2


def test_askrene_timeout(node_factory, bitcoind):
    """Test askrene's route timeout"""
    l1, l2 = node_factory.line_graph(2, opts=[{'broken_log': 'linear_routes: timed out after deadline'}, {}])

    assert l1.rpc.listconfigs('askrene-timeout')['configs']['askrene-timeout']['value_int'] == 10
    l1.rpc.getroutes(source=l1.info['id'],
                     destination=l2.info['id'],
                     amount_msat=1,
                     layers=['auto.localchans'],
                     maxfee_msat=1,
                     final_cltv=5)


def test_reservations_leak(node_factory, executor):
    l1, l2, l3, l4, l5, l6 = node_factory.get_nodes(
        6,
        opts=[
            {"fee-base": 0, "fee-per-satoshi": 0},
            {"fee-base": 0, "fee-per-satoshi": 0},
            {
                "fee-base": 0,
                "fee-per-satoshi": 0,
                "plugin": os.path.join(os.getcwd(), "tests/plugins/hold_htlcs.py"),
            },
            {"fee-base": 0, "fee-per-satoshi": 0},
            {"fee-base": 0, "fee-per-satoshi": 0},
            {"fee-base": 1000, "fee-per-satoshi": 0},
        ],
    )

    # There must be a common non-local channel in both payment paths.
    # With a local channel we cannot trigger the reservation leak because we
    # reserve slightly different amounts locally due to HTLC onchain costs.
    node_factory.join_nodes([l1, l2, l4, l6, l3], wait_for_announce=True)
    node_factory.join_nodes([l1, l2, l4, l5], wait_for_announce=True)

    # Use offers instead of bolt11 because we are going to pay through a blinded
    # path and trigger a fake channel collision between both payments.
    offer1 = l3.rpc.offer("any")["bolt12"]
    offer2 = l5.rpc.offer("any")["bolt12"]

    inv1 = l1.rpc.fetchinvoice(offer1, "100sat")["invoice"]
    inv2 = l1.rpc.fetchinvoice(offer2, "101sat")["invoice"]

    # Initiate the first payment that has a delay.
    fut = executor.submit(l1.rpc.xpay, (inv1))

    # Wait for the first payment to reserve the path.
    l1.daemon.wait_for_log(r"json_askrene_reserve called")

    # A second payment starts.
    l1.rpc.xpay(inv2)
    l1.daemon.wait_for_log(r"json_askrene_unreserve called")

    l3.daemon.wait_for_log(r"Holding onto an incoming htlc for 10 seconds")

    # There is a payment pending therefore we expect reservations.
    reservations = l1.rpc.askrene_listreservations()
    assert reservations != {"reservations": []}

    l3.daemon.wait_for_log(r"htlc_accepted hook called")
    fut.result()
    l1.daemon.wait_for_log(r"json_askrene_unreserve called")

    # The first payment has finished we expect no reservations.
    reservations = l1.rpc.askrene_listreservations()
    assert reservations == {"reservations": []}

    # We shouldn't fail askrene-unreserve. If it does it means something went
    # wrong.
    assert l1.daemon.is_in_log("askrene-unreserve failed") is None

    # It will exit instantly.
    l1.rpc.setconfig('askrene-timeout', 0)

    with pytest.raises(RpcError, match='linear_routes: timed out after deadline'):
        l1.rpc.getroutes(source=l1.info['id'],
                         destination=l2.info['id'],
                         amount_msat=1,
                         layers=['auto.localchans'],
                         maxfee_msat=1,
                         final_cltv=5)

    # We can put it back though.
    l1.rpc.setconfig('askrene-timeout', 10)
    l1.rpc.getroutes(source=l1.info['id'],
                     destination=l2.info['id'],
                     amount_msat=1,
                     layers=['auto.localchans'],
                     maxfee_msat=1,
                     final_cltv=5)


def test_askrene_reserve_clash(node_factory, bitcoind):
    """Reserves get (erroneously) counted globally by scid, even for fake scids."""
    l1 = node_factory.get_node()

    node1 = "020000000000000000000000000000000000000000000000000000000000000001"
    node2 = "020000000000000000000000000000000000000000000000000000000000000002"
    l1.rpc.askrene_create_layer('layer1')
    l1.rpc.askrene_create_layer('layer2')
    l1.rpc.askrene_create_channel(layer="layer1",
                                  source=l1.info['id'],
                                  destination=node1,
                                  short_channel_id="0x0x0",
                                  capacity_msat=1000000)
    l1.rpc.askrene_update_channel(layer='layer1',
                                  short_channel_id_dir='0x0x0/1',
                                  enabled=True,
                                  htlc_minimum_msat=0,
                                  htlc_maximum_msat=1000000,
                                  fee_base_msat=1,
                                  fee_proportional_millionths=2,
                                  cltv_expiry_delta=18)
    l1.rpc.askrene_create_channel(layer="layer2",
                                  source=l1.info['id'],
                                  destination=node2,
                                  short_channel_id="0x0x0",
                                  capacity_msat=1000000)
    l1.rpc.askrene_update_channel(layer='layer2',
                                  short_channel_id_dir='0x0x0/1',
                                  enabled=True,
                                  htlc_minimum_msat=0,
                                  htlc_maximum_msat=1000000,
                                  fee_base_msat=1,
                                  fee_proportional_millionths=2,
                                  cltv_expiry_delta=18)
    l1.rpc.getroutes(source=l1.info['id'],
                     destination=node1,
                     amount_msat=500000,
                     layers=['layer1'],
                     maxfee_msat=1000,
                     final_cltv=5)
    l1.rpc.getroutes(source=l1.info['id'],
                     destination=node2,
                     amount_msat=500000,
                     layers=['layer2'],
                     maxfee_msat=1000,
                     final_cltv=5)

    l1.rpc.askrene_reserve(path=[{'short_channel_id_dir': '0x0x0/1',
                                  'amount_msat': 950000,
                                  'layer': 'layer1'
                                  }])

    # We can't use this on layer 1 anymore, only 50000 msat left.
    with pytest.raises(RpcError, match=r"We could not find a usable set of paths.  The shortest path is 0x0x0, but 0x0x0/1 already reserved 950000msat by command"):
        l1.rpc.getroutes(source=l1.info['id'],
                         destination=node1,
                         amount_msat=500000,
                         layers=['layer1'],
                         maxfee_msat=1000,
                         final_cltv=5)

    # But layer2 should be unaffected
    l1.rpc.getroutes(source=l1.info['id'],
                     destination=node2,
                     amount_msat=500000,
                     layers=['layer2'],
                     maxfee_msat=1000,
                     final_cltv=5)


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_splice_dying_channel(node_factory, bitcoind):
    """We should NOT try to use the pre-splice channel here"""
    l1, l2, l3 = node_factory.line_graph(3,
                                         wait_for_announce=True,
                                         fundamount=200000,
                                         opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)
    funds_result = l1.rpc.addpsbtoutput(100000)
    pre_splice_scidd = first_scidd(l1, l2)

    # Pay with fee by subjtracting 5000 from channel balance
    result = l1.rpc.splice_init(chan_id, -105000, funds_result['psbt'])
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is False)
    result = l1.rpc.splice_update(chan_id, result['psbt'])
    assert(result['commitments_secured'] is True)
    result = l1.rpc.splice_signed(chan_id, result['psbt'])

    mine_funding_to_announce(bitcoind,
                             [l1, l2, l3],
                             num_blocks=6, wait_for_mempool=1)

    wait_for(lambda: only_one(l1.rpc.listpeerchannels()['channels'])['state'] == 'CHANNELD_NORMAL')
    post_splice_scidd = first_scidd(l1, l2)

    # You will use the new scid
    route = only_one(l1.rpc.getroutes(l1.info['id'], l2.info['id'], '50000sat', ['auto.localchans'], 100000, 6)['routes'])
    assert only_one(route['path'])['short_channel_id_dir'] == post_splice_scidd

    # And you will not be able to route 100001 sats:
    with pytest.raises(RpcError, match="We could not find a usable set of paths"):
        l1.rpc.getroutes(l1.info['id'], l2.info['id'], '100001sat', ['auto.localchans'], 100000, 6)

    # But l3 would think it can use both, since it doesn't eliminate dying channel!
    wait_for(lambda: [c['active'] for c in l3.rpc.listchannels()['channels']] == [True] * 6)
    routes = l3.rpc.getroutes(l1.info['id'], l2.info['id'], '200001sat', [], 100000, 6)['routes']
    assert set([only_one(r['path'])['short_channel_id_dir'] for r in routes]) == set([pre_splice_scidd, post_splice_scidd])


def test_excessive_fee_cost(node_factory):
    """Produce a arc with very large fee cost that triggers an assertion in
    askrene's single path solver."""
    l1 = node_factory.get_node()
    node1 = "020000000000000000000000000000000000000000000000000000000000000001"
    one_btc = 100000000000
    l1.rpc.askrene_create_layer("mylayer")
    l1.rpc.askrene_create_channel(
        layer="mylayer",
        source=l1.info["id"],
        destination=node1,
        short_channel_id="0x0x0",
        capacity_msat=one_btc,
    )
    l1.rpc.askrene_update_channel(
        layer="mylayer",
        short_channel_id_dir="0x0x0/1",
        enabled=True,
        htlc_minimum_msat=0,
        htlc_maximum_msat=one_btc,
        fee_base_msat=0,
        fee_proportional_millionths=100000,  # 10%
        cltv_expiry_delta=18,
    )
    with pytest.raises(RpcError, match=r"Could not find route without excessive cost"):
        l1.rpc.getroutes(
            source=l1.info["id"],
            destination=node1,
            amount_msat=one_btc // 2,
            layers=["mylayer", "auto.no_mpp_support"],
            maxfee_msat=1000,
            final_cltv=5,
        )


def check_getroute_routes(
    node,
    source,
    destination,
    amount_msat,
    routes,
    layers=[],
    maxfee_msat=1000,
    final_cltv=99,
):
    """Check that routes are as expected in result. This is similar to
    check_getroute_paths but it compares all fields inside the routes and not
    just the path."""

    def check_route_as_expected(routes, expected_routes):
        """Make sure all fields in paths are match those in routes"""

        def dict_subset_eq(a, b):
            """Is every key in B is the same in A?"""
            return all(a.get(key) == b[key] for key in b if key != "path")

        for r in expected_routes:
            found = False
            for i, candidate in enumerate(routes):
                pathlen = len(r["path"])
                if len(candidate["path"]) != pathlen:
                    continue
                if dict_subset_eq(candidate, r) and all(
                    dict_subset_eq(candidate["path"][i], r["path"][i])
                    for i in range(pathlen)
                ):
                    del routes[i]
                    found = True
                    break

            if not found:
                raise ValueError(
                    "Could not find route {} in routes {}".format(r, routes)
                )

        if routes != []:
            raise ValueError("Did not expect paths {}".format(routes))

    getroutes = node.rpc.getroutes(
        source=source,
        destination=destination,
        amount_msat=amount_msat,
        layers=layers,
        maxfee_msat=maxfee_msat,
        final_cltv=final_cltv,
    )
    assert getroutes["probability_ppm"] <= 1000000
    check_route_as_expected(getroutes["routes"], routes)


def test_includefees(node_factory):
    """Test the amounts in the hops is set correctly when we use
    auto.include_fees layer."""
    gsfile, nodemap = generate_gossip_store(
        [
            GenChannel(
                0,
                1,
                capacity_sats=1000000,
                forward=GenChannel.Half(basefee=1, propfee=10000, delay=5),
            ),
            GenChannel(
                1,
                2,
                capacity_sats=1000000,
                forward=GenChannel.Half(basefee=2, propfee=20000, delay=5),
            ),
            GenChannel(
                2,
                3,
                capacity_sats=1000000,
                forward=GenChannel.Half(basefee=3, propfee=30000, delay=5),
            ),
        ]
    )
    l1 = node_factory.get_node(gossip_store_file=gsfile.name)

    # Check computed fees in normal mode
    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[1],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1011,
                        "delay": 99 + 5,
                    }
                ],
            }
        ],
        layers=[],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[2],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1033,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1022,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=[],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[3],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1066,
                        "delay": 99 + 5 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1055,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "4x3x2/0",
                        "next_node_id": nodemap[3],
                        "amount_msat": 1033,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=[],
    )

    # Check computed fees in include_fees mode
    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[1],
        1000,
        [
            # we compute a route for 1000msat and the recepient receives 990
            {
                "amount_msat": 990,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99 + 5,
                    }
                ],
            }
        ],
        layers=["auto.include_fees"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[2],
        1000,
        [
            {
                "amount_msat": 969,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 990,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.include_fees"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[3],
        1000,
        [
            {
                "amount_msat": 938,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99 + 5 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 990,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "4x3x2/0",
                        "next_node_id": nodemap[3],
                        "amount_msat": 969,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.include_fees"],
    )

    # Normal mode combined with "auto.sourcefree"
    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[1],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99,
                    }
                ],
            }
        ],
        layers=["auto.sourcefree"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[2],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1022,
                        "delay": 99 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1022,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.sourcefree"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[3],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1055,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1055,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "4x3x2/0",
                        "next_node_id": nodemap[3],
                        "amount_msat": 1033,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.sourcefree"],
    )

    # "auto.include_fees" mode combined with "auto.sourcefree"
    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[1],
        1000,
        [
            {
                "amount_msat": 1000,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99,
                    }
                ],
            }
        ],
        layers=["auto.sourcefree", "auto.include_fees"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[2],
        1000,
        [
            {
                "amount_msat": 979,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1000,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.sourcefree", "auto.include_fees"],
    )

    check_getroute_routes(
        l1,
        nodemap[0],
        nodemap[3],
        1000,
        [
            {
                "amount_msat": 948,
                "path": [
                    {
                        "short_channel_id_dir": "0x1x0/1",
                        "next_node_id": nodemap[1],
                        "amount_msat": 1000,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "2x2x1/1",
                        "next_node_id": nodemap[2],
                        "amount_msat": 1000,
                        "delay": 99 + 5 + 5,
                    },
                    {
                        "short_channel_id_dir": "4x3x2/0",
                        "next_node_id": nodemap[3],
                        "amount_msat": 979,
                        "delay": 99 + 5,
                    },
                ],
            }
        ],
        layers=["auto.sourcefree", "auto.include_fees"],
    )


def test_impossible_payment(node_factory):
    """A payment that is impossible due to HTLC constraints and fees. The
    constraint might cause a timeout in in askrene's main loop due to the refine
    step."""
    l1 = node_factory.get_node()
    node1 = "020000000000000000000000000000000000000000000000000000000000000001"
    node2 = "020000000000000000000000000000000000000000000000000000000000000002"
    node3 = "020000000000000000000000000000000000000000000000000000000000000003"
    million_sats = 1000000000
    pay_amt = 10000000
    base_amt = int(pay_amt * 1.1)
    l1.rpc.askrene_create_layer("mylayer")
    l1.rpc.askrene_create_channel(
        layer="mylayer",
        source=node1,
        destination=node2,
        short_channel_id="0x0x1",
        capacity_msat=million_sats,
    )
    l1.rpc.askrene_update_channel(
        layer="mylayer",
        short_channel_id_dir="0x0x1/0",
        enabled=True,
        htlc_minimum_msat=0,
        htlc_maximum_msat=base_amt,
        fee_base_msat=0,
        fee_proportional_millionths=0,
        cltv_expiry_delta=18,
    )
    l1.rpc.askrene_create_channel(
        layer="mylayer",
        source=node2,
        destination=node3,
        short_channel_id="0x0x2",
        capacity_msat=million_sats,
    )
    l1.rpc.askrene_update_channel(
        layer="mylayer",
        short_channel_id_dir="0x0x2/0",
        enabled=True,
        htlc_minimum_msat=0,
        htlc_maximum_msat=million_sats,
        fee_base_msat=base_amt,
        fee_proportional_millionths=0,
        cltv_expiry_delta=18,
    )
    with pytest.raises(
        RpcError,
        match=r"We could not find a usable set of paths.  The shortest path is 0x0x1->0x0x2, but 0x0x1/0 exceeds htlc_maximum_msat",
    ):
        l1.rpc.getroutes(
            source=node1,
            destination=node3,
            amount_msat=pay_amt,
            layers=["mylayer"],
            maxfee_msat=2 * pay_amt,
            final_cltv=5,
        )
    with pytest.raises(
        RpcError,
        match=r"We could not find a usable set of paths.  The shortest path is 0x0x1->0x0x2, but 0x0x1/0 exceeds htlc_maximum_msat",
    ):
        l1.rpc.getroutes(
            source=node1,
            destination=node3,
            amount_msat=pay_amt,
            layers=["mylayer", "auto.no_mpp_support"],
            maxfee_msat=2 * pay_amt,
            final_cltv=5,
        )
