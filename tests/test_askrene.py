from fixtures import *  # noqa: F401,F403
from utils import (
    only_one, first_scid
)
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
