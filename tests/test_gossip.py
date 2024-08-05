from collections import Counter
from fixtures import *  # noqa: F401,F403
from fixtures import TEST_NETWORK
from pyln.client import RpcError, Millisatoshi
from utils import (
    wait_for, TIMEOUT, only_one, sync_blockheight,
    expected_node_features,
    mine_funding_to_announce, default_ln_port, CHANNEL_SIZE,
    first_scid, generate_gossip_store, GenChannel
)

import json
import logging
import math
import os
import pytest
import struct
import subprocess
import time
import unittest
import shutil
import socket


with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])


def test_gossip_pruning(node_factory, bitcoind):
    """ Create channel and see it being updated in time before pruning
    """
    l1, l2, l3 = node_factory.get_nodes(3, opts={'dev-fast-gossip-prune': None,
                                                 'allow_bad_gossip': True})

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    scid1, _ = l1.fundchannel(l2, 10**6)
    scid2, _ = l2.fundchannel(l3, 10**6)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Channels should be activated locally
    wait_for(lambda: [c['active'] for c in l1.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l2.rpc.listchannels()['channels']] == [True] * 4)
    wait_for(lambda: [c['active'] for c in l3.rpc.listchannels()['channels']] == [True] * 4)

    # All of them should send a keepalive message (after 30 seconds)
    l1.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
    ], timeout=50)
    l2.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid1),
        'Sending keepalive channel_update for {}'.format(scid2),
    ])
    l3.daemon.wait_for_logs([
        'Sending keepalive channel_update for {}'.format(scid2),
    ])

    # Now kill l2, so that l1 and l3 will prune from their view after 60 seconds
    l2.stop()

    # We check every 60/4 seconds, and takes 60 seconds since last update.
    l1.daemon.wait_for_log("Pruning channel {} from network view".format(scid2),
                           timeout=80)
    l3.daemon.wait_for_log("Pruning channel {} from network view".format(scid1))

    assert scid2 not in [c['short_channel_id'] for c in l1.rpc.listchannels()['channels']]
    assert scid1 not in [c['short_channel_id'] for c in l3.rpc.listchannels()['channels']]
    assert l3.info['id'] not in [n['nodeid'] for n in l1.rpc.listnodes()['nodes']]
    assert l1.info['id'] not in [n['nodeid'] for n in l3.rpc.listnodes()['nodes']]


def test_gossip_disable_channels(node_factory, bitcoind):
    """Simple test to check that channels get disabled correctly on disconnect and
    reenabled upon reconnecting

    """
    opts = {'dev-no-reconnect': None, 'may_reconnect': True}
    l1, l2 = node_factory.get_nodes(2, opts=opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
    bitcoind.generate_block(5)

    def count_active(node):
        chans = node.rpc.listchannels()['channels']
        active = [c for c in chans if c['active']]
        connected = len([p for p in node.rpc.listpeerchannels()['channels'] if p['peer_connected'] is True])
        return connected * len(active)

    l1.wait_channel_active(scid)
    l2.wait_channel_active(scid)

    assert(count_active(l1) == 2)
    assert(count_active(l2) == 2)

    l2.restart()

    wait_for(lambda: count_active(l1) == 0)
    assert(count_active(l2) == 0)

    # Now reconnect, they should re-enable the channels
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    wait_for(lambda: count_active(l1) == 2)
    wait_for(lambda: count_active(l2) == 2)


def test_announce_address(node_factory, bitcoind):
    """Make sure our announcements are well formed."""

    # We do not allow announcement of duplicates.
    opts = {'announce-addr':
            ['4acth47i6kxnvkewtm6q7ib2s3ufpo5sqbsnzjpbi7utijcltosqemad.onion',
             '1.2.3.4:1234',
             'dns:example.com:1236',
             '::'],
            'log-level': 'io',
            'dev-allow-localhost': None}
    l1, l2 = node_factory.get_nodes(2, opts=[opts, {}])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
    bitcoind.generate_block(5)

    l1.wait_channel_active(scid)
    l2.wait_channel_active(scid)

    # We should see it send node announce with all addresses (257 = 0x0101)
    # Note: local ephemeral port is masked out.
    # Note: Since we `disable-dns` it should not announce a resolved IPv4
    #       or IPv6 address for example.com
    #
    # Also expect the address descriptor types to be sorted!
    # BOLT #7:
    #   - MUST place address descriptors in ascending order.
    l1.daemon.wait_for_log(r"\[OUT\] 0101.*0056"
                           "010102030404d2"  # IPv4 01 1.2.3.4:1234
                           "017f000001...."  # IPv4 01 127.0.0.1:wxyz
                           "0200000000000000000000000000000000...."  # IPv6 02 :::<any_port>
                           "04e00533f3e8f2aedaa8969b3d0fa03a96e857bbb28064dca5e147e934244b9ba5023003...."  # TORv3 04
                           "050b6578616d706c652e636f6d04d4")  # DNS 05 len example.com:1236

    # Check other node can parse these (make sure it has digested msg)
    wait_for(lambda: 'addresses' in l2.rpc.listnodes(l1.info['id'])['nodes'][0])
    addresses = l2.rpc.listnodes(l1.info['id'])['nodes'][0]['addresses']
    addresses_dns = [address for address in addresses if address['type'] == 'dns']
    assert len(addresses) == 5
    assert len(addresses_dns) == 1
    assert addresses_dns[0]['address'] == 'example.com'
    assert addresses_dns[0]['port'] == 1236


def test_announce_dns_suppressed(node_factory, bitcoind):
    """By default announce DNS names as IPs"""
    opts = {'announce-addr': 'example.com:1236',
            'start': False}
    l1, l2 = node_factory.get_nodes(2, opts=[opts, {}])
    # Remove unwanted disable-dns option!
    del l1.daemon.opts['disable-dns']
    l1.start()

    # Need a channel so l1 will announce itself.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
    bitcoind.generate_block(5)

    # Wait for l2 to see l1, with addresses.
    wait_for(lambda: l2.rpc.listnodes(l1.info['id'])['nodes'] != [])
    wait_for(lambda: 'addresses' in only_one(l2.rpc.listnodes(l1.info['id'])['nodes']))

    addresses = only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['addresses']
    assert len(addresses) == 1
    assert addresses[0]['type'] in ['ipv4', 'ipv6']
    assert addresses[0]['address'] != 'example.com'
    assert addresses[0]['port'] == 1236


def test_announce_and_connect_via_dns(node_factory, bitcoind):
    """ Test that DNS announcements propagate and can be used when connecting.

        - First node announces only a FQDN like 'localhost.localdomain'.
        - Second node gets a channel with first node.
        - Third node just connects to second node.
        - Fourth node with DNS disabled also connects to second node.
        - Wait for gossip so third and fourth node sees first node.
        - Third node must be able to 'resolve' 'localhost.localdomain'
          and connect to first node.
        - Fourth node must not be able to connect because he has disabled DNS.

        Notes:
        - --disable-dns is needed so the first node does not announce 127.0.0.1 itself.
        - 'dev-allow-localhost' must not be set, so it does not resolve localhost anyway.
    """
    opts1 = {'disable-dns': None,
             'announce-addr': ['dns:localhost.localdomain:12345'],  # announce dns
             'bind-addr': ['127.0.0.1:12345', '[::1]:12345']}   # and bind local IPs
    opts3 = {'may_reconnect': True}
    opts4 = {'disable-dns': None}
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=[opts1, {}, opts3, opts4])

    # In order to enable DNS on a pyln testnode we need to delete the
    # 'disable-dns' opt (which is added by pyln test utils) and restart it.
    del l3.daemon.opts['disable-dns']
    l3.restart()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l4.rpc.connect(l2.info['id'], 'localhost', l2.port)
    scid, _ = l1.fundchannel(l2, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # wait until l3 and l4 see l1 via gossip with announced addresses
    wait_for(lambda: len(l3.rpc.listnodes(l1.info['id'])['nodes']) == 1)
    wait_for(lambda: len(l4.rpc.listnodes(l1.info['id'])['nodes']) == 1)
    wait_for(lambda: 'addresses' in l3.rpc.listnodes(l1.info['id'])['nodes'][0])
    wait_for(lambda: 'addresses' in l4.rpc.listnodes(l1.info['id'])['nodes'][0])
    addresses = l3.rpc.listnodes(l1.info['id'])['nodes'][0]['addresses']
    assert(len(addresses) == 1)  # no other addresses must be announced for this
    assert(addresses[0]['type'] == 'dns')
    assert(addresses[0]['address'] == 'localhost.localdomain')
    assert(addresses[0]['port'] == 12345)

    # now l3 must be able to use DNS to resolve and connect to l1
    result = l3.rpc.connect(l1.info['id'])
    assert result['id'] == l1.info['id']
    assert result['direction'] == 'out'
    assert result['address']['port'] == 12345
    if result['address']['type'] == 'ipv4':
        assert result['address']['address'] == '127.0.0.1'
    elif result['address']['type'] == 'ipv6':
        assert result['address']['address'] == '::1'
    else:
        assert False

    # l4 however must not be able to connect because he used '--disable-dns'
    # This raises RpcError code 401, currently with an empty error message.
    with pytest.raises(RpcError, match=r"401.*dns disabled"):
        l4.rpc.connect(l1.info['id'])


def test_only_announce_one_dns(node_factory, bitcoind):
    # and test that we can't announce more than one DNS address
    l1 = node_factory.get_node(expect_fail=True, start=False,
                               options={'announce-addr': ['dns:localhost.localdomain:12345', 'dns:example.com:12345']})
    l1.daemon.start(wait_for_initialized=False, stderr_redir=True)
    wait_for(lambda: l1.daemon.is_in_stderr("Only one DNS can be announced"))


def test_announce_dns_without_port(node_factory, bitcoind):
    """ Checks that the port of a DNS announcement is set to the corresponding
        network port. In this case regtest 19846
    """
    opts = {'announce-addr': ['dns:example.com']}
    l1 = node_factory.get_node(options=opts)

    # 'address': [{'type': 'dns', 'address': 'example.com', 'port': 0}]
    info = l1.rpc.getinfo()
    assert info['address'][0]['type'] == 'dns'
    assert info['address'][0]['address'] == 'example.com'

    if TEST_NETWORK == 'regtest':
        default_port = 19846
    else:
        assert TEST_NETWORK == 'liquid-regtest'
        default_port = 20735
    assert info['address'][0]['port'] == default_port


def test_gossip_timestamp_filter(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.line_graph(4, fundchannel=False, opts={'log-level': 'io'})
    genesis_blockhash = chainparams['chain_hash']

    before_anything = int(time.time())

    # Make a public channel.
    chan12, _ = l1.fundchannel(l2, 10**5)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])

    l3.wait_for_channel_updates([chan12])
    after_12 = int(time.time())

    # Make another one, different timestamp.
    time.sleep(10)
    before_23 = int(time.time())
    chan23, _ = l2.fundchannel(l3, 10**5)
    bitcoind.generate_block(5)

    l1.wait_for_channel_updates([chan23])
    after_23 = int(time.time()) + 1

    # Make sure l4 has received all the gossip.
    wait_for(lambda: ['alias' in node for node in l4.rpc.listnodes()['nodes']] == [True, True, True])

    msgs = l4.query_gossip('gossip_timestamp_filter',
                           genesis_blockhash,
                           '0', '0xFFFFFFFF',
                           filters=['0109', '0107', '0012'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # 0x0101 = node_announcement
    # The order of node_announcements relative to others is undefined.
    types = Counter([m[0:4] for m in msgs])
    assert types == Counter(['0100'] * 2 + ['0102'] * 4 + ['0101'] * 3)

    # Now timestamp which doesn't overlap (gives nothing).
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           genesis_blockhash,
                           '0', before_anything,
                           filters=['0109', '0107', '0012'])
    assert msgs == []

    # Now choose range which will only give first update.
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           genesis_blockhash,
                           before_anything,
                           after_12 - before_anything + 1,
                           filters=['0109', '0107', '0012'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    types = Counter([m[0:4] for m in msgs])
    assert types['0100'] == 1
    assert types['0102'] == 2

    # Now choose range which will only give second update.
    msgs = l4.query_gossip('gossip_timestamp_filter',
                           genesis_blockhash,
                           before_23,
                           after_23 - before_23 + 1,
                           filters=['0109', '0107', '0012'])

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # (Node announcement may have any timestamp)
    types = Counter([m[0:4] for m in msgs])
    assert types['0100'] == 1
    assert types['0102'] == 2


def test_connect_by_gossip(node_factory, bitcoind):
    """Test connecting to an unknown peer using node gossip
    """
    # l1 announces a bogus addresses.
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'announce-addr':
                                               ['127.0.0.1:2',
                                                '[::]:2',
                                                'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion'],
                                               'dev-allow-localhost': None},
                                              {},
                                              {'dev-allow-localhost': None,
                                               'log-level': 'io'}])
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Nodes are gossiped only if they have channels
    chanid, _ = l2.fundchannel(l3, 10**6)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Let channel reach announcement depth
    l2.wait_channel_active(chanid)

    # Make sure l3 has given node announcement to l2.
    l2.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Let l1 learn of l3 by node gossip
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.daemon.wait_for_logs(['Received node_announcement for node {}'.format(l3.info['id'])])

    # Have l1 connect to l3 without explicit host and port.
    ret = l1.rpc.connect(l3.info['id'])
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l3.port}

    # Now give it *wrong* port (after we make sure l2 isn't listening), it should fall back.
    l1.rpc.disconnect(l3.info['id'])
    l2.stop()
    ret = l1.rpc.connect(l3.info['id'], 'localhost', l2.port)
    assert ret['address'] == {'type': 'ipv4', 'address': '127.0.0.1', 'port': l3.port}


def test_gossip_jsonrpc(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True, wait_for_announce=False)

    # Shouldn't send announce signatures until 6 deep.
    assert not l1.daemon.is_in_log('peer_out WIRE_ANNOUNCEMENT_SIGNATURES')

    # Make sure we can route through the channel, will raise on failure
    l1.rpc.getroute(l2.info['id'], 100, 1)

    # Channels not should be activated locally
    assert l1.rpc.listchannels() == {'channels': []}
    assert l2.rpc.listchannels() == {'channels': []}

    # Outgoing should be public, even if not announced yet.
    channels1 = l1.rpc.listpeerchannels()['channels']
    channels2 = l2.rpc.listpeerchannels()['channels']

    assert [c['private'] for c in channels1] == [False]
    assert [c['private'] for c in channels2] == [False]

    # Now proceed to funding-depth and do a full gossip round
    l1.bitcoin.generate_block(5)
    # Could happen in either order.
    l1.daemon.wait_for_logs(['peer_out WIRE_ANNOUNCEMENT_SIGNATURES',
                             'peer_in WIRE_ANNOUNCEMENT_SIGNATURES'])

    # Just wait for the update to kick off and then check the effect
    needle = "Received node_announcement for node"
    l1.daemon.wait_for_log(needle)
    l2.daemon.wait_for_log(needle)
    l1.wait_channel_active(only_one(channels1)['short_channel_id'])
    l2.wait_channel_active(only_one(channels1)['short_channel_id'])

    # Test listchannels-by-source
    channels1 = l1.rpc.listchannels(source=l1.info['id'])['channels']
    channels2 = l2.rpc.listchannels(source=l1.info['id'])['channels']
    assert only_one(channels1)['source'] == l1.info['id']
    assert only_one(channels1)['destination'] == l2.info['id']
    if l1.info['id'] > l2.info['id']:
        assert only_one(channels1)['direction'] == 1
    else:
        assert only_one(channels1)['direction'] == 0
    assert channels1 == channels2

    # Test listchannels-by-destination
    channels1 = l1.rpc.listchannels(destination=l1.info['id'])['channels']
    channels2 = l2.rpc.listchannels(destination=l1.info['id'])['channels']
    assert only_one(channels1)['destination'] == l1.info['id']
    assert only_one(channels1)['source'] == l2.info['id']
    if l2.info['id'] > l1.info['id']:
        assert only_one(channels1)['direction'] == 1
    else:
        assert only_one(channels1)['direction'] == 0
    assert channels1 == channels2

    # Test only one of short_channel_id, source or destination can be supplied
    with pytest.raises(RpcError, match=r"Can only specify one of.*"):
        l1.rpc.listchannels(source=l1.info['id'], destination=l2.info['id'])
    with pytest.raises(RpcError, match=r"Can only specify one of.*"):
        l1.rpc.listchannels(short_channel_id="1x1x1", source=l2.info['id'])

    nodes = l1.rpc.listnodes()['nodes']
    assert set([n['nodeid'] for n in nodes]) == set([l1.info['id'], l2.info['id']])

    # Test listnodes with an arg, while we're here.
    n1 = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    n2 = l1.rpc.listnodes(l2.info['id'])['nodes'][0]
    assert n1['nodeid'] == l1.info['id']
    assert n2['nodeid'] == l2.info['id']

    # Might not have seen other node-announce yet.
    assert n1['alias'].startswith('JUNIORBEAM')
    assert n1['color'] == '0266e4'
    if 'alias' not in n2:
        assert 'color' not in n2
        assert 'addresses' not in n2
    else:
        assert n2['alias'].startswith('SILENTARTIST')
        assert n2['color'] == '022d22'

    assert [c['active'] for c in l1.rpc.listchannels()['channels']] == [True, True]
    assert [c['public'] for c in l1.rpc.listchannels()['channels']] == [True, True]
    assert [c['active'] for c in l2.rpc.listchannels()['channels']] == [True, True]
    assert [c['public'] for c in l2.rpc.listchannels()['channels']] == [True, True]


def test_gossip_badsig(node_factory, bitcoind):
    """Make sure node announcement signatures are ok.

    This is a smoke test to see if signatures fail. This used to be the case
    occasionally before PR #276 was merged: we'd be waiting for the HSM to reply
    with a signature and would then regenerate the message, which might roll the
    timestamp, invalidating the signature.

    """
    l1, l2, l3 = node_factory.get_nodes(3)

    # l2 connects to both, so l1 can't reconnect and thus l2 drops to chain
    l2.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.fundchannel(l1, 10**6)
    l2.fundchannel(l3, 10**6)

    # Wait for route propagation.
    mine_funding_to_announce(bitcoind, [l1, l2, l3])
    l1.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l3.info['id']))
    assert not l1.daemon.is_in_log('signature verification failed')
    assert not l2.daemon.is_in_log('signature verification failed')
    assert not l3.daemon.is_in_log('signature verification failed')


def test_gossip_weirdalias(node_factory, bitcoind):
    weird_name = '\t \n \" \n \r \n \\'
    normal_name = 'Normal name'
    opts = [
        {'alias': weird_name},
        {'alias': normal_name}
    ]
    l1, l2 = node_factory.get_nodes(2, opts=opts)
    weird_name_json = json.encoder.JSONEncoder().encode(weird_name)[1:-1]
    aliasline = l1.daemon.is_in_log('Server started with public key .* alias')
    assert weird_name_json in str(aliasline)
    assert l2.daemon.is_in_log('Server started with public key .* alias {}'
                               .format(normal_name))

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.daemon.wait_for_log('Handed peer, entering loop')
    l2.fundchannel(l1, 10**6)
    bitcoind.generate_block(6)

    # They should gossip together.
    l1.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l2.info['id']))
    l2.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l1.info['id']))

    node = l1.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['alias'] == weird_name
    node = l2.rpc.listnodes(l1.info['id'])['nodes'][0]
    assert node['alias'] == weird_name


def test_gossip_persistence(node_factory, bitcoind):
    """Gossip for a while, restart and it should remember.

    Also tests for funding outpoint spends, and they should be persisted
    too.
    """
    opts = {'dev-no-reconnect': None, 'may_reconnect': True}
    l1, l2, l3, l4 = node_factory.get_nodes(4, opts=opts)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)

    scid12, _ = l1.fundchannel(l2, 10**6)
    scid23, _ = l2.fundchannel(l3, 10**6)

    # Make channels public, except for l3 -> l4, which is kept local-only
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])
    scid34, _ = l3.fundchannel(l4, 10**6, announce_channel=False)
    bitcoind.generate_block(1)

    def active(node):
        chans = node.rpc.listchannels()['channels']
        return sorted([c['short_channel_id'] for c in chans if c['active']])

    def non_public(node):
        # Not just c["private"] == True, but immature ones too.
        public_chans = [c['short_channel_id'] for c in node.rpc.listchannels()['channels']]
        our_chans = [c['short_channel_id'] for c in node.rpc.listpeerchannels()['channels'] if c['state'] in ('CHANNELD_NORMAL', 'CHANNELD_AWAITING_SPLICE')]
        return sorted(list(set(our_chans) - set(public_chans)))

    # Channels should be activated
    wait_for(lambda: active(l1) == [scid12, scid12, scid23, scid23])
    wait_for(lambda: active(l2) == [scid12, scid12, scid23, scid23])
    # This one has private channels, but doesn't appear in listchannels.
    wait_for(lambda: active(l3) == [scid12, scid12, scid23, scid23])

    # l1 restarts and public gossip should persist
    l1.restart()
    wait_for(lambda: active(l1) == [scid12, scid12, scid23, scid23])

    # Now reconnect, they should re-enable the two l1 <-> l2 directions
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: active(l1) == [scid12, scid12, scid23, scid23])

    # Now spend the funding tx, generate a block and see others deleting the
    # channel from their network view
    l1.rpc.dev_fail(l2.info['id'])

    # We need to wait for the unilateral close to hit the mempool,
    # and 12 blocks for nodes to actually forget it.
    bitcoind.generate_block(13, wait_for_mempool=1)

    wait_for(lambda: active(l1) == [scid23, scid23])
    wait_for(lambda: active(l2) == [scid23, scid23])
    wait_for(lambda: active(l3) == [scid23, scid23])

    # The channel l3 -> l4 should be known only to them
    assert non_public(l1) == []
    assert non_public(l2) == []
    wait_for(lambda: non_public(l3) == [scid34])
    wait_for(lambda: non_public(l4) == [scid34])

    # Finally, it should also remember the deletion after a restart
    l3.restart()
    l4.restart()
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l3.rpc.connect(l4.info['id'], 'localhost', l4.port)
    wait_for(lambda: active(l3) == [scid23, scid23])

    # Both l3 and l4 should remember their local-only channel
    wait_for(lambda: non_public(l3) == [scid34])
    wait_for(lambda: non_public(l4) == [scid34])


def test_routing_gossip_reconnect(node_factory, bitcoind):
    # Connect two peers, reconnect and then see if we resume the
    # gossip.
    disconnects = ['-WIRE_CHANNEL_ANNOUNCEMENT']
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{'disconnect': disconnects,
                                               'may_reconnect': True},
                                              {'may_reconnect': True},
                                              {}])
    # Make sure everyone is up to block height so we don't get bad gossip msgs!
    sync_blockheight(bitcoind, [l1, l2, l3])

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.openchannel(l2, CHANNEL_SIZE)

    # Make sure everyone is up to block height so we don't get bad gossip msgs!
    sync_blockheight(bitcoind, [l1, l2, l3])

    # Now open new channels and everybody should sync
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    l2.openchannel(l3, CHANNEL_SIZE)

    # Settle the gossip
    for n in [l1, l2, l3]:
        wait_for(lambda: len(n.rpc.listchannels()['channels']) == 4)


def test_gossip_no_empty_announcements(node_factory, bitcoind, chainparams):
    # Need full IO logging so we can see gossip
    # l2 sends CHANNEL_ANNOUNCEMENT to l1, but not CHANNEL_UDPATE.
    l1, l2, l3, l4 = node_factory.line_graph(4, opts=[{'log-level': 'io',
                                                       'dev-no-reconnect': None},
                                                      {'log-level': 'io',
                                                       'disconnect': ['+WIRE_CHANNEL_ANNOUNCEMENT'],
                                                       'may_reconnect': True},
                                                      {'may_reconnect': True},
                                                      {'may_reconnect': True}],
                                             fundchannel=False)

    l3.fundchannel(l4, 10**5)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])

    # l2 sends CHANNEL_ANNOUNCEMENT to l1, then disconnects/
    l2.daemon.wait_for_log('dev_disconnect')
    l1.daemon.wait_for_log(r'\[IN\] 0100')
    wait_for(lambda: l1.rpc.listchannels()['channels'] == [])

    # l1 won't mention it in reply (make sure it has time to digest though)
    # but it may actually relay it
    time.sleep(2)
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00'],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    assert l1.query_gossip('query_channel_range',
                           chainparams['chain_hash'],
                           0, 1000000,
                           filters=['0109', '0107', '0012', '0100']) == ['0108'
                                                                         # blockhash
                                                                         + chainparams['chain_hash']
                                                                         # first_blocknum, number_of_blocks, complete
                                                                         + format(0, '08x') + format(1000000, '08x') + '01'
                                                                         # encoded_short_ids
                                                                         + format(len(encoded) // 2, '04x')
                                                                         + encoded]

    # If we reconnect, gossip will now flow.
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)


def test_routing_gossip(node_factory, bitcoind):
    nodes = node_factory.get_nodes(5)

    for i in range(len(nodes) - 1):
        src, dst = nodes[i], nodes[i + 1]
        src.rpc.connect(dst.info['id'], 'localhost', dst.port)
        src.openchannel(dst, CHANNEL_SIZE, confirm=False, wait_for_announce=False)

    # openchannel calls fundwallet which mines a block; so first channel
    # is 4 deep, last is unconfirmed.

    # Allow announce messages, but don't run too fast, otherwise gossip can be in the future for nodes.
    sync_blockheight(bitcoind, nodes)
    bitcoind.generate_block(wait_for_mempool=1)
    mine_funding_to_announce(bitcoind, nodes)

    # Deep check that all channels are in there
    comb = []
    for i in range(len(nodes) - 1):
        comb.append((nodes[i].info['id'], nodes[i + 1].info['id']))
        comb.append((nodes[i + 1].info['id'], nodes[i].info['id']))

    def check_gossip(n):
        seen = []
        channels = n.rpc.listchannels()['channels']
        for c in channels:
            seen.append((c['source'], c['destination']))
        missing = set(comb) - set(seen)
        logging.debug("Node {id} is missing channels {chans}".format(
            id=n.info['id'],
            chans=missing)
        )
        return len(missing) == 0

    for n in nodes:
        wait_for(lambda: check_gossip(n))


def test_gossip_query_channel_range(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.line_graph(4, fundchannel=False)
    genesis_blockhash = chainparams['chain_hash']

    # Make public channels on consecutive blocks
    l1.fundwallet(10**6)
    l2.fundwallet(10**6)

    num_tx = len(bitcoind.rpc.getrawmempool())
    # We want these one block apart.
    l1.rpc.fundchannel(l2.info['id'], 10**5)['tx']
    bitcoind.generate_block(wait_for_mempool=num_tx + 1)
    sync_blockheight(bitcoind, [l1, l2, l3, l4])
    l2.rpc.fundchannel(l3.info['id'], 10**5)['tx']
    # Get them both to gossip depth.
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4],
                             num_blocks=6,
                             wait_for_mempool=1)

    # Make sure l4 has received all the gossip.
    l4.daemon.wait_for_logs(['Received node_announcement for node ' + n.info['id'] for n in (l1, l2, l3)])

    scid12 = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['short_channel_id']
    scid23 = l3.rpc.listpeerchannels(l2.info['id'])['channels'][0]['short_channel_id']
    block12 = int(scid12.split('x')[0])
    block23 = int(scid23.split('x')[0])

    assert block23 == block12 + 1

    # Asks l4 for all channels, gets both.
    msgs = l4.query_gossip('query_channel_range',
                           chainparams['chain_hash'],
                           0, 1000000,
                           filters=['0109', '0107', '0012'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(1000000, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Does not include scid12
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block12,
                           filters=['0109', '0107', '0012'])
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block12, '08x') + '01'
                    # encoded_short_ids
                    '000100']

    # Does include scid12
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block12 + 1,
                           filters=['0109', '0107', '0012'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block12 + 1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Doesn't include scid23
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, block23,
                           filters=['0109', '0107', '0012'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(0, '08x') + format(block23, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Does include scid23
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block12, block23 - block12 + 1,
                           filters=['0109', '0107', '0012'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block12, '08x') + format(block23 - block12 + 1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Only includes scid23
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block23, 1,
                           filters=['0109', '0107', '0012'])
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block23, '08x') + format(1, '08x') + '01'
                    # encoded_short_ids
                    + format(len(encoded) // 2, '04x')
                    + encoded]

    # Past both
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           block23 + 1, 1000000,
                           filters=['0109', '0107', '0012'])
    # reply_channel_range == 264
    assert msgs == ['0108'
                    # blockhash
                    + genesis_blockhash
                    # first_blocknum, number_of_blocks, complete
                    + format(block23 + 1, '08x') + format(1000000, '08x') + '01'
                    # encoded_short_ids
                    + '000100']

    # Make l4 split reply into two (technically async)
    l4.rpc.dev_set_max_scids_encode_size(max=9)
    l4.daemon.wait_for_log('Set max_scids_encode_bytes to 9')

    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           0, 1000000,
                           filters=['0109', '0107', '0012'])
    # It should definitely have split
    l4.daemon.wait_for_log('reply_channel_range: splitting 0-1 of 2')

    start = 0
    scids = '00'
    for m in msgs:
        assert m.startswith('0108' + genesis_blockhash)
        this_start = int(m[4 + 64:4 + 64 + 8], base=16)
        num = int(m[4 + 64 + 8:4 + 64 + 8 + 8], base=16)
        # Pull off end of packet, assume it's uncompressed, and no TLVs!
        scids += m[4 + 64 + 8 + 8 + 2 + 4 + 2:]
        assert this_start == start
        start += num

    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    assert scids == encoded

    # Test overflow case doesn't split forever; should still only get 2 for this
    msgs = l4.query_gossip('query_channel_range',
                           genesis_blockhash,
                           1, 429496000,
                           filters=['0109', '0107', '0012'])
    assert len(msgs) == 2


# Long test involving 4 lightningd instances.
def test_report_routing_failure(node_factory, bitcoind):
    """Test routing failure and retrying of routing.
    """
    # The setup is as follows:
    #   l3-->l4
    #   ^   / |
    #   |  /  |
    #   | L   v
    #   l2<--l1
    #
    # l1 wants to pay to l4.
    # The shortest route is l1-l4, but l1 cannot
    # afford to pay to l1 because l4 has all the
    # funds.
    # This is a local failure.
    # The next shortest route is l1-l2-l4, but
    # l2 cannot afford to pay l4 for same reason.
    # This is a remote failure.
    # Finally the only possible path is
    # l1-l2-l3-l4.

    # Setup
    # Construct lightningd
    l1, l2, l3, l4 = node_factory.get_nodes(4)

    # Wire them up
    # The ordering below matters!
    # Particularly, l1 is payer and we will
    # wait for l1 to receive gossip for the
    # channel being made.
    channels = []
    for src, dst in [(l1, l2), (l2, l3), (l3, l4), (l4, l1), (l4, l2)]:
        src.rpc.connect(dst.info['id'], 'localhost', dst.port)
        print("src={}, dst={}".format(src.daemon.lightning_dir,
                                      dst.daemon.lightning_dir))
        c, _ = src.fundchannel(dst, 10**6)
        channels.append(c)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4])

    for c in channels:
        l1.wait_channel_active(c)

    # Test
    inv = l4.rpc.invoice(1234567, 'inv', 'for testing')['bolt11']
    l1.rpc.pay(inv)


def test_query_short_channel_id(node_factory, bitcoind, chainparams):
    l1, l2, l3, l4 = node_factory.get_nodes(4)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l2.rpc.connect(l3.info['id'], 'localhost', l3.port)
    chain_hash = chainparams['chain_hash']

    # Empty result tests.
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', '1x1x1', '2x2x2'],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()

    msgs = l1.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109', '0107', '0012'])

    # Should just get the WIRE_REPLY_SHORT_CHANNEL_IDS_END = 262
    # (with chainhash and completeflag = 1)
    assert len(msgs) == 1
    assert msgs[0] == '0106{}01'.format(chain_hash)

    # Make channels public.
    scid12, _ = l1.fundchannel(l2, 10**5)
    scid23, _ = l2.fundchannel(l3, 10**5)
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Attach node which won't spam us (since it's not their channel).
    l4.rpc.connect(l1.info['id'], 'localhost', l1.port)
    l4.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l4.rpc.connect(l3.info['id'], 'localhost', l3.port)

    # Make sure it sees all channels, then node announcements.
    wait_for(lambda: len(l4.rpc.listchannels()['channels']) == 4)
    wait_for(lambda: all('alias' in n for n in l4.rpc.listnodes()['nodes']))

    # This query should get channel announcements, channel updates, and node announcements.
    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    msgs = l4.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109', '0107', '0012'])

    assert len(msgs) == 6
    # 0x0100 = channel_announcement
    assert msgs[0].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[1].startswith('0102')
    assert msgs[2].startswith('0102')
    # 0x0101 = node_announcement
    assert msgs[3].startswith('0101')
    assert msgs[4].startswith('0101')
    assert msgs[5] == '0106{}01'.format(chain_hash)

    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00', scid12, scid23],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()
    msgs = l4.query_gossip('query_short_channel_ids',
                           chain_hash,
                           encoded,
                           filters=['0109', '0107', '0012'])

    # Technically, this order could be different, but this matches code.
    assert len(msgs) == 10
    # 0x0100 = channel_announcement
    assert msgs[0].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[1].startswith('0102')
    assert msgs[2].startswith('0102')
    # 0x0100 = channel_announcement
    assert msgs[3].startswith('0100')
    # 0x0102 = channel_update
    assert msgs[4].startswith('0102')
    assert msgs[5].startswith('0102')
    # 0x0101 = node_announcement
    assert msgs[6].startswith('0101')
    assert msgs[7].startswith('0101')
    assert msgs[8].startswith('0101')
    assert msgs[9] == '0106{}01'.format(chain_hash)


def test_gossip_addresses(node_factory, bitcoind):
    l1 = node_factory.get_node(options={
        'announce-addr': [
            '[::]:3',
            '[::]',
            '127.0.0.1:2',
            '127.0.0.1',
            'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion',
            '4acth47i6kxnvkewtm6q7ib2s3ufpo5sqbsnzjpbi7utijcltosqemad.onion:1234'
        ],
    })
    l2 = node_factory.get_node()
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    l1.fundchannel(l2, 100000)
    bitcoind.generate_block(6)
    l2.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l1.info['id']))

    nodes = l2.rpc.listnodes(l1.info['id'])['nodes']
    if TEST_NETWORK == 'regtest':
        default_port = 19846
    else:
        assert TEST_NETWORK == 'liquid-regtest'
        default_port = 20735

    assert len(nodes) == 1 and nodes[0]['addresses'] == [
        {'type': 'ipv4', 'address': '127.0.0.1', 'port': 2},
        {'type': 'ipv4', 'address': '127.0.0.1', 'port': default_port},
        {'type': 'ipv6', 'address': '::', 'port': 3},
        {'type': 'ipv6', 'address': '::', 'port': default_port},
        {'type': 'torv3', 'address': 'vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion', 'port': default_port},
        {'type': 'torv3', 'address': '4acth47i6kxnvkewtm6q7ib2s3ufpo5sqbsnzjpbi7utijcltosqemad.onion', 'port': 1234},
    ]


@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
@pytest.mark.openchannel('v2')
def test_gossip_lease_rates(node_factory, bitcoind):
    lease_opts = {'lease-fee-basis': 50,
                  'lease-fee-base-sat': '2000msat',
                  'channel-fee-max-base-msat': '500sat',
                  'channel-fee-max-proportional-thousandths': 200}
    l1, l2 = node_factory.get_nodes(2, opts=[lease_opts, {}])

    rates = l1.rpc.call('funderupdate')
    assert rates['channel_fee_max_base_msat'] == Millisatoshi('500000msat')
    assert rates['channel_fee_max_proportional_thousandths'] == 200
    assert rates['funding_weight'] == 666  # Default on regtest
    assert rates['lease_fee_base_msat'] == Millisatoshi('2000msat')
    assert rates['lease_fee_basis'] == 50

    rates = l2.rpc.call('funderupdate')
    assert 'channel_fee_max_base_msat' not in rates
    assert 'channel_fee_max_proportional_thousandths' not in rates
    assert 'funding_weight' not in rates
    assert 'lease_fee_base_msat' not in rates
    assert 'lease_fee_basis' not in rates

    # Open a channel, check that the node_announcements
    # include offer details, as expected
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    l1.fundchannel(l2, 10**6)

    # Don't have l2 reject channel_announcement as too far in future.
    sync_blockheight(bitcoind, [l1, l2])
    # Announce depth is ALWAYS 6 blocks
    bitcoind.generate_block(5)

    l2.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l1.info['id']))
    l1.daemon.wait_for_log('Received node_announcement for node {}'
                           .format(l2.info['id']))

    l2_nodeinfo = only_one(l1.rpc.listnodes(l2.info['id'])['nodes'])
    l1_nodeinfo = only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])

    assert 'option_will_fund' not in l2_nodeinfo
    rates = l1_nodeinfo['option_will_fund']
    assert rates['channel_fee_max_base_msat'] == Millisatoshi('500000msat')
    assert rates['channel_fee_max_proportional_thousandths'] == 200
    assert rates['funding_weight'] == 666  # Default on regtest
    assert rates['lease_fee_base_msat'] == Millisatoshi('2000msat')
    assert rates['lease_fee_basis'] == 50

    # Update the node announce (set new on l2, turn off l1)
    # (Turn off by setting everything to zero)
    l1.rpc.call('funderupdate', {'channel_fee_max_base_msat': '0msat',
                                 'channel_fee_max_proportional_thousandths': 0,
                                 'funding_weight': 0,
                                 'lease_fee_base_msat': '0msat',
                                 'lease_fee_basis': 0})
    l2.rpc.call('funderupdate', {'channel_fee_max_base_msat': '30000msat',
                                 'channel_fee_max_proportional_thousandths': 100,
                                 'lease_fee_base_msat': '400000msat',
                                 'lease_fee_basis': 20})

    l1.daemon.wait_for_log('Received node_announcement for node {}'.format(l2.info['id']))
    l2.daemon.wait_for_log('Received node_announcement for node {}'.format(l1.info['id']))

    l2_nodeinfo = only_one(l1.rpc.listnodes(l2.info['id'])['nodes'])
    l1_nodeinfo = only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])

    assert 'option_will_fund' not in l1_nodeinfo
    rates = l2_nodeinfo['option_will_fund']
    assert rates['channel_fee_max_base_msat'] == Millisatoshi('30000msat')
    assert rates['channel_fee_max_proportional_thousandths'] == 100
    assert rates['funding_weight'] == 666  # Default on regtest
    assert rates['lease_fee_base_msat'] == Millisatoshi('400000msat')
    assert rates['lease_fee_basis'] == 20


def test_gossip_store_load(node_factory):
    """Make sure we can read canned gossip store"""
    l1 = node_factory.get_node(start=False)
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("0c"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "0000008a"  # len
                                  "0c6aca0e"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440100009000000000000003e8000003e8000000010000000000FFFFFF"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log('Read 1/1/1/0 cannounce/cupdate/nannounce/delete from store in 800 bytes, now 778 bytes'))
    assert not l1.daemon.is_in_log('gossip_store.*truncating')


def test_gossip_store_v10_upgrade(node_factory):
    """We remove a channel_update without an htlc_maximum_msat"""
    l1 = node_factory.get_node(start=False)
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("0a"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "00000082"  # len
                                  "fd421aeb"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440000009000000000000003e8000003e800000001"))

    l1.start()
    # Channel "exists" but doesn't show in listchannels, as it has no updates.
    assert l1.rpc.listchannels() == {'channels': []}
    assert only_one(l1.rpc.listnodes('021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c675')['nodes'])
    assert only_one(l1.rpc.listnodes('03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d2')['nodes'])
    assert len(l1.rpc.listnodes()['nodes']) == 2


def test_gossip_store_load_announce_before_update(node_factory):
    """Make sure we can read canned gossip store with node_announce before update.  This happens when a channel_update gets replaced, leaving node_announce before it"""
    l1 = node_factory.get_node(start=False)
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("0c"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "8000008a"  # len (DELETED)
                                  "ca01ed56"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  # Note - msgflags set and htlc_max added by hand, so signature doesn't match (gossipd ignores)
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440100009000000000000003e8000003e8000000010000000000FFFFFF"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"
                                  "0000008a"  # len
                                  "0c6aca0e"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0102"      # WIRE_CHANNEL_UPDATE
                                  # Note - msgflags set and htlc_max added by hand, so signature doesn't match (gossipd ignores)
                                  "1ea7c2eadf8a29eb8690511a519b5656e29aa0a853771c4e38e65c5abf43d907295a915e69e451f4c7a0c3dc13dd943cfbe3ae88c0b96667cd7d58955dbfedcf43497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b500015b8d9b440100009000000000000003e8000003e8000000010000000000FFFFFF"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log('Read 1/1/1/1 cannounce/cupdate/nannounce/delete from store in 950 bytes, now 778 bytes'))
    assert not l1.daemon.is_in_log('gossip_store.*truncating')


def test_gossip_store_load_amount_truncated(node_factory):
    """Make sure we can read canned gossip store with truncated amount"""
    l1 = node_factory.get_node(start=False, broken_log=r'gossip_store: channel_announcement without amount \(offset 1\). Moving to gossip_store.corrupt and truncating|plugin-cln-renepay:.*unable to fetch channel capacity')
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("0c"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"))

    l1.start()
    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log(r'\*\*BROKEN\*\* gossipd: gossip_store: channel_announcement without amount \(offset 1\). Moving to gossip_store.corrupt and truncating'))
    wait_for(lambda: l1.daemon.is_in_log(r'gossip_store: Read 0/0/0/0 cannounce/cupdate/nannounce/delete from store in 467 bytes, now 1 bytes \(populated=false\)'))
    assert os.path.exists(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.corrupt'))


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
def test_node_reannounce(node_factory, bitcoind, chainparams):
    "Test that we reannounce a node when parameters change"
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True,
                                              'log-level': 'io'})
    bitcoind.generate_block(5)
    genesis_blockhash = chainparams['chain_hash']

    # Wait for node_announcement for l1.
    l2.daemon.wait_for_log(r'\[IN\] 0101.*{}'.format(l1.info['id']))
    # Wait for it to process it.
    wait_for(lambda: l2.rpc.listnodes(l1.info['id'])['nodes'] != [])
    wait_for(lambda: 'alias' in only_one(l2.rpc.listnodes(l1.info['id'])['nodes']))
    assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'].startswith('JUNIORBEAM')

    # Make sure it gets features correct.
    assert only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['features'] == expected_node_features()

    l1.stop()
    l1.daemon.opts['alias'] = 'SENIORBEAM'
    # It won't update within 5 seconds, so sleep.
    time.sleep(5)
    l1.start()

    wait_for(lambda: only_one(l2.rpc.listnodes(l1.info['id'])['nodes'])['alias'] == 'SENIORBEAM')

    # Get node_announcements.
    msgs = l1.query_gossip('gossip_timestamp_filter',
                           genesis_blockhash,
                           '0', '0xFFFFFFFF',
                           # Filter out gossip_timestamp_filter,
                           # channel_announcement and channel_updates.
                           # And pings.
                           filters=['0109', '0107', '0102', '0100', '0012'])

    # May send its own announcement *twice*, since it always spams us.
    msgs = list(set(msgs))
    assert len(msgs) == 2
    assert (bytes("SENIORBEAM", encoding="utf8").hex() in msgs[0]
            or bytes("SENIORBEAM", encoding="utf8").hex() in msgs[1])

    # Restart should re-xmit exact same update on reconnect!
    l1.restart()

    msgs2 = l1.query_gossip('gossip_timestamp_filter',
                            genesis_blockhash,
                            '0', '0xFFFFFFFF',
                            # Filter out gossip_timestamp_filter,
                            # channel_announcement and channel_updates.
                            # And pings.
                            filters=['0109', '0107', '0102', '0100', '0012'])

    # May send its own announcement *twice*, since it always spams us.
    assert set(msgs) == set(msgs2)
    # Won't have queued up another one, either.
    assert not l1.daemon.is_in_log('node_announcement: delaying')

    # Try updating the lease rates ad
    ad = l1.rpc.call('setleaserates',
                     {'lease_fee_base_msat': '1000sat',
                      'lease_fee_basis': 20,
                      'funding_weight': 150,
                      'channel_fee_max_base_msat': '2000msat',
                      'channel_fee_max_proportional_thousandths': 22})

    assert ad['lease_fee_base_msat'] == Millisatoshi('1000000msat')
    assert ad['lease_fee_basis'] == 20
    assert ad['funding_weight'] == 150
    assert ad['channel_fee_max_base_msat'] == Millisatoshi('2000msat')
    assert ad['channel_fee_max_proportional_thousandths'] == 22

    # May send its own announcement *twice*, since it always spams us.
    msgs2 = l1.query_gossip('gossip_timestamp_filter',
                            genesis_blockhash,
                            '0', '0xFFFFFFFF',
                            # Filter out gossip_timestamp_filter,
                            # channel_announcement and channel_updates.
                            # And pings.
                            filters=['0109', '0107', '0102', '0100', '0012'])
    assert set(msgs) != set(msgs2)


def test_gossipwith(node_factory):
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    out = subprocess.run(['devtools/gossipwith',
                          '--all-gossip',
                          '--network={}'.format(TEST_NETWORK),
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port)],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

    msgs = set()
    while len(out):
        l, t = struct.unpack('>HH', out[0:4])
        msg = out[2:2 + l]
        out = out[2 + l:]

        # Ignore pings, gossip_timestamp_filter, query_channel_range
        if t in (18, 263, 265):
            continue
        # channel_announcement node_announcement or channel_update
        assert t == 256 or t == 257 or t == 258
        msgs.add(msg)

    # one channel announcement, two channel_updates, two node announcements.
    # due to initial blast, we can have duplicates!
    assert len(msgs) == 5


def test_gossip_notices_close(node_factory, bitcoind):
    # We want IO logging so we can replay a channel_announce to l1;
    # We also *really* do feed it bad gossip!
    l1, l2, l3 = node_factory.get_nodes(3, opts=[{'log-level': 'io',
                                                  'allow_bad_gossip': True},
                                                 {},
                                                 {}])
    node_factory.join_nodes([l2, l3])
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Make sure l1 learns about channel and nodes.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: ['alias' in n for n in l1.rpc.listnodes()['nodes']] == [True, True])
    l1.rpc.disconnect(l2.info['id'])

    # Grab channel_announcement from io logs (ends in ')
    channel_announcement = l1.daemon.is_in_log(r'\[IN\] 0100').split(' ')[-1][:-1]
    channel_update = l1.daemon.is_in_log(r'\[IN\] 0102').split(' ')[-1][:-1]
    node_announcement = l1.daemon.is_in_log(r'\[IN\] 0101').split(' ')[-1][:-1]

    txid = l2.rpc.close(l3.info['id'])['txid']
    wait_for(lambda: l2.rpc.listpeerchannels(l3.info['id'])['channels'][0]['state'] == 'CLOSINGD_COMPLETE')
    bitcoind.generate_block(13, txid)

    wait_for(lambda: l1.rpc.listchannels()['channels'] == [])
    wait_for(lambda: l1.rpc.listnodes()['nodes'] == [])

    subprocess.run(['devtools/gossipwith',
                    '--network={}'.format(TEST_NETWORK),
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    channel_announcement,
                    channel_update,
                    node_announcement],
                   timeout=TIMEOUT)

    # l1 should reject it.
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])

    l1.stop()
    l1.start()
    assert(l1.rpc.listchannels()['channels'] == [])
    assert(l1.rpc.listnodes()['nodes'] == [])


def test_getroute_exclude_duplicate(node_factory):
    """Test that accidentally duplicating the same channel or same node
    in the exclude list will not have permanent effects.
    """

    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    # Starting route
    route = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    # l1 id is > l2 id, so 1 means l1->l2
    chan_l1l2 = route[0]['channel'] + '/1'

    # This should fail to find a route as the only viable channel
    # is excluded, and worse, is excluded twice.
    with pytest.raises(RpcError):
        l1.rpc.getroute(l2.info['id'], 1, 1, exclude=[chan_l1l2, chan_l1l2])

    # This should still succeed since nothing is excluded anymore
    # and in particular should return the exact same route as
    # earlier.
    route2 = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    assert route == route2

    # This should also fail to find a route as the only viable channel
    # is excluded, and worse, is excluded twice.
    with pytest.raises(RpcError):
        l1.rpc.getroute(l2.info['id'], 1, 1, exclude=[l2.info['id'], l2.info['id']])

    # This should still succeed since nothing is excluded anymore
    # and in particular should return the exact same route as
    # earlier.
    route3 = l1.rpc.getroute(l2.info['id'], 1, 1)['route']
    assert route == route3


def test_getroute_exclude(node_factory, bitcoind):
    """Test getroute's exclude argument"""
    l1, l2, l3, l4, l5 = node_factory.get_nodes(5)
    node_factory.join_nodes([l1, l2, l3, l4], wait_for_announce=True)

    # This should work
    route = l1.rpc.getroute(l4.info['id'], 1, 1)['route']

    # l1 id is > l2 id, so 1 means l1->l2
    chan_l1l2 = route[0]['channel'] + '/1'
    chan_l2l1 = route[0]['channel'] + '/0'

    # This should not
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l1l2])

    # This should also not
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l2.info['id']])

    # Blocking the wrong way should be fine.
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l1])

    # Now, create an alternate (better) route.
    l2.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid, _ = l2.fundchannel(l4, 1000000, wait_for_active=False)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])

    # We don't wait above, because we care about it hitting l1.
    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scid),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid)])

    # l3 id is > l2 id, so 1 means l3->l2
    # chan_l3l2 = route[1]['channel'] + '/1'
    chan_l2l3 = route[1]['channel'] + '/0'

    # l4 is > l2
    # chan_l4l2 = scid + '/1'
    chan_l2l4 = scid + '/0'

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3])

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l4])

    # This works
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id']])

    # This doesn't
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3, chan_l2l4])

    # This doesn't
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], chan_l2l4])

    l1.rpc.connect(l5.info['id'], 'localhost', l5.port)
    scid15, _ = l1.fundchannel(l5, 1000000, wait_for_active=False)
    l5.rpc.connect(l4.info['id'], 'localhost', l4.port)
    scid54, _ = l5.fundchannel(l4, 1000000, wait_for_active=False)
    mine_funding_to_announce(bitcoind, [l1, l2, l3, l4, l5])

    # We don't wait above, because we care about it hitting l1.
    l1.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                             .format(scid15),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid15),
                             r'update for channel {}/0 now ACTIVE'
                             .format(scid54),
                             r'update for channel {}/1 now ACTIVE'
                             .format(scid54)])

    # This works now
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], chan_l2l4])

    # This works now
    l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], l5.info['id']])

    # This doesn't work
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[l3.info['id'], l5.info['id'], chan_l2l4])

    # This doesn't work
    with pytest.raises(RpcError):
        l1.rpc.getroute(l4.info['id'], 1, 1, exclude=[chan_l2l3, l5.info['id'], chan_l2l4])


def setup_gossip_store_test(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3, wait_for_announce=True)

    # Now, replace the one channel_update, so it's past the node announcements.
    l2.rpc.setchannel(l3.info['id'], 20, 1000)
    l3.rpc.setchannel(l2.info['id'], 21, 1001)

    # Wait for it to hit l1's gossip store.
    wait_for(lambda: sorted([c['fee_per_millionth'] for c in l1.rpc.listchannels()['channels']]) == [10, 10, 1000, 1001])

    # Records in l2's store now looks (something) like:
    #  channel_announcement (scid12)
    #  channel_amount
    #  channel_update (scid12/0)
    #  channel_update (scid12/1)
    #  node_announcement (l1)
    #  node_announcement (l2)
    #  channel_announcement (scid23)
    #  channel_amount
    #    DELETED: channel_update (scid23/0)
    #    DELETED: channel_update (scid23/1)
    #  node_announcement
    #  channel_update (scid23/0)
    #  channel_update (scid23/1)
    return l2


def test_gossip_store_compact_noappend(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    # It should truncate this, not leave junk!
    with open(os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.tmp'), 'wb') as f:
        f.write(bytearray.fromhex("07deadbeef"))

    l2.restart()
    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))
    assert not l2.daemon.is_in_log('gossip_store:.*truncate')


def test_gossip_store_load_complex(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    l2.restart()

    wait_for(lambda: l2.daemon.is_in_log('gossip_store: Read '))


def test_gossip_store_load_no_channel_update(node_factory):
    """Make sure we can read truncated gossip store with a channel_announcement and no channel_update"""
    l1 = node_factory.get_node(start=False)

    # A channel announcement with no channel_update.
    with open(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'), 'wb') as f:
        f.write(bytearray.fromhex("0d"        # GOSSIP_STORE_VERSION
                                  "000001b0"  # len
                                  "fea676e8"  # csum
                                  "5b8d9b44"  # timestamp
                                  "0100"      # WIRE_CHANNEL_ANNOUNCEMENT
                                  "bb8d7b6998cca3c2b3ce12a6bd73a8872c808bb48de2a30c5ad9cdf835905d1e27505755087e675fb517bbac6beb227629b694ea68f49d357458327138978ebfd7adfde1c69d0d2f497154256f6d5567a5cf2317c589e0046c0cc2b3e986cf9b6d3b44742bd57bce32d72cd1180a7f657795976130b20508b239976d3d4cdc4d0d6e6fbb9ab6471f664a662972e406f519eab8bce87a8c0365646df5acbc04c91540b4c7c518cec680a4a6af14dae1aca0fd5525220f7f0e96fcd2adef3c803ac9427fe71034b55a50536638820ef21903d09ccddd38396675b598587fa886ca711415c813fc6d69f46552b9a0a539c18f265debd0e2e286980a118ba349c216000043497fd7f826957108f4a30fd9cec3aeba79972084e90ead01ea33090000000013a63c0000b50001021bf3de4e84e3d52f9a3e36fbdcd2c4e8dbf203b9ce4fc07c2f03be6c21d0c67503f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d203801fd8ab98032f11cc9e4916dd940417082727077609d5c7f8cc6e9a3ad25dd102517164b97ab46cee3826160841a36c46a2b7b9c74da37bdc070ed41ba172033a"
                                  "0000000a"  # len
                                  "99dc98b4"  # csum
                                  "00000000"  # timestamp
                                  "1005"      # WIRE_GOSSIP_STORE_CHANNEL_AMOUNT
                                  "0000000001000000"
                                  "00000095"  # len
                                  "f036515e"  # csum
                                  "5aab817c"  # timestamp
                                  "0101"      # WIRE_NODE_ANNOUNCEMENT
                                  "cf5d870bc7ecabcb7cd16898ef66891e5f0c6c5851bd85b670f03d325bc44d7544d367cd852e18ec03f7f4ff369b06860a3b12b07b29f36fb318ca11348bf8ec00005aab817c03f113414ebdc6c1fb0f33c99cd5a1d09dd79e7fdf2468cf1fe1af6674361695d23974b250757a7a6c6549544300000000000000000000000000000000000000000000000007010566933e2607"))

    l1.start()

    # May preceed the Started msg waited for in 'start'.
    wait_for(lambda: l1.daemon.is_in_log('Read 1/0/1/0 cannounce/cupdate/nannounce/delete from store in 650 bytes, now 628 bytes'))
    assert not os.path.exists(os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store.corrupt'))


def test_gossip_store_compact_on_load(node_factory, bitcoind):
    l2 = setup_gossip_store_test(node_factory, bitcoind)

    gs_path = os.path.join(l2.daemon.lightning_dir, TEST_NETWORK, 'gossip_store')
    gs = subprocess.run(['devtools/dump-gossipstore', '--print-deleted', gs_path],
                        check=True, timeout=TIMEOUT, stdout=subprocess.PIPE)
    print(gs.stdout.decode())

    l2.restart()

    # These appear before we're fully started, so will already in log:
    assert l2.daemon.is_in_log('gossip_store: Read 2/4/3/2 cannounce/cupdate/nannounce/delete from store')


def test_gossip_announce_invalid_block(node_factory, bitcoind):
    """bitcoind lags and we might get an announcement for a block we don't have.

    """
    # Need to slow down the poll interval so the announcement preceeds the
    # blockchain catchup, otherwise we won't call `getfilteredblock`.
    opts = {'dev-bitcoind-poll': TIMEOUT // 2}

    l1 = node_factory.get_node(options=opts)
    bitcoind.generate_block(1)
    assert bitcoind.rpc.getblockchaininfo()['blocks'] == 102

    # Test gossip for an unknown block.
    subprocess.run(['devtools/gossipwith',
                    '--network={}'.format(TEST_NETWORK),
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    # short_channel_id=103x1x1
                    '01008d9f3d16dbdd985c099b74a3c9a74ccefd52a6d2bd597a553ce9a4c7fac3bfaa7f93031932617d38384cc79533730c9ce875b02643893cacaf51f503b5745fc3aef7261784ce6b50bff6fc947466508b7357d20a7c2929cc5ec3ae649994308527b2cbe1da66038e3bfa4825b074237708b455a4137bdb541cf2a7e6395a288aba15c23511baaae722fdb515910e2b42581f9c98a1f840a9f71897b4ad6f9e2d59e1ebeaf334cf29617633d35bcf6e0056ca0be60d7c002337bbb089b1ab52397f734bcdb2e418db43d1f192195b56e60eefbf82acf043d6068a682e064db23848b4badb20d05594726ec5b59267f4397b093747c23059b397b0c5620c4ab37a000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010001022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d029053521d6ea7a52cdd55f733d0fb2d077c0373b0053b5b810d927244061b757302d6063d022691b2490ab454dee73a57c6ff5d308352b461ece69f3c284f2c2412'],
                   check=True, timeout=TIMEOUT)

    # Make sure it's OK once it's caught up.
    sync_blockheight(bitcoind, [l1])


def test_gossip_announce_unknown_block(node_factory, bitcoind):
    """Don't backfill the future!

    If we get a channel_announcement that is for a block height that is above
    our sync height we should not store the filteredblock in the blocks table,
    otherwise we end up with a duplicate when we finally catch up with the
    blockchain.

    """
    # Need to slow down the poll interval so the announcement preceeds the
    # blockchain catchup, otherwise we won't call `getfilteredblock`.
    opts = {'dev-bitcoind-poll': TIMEOUT // 2}

    l1 = node_factory.get_node(options=opts)

    bitcoind.generate_block(2)
    assert bitcoind.rpc.getblockchaininfo()['blocks'] == 103

    # Test gossip for unknown block.
    subprocess.run(['devtools/gossipwith',
                    '--network={}'.format(TEST_NETWORK),
                    '--max-messages=0',
                    '{}@localhost:{}'.format(l1.info['id'], l1.port),
                    # short_channel_id=103x1x1
                    '01008d9f3d16dbdd985c099b74a3c9a74ccefd52a6d2bd597a553ce9a4c7fac3bfaa7f93031932617d38384cc79533730c9ce875b02643893cacaf51f503b5745fc3aef7261784ce6b50bff6fc947466508b7357d20a7c2929cc5ec3ae649994308527b2cbe1da66038e3bfa4825b074237708b455a4137bdb541cf2a7e6395a288aba15c23511baaae722fdb515910e2b42581f9c98a1f840a9f71897b4ad6f9e2d59e1ebeaf334cf29617633d35bcf6e0056ca0be60d7c002337bbb089b1ab52397f734bcdb2e418db43d1f192195b56e60eefbf82acf043d6068a682e064db23848b4badb20d05594726ec5b59267f4397b093747c23059b397b0c5620c4ab37a000006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f0000670000010001022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d029053521d6ea7a52cdd55f733d0fb2d077c0373b0053b5b810d927244061b757302d6063d022691b2490ab454dee73a57c6ff5d308352b461ece69f3c284f2c2412'],
                   check=True, timeout=TIMEOUT)

    # Make sure it's OK once it's caught up.
    sync_blockheight(bitcoind, [l1])


def test_gossip_no_backtalk(node_factory):
    # l3 connects, gets gossip, but should *not* play it back.
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{}, {}, {'log-level': 'io'}])
    node_factory.join_nodes([l1, l2], wait_for_announce=True)

    l3.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Will get channel_announce, then two channel_update and two node_announcement
    l3.daemon.wait_for_logs([r'\[IN\] 0100',
                             r'\[IN\] 0102', r'\[IN\] 0102',
                             r'\[IN\] 0101', r'\[IN\] 0101'])

    # With --developer, this is long enough for gossip flush.
    time.sleep(2)
    assert not l3.daemon.is_in_log(r'\[OUT\] 0100')


@unittest.skipIf(
    TEST_NETWORK != 'regtest',
    "Channel announcement contains genesis hash, receiving node discards on mismatch"
)
def check_socket(ip_addr, port):
    result = True
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # let's also check for fatal and try it ;-)
    try:
        result = sock.connect_ex((ip_addr, port))
        sock.close()
    except Exception:
        return False

    return not result


def test_static_tor_onions(node_factory):
    """First basic tests ;-)

    Assume that tor is configured and just test
    if we see the right onion address for our blob
    """
    # please define your values
    torip = '127.0.0.1'
    torips = '127.0.0.1:9051'
    torport = 9050
    torserviceport = 9051

    if not check_socket(format(torip), torserviceport):
        return

    if not check_socket(format(torip), torport):
        return

    portA = node_factory.get_unused_port()
    l1 = node_factory.get_node(may_fail=True, options={
        'bind-addr': '127.0.0.1:{}'.format(portA),
        'addr': ['statictor:{}'.format(torips)]
    })
    portB = node_factory.get_unused_port()
    l2 = node_factory.get_node(may_fail=True, options={
        'bind-addr': '127.0.0.1:{}'.format(portB),
        'addr': ['statictor:{}/torblob=11234567890123456789012345678901/torport={}'.format(torips, 9736)]
    })

    assert l1.daemon.is_in_log('127.0.0.1:{}'.format(l1.port))
    # Did not specify torport, so it's the default.
    assert l1.daemon.is_in_log('.onion:{}'.format(default_ln_port(l1.info["network"])))
    assert l2.daemon.is_in_log('x2y4zvh4fn5q3eouuh7nxnc7zeawrqoutljrup2xjtiyxgx3emgkemad.onion:{},127.0.0.1:{}'.format(9736, l2.port))


def test_tor_port_onions(node_factory):
    """First basic tests for torport ;-)

    Assume that tor is configured and just test
    if we see the right onion address for our blob
    """
    # please define your values
    torip = '127.0.0.1'
    torips = '127.0.0.1:9051'
    torport = 9050
    torserviceport = 9051

    if not check_socket(torip, torserviceport):
        return

    if not check_socket(torip, torport):
        return

    portA = node_factory.get_unused_port()
    l1 = node_factory.get_node(may_fail=True, options={'bind-addr': '127.0.0.1:{}'.format(portA), 'addr': ['statictor:{}/torport=45321'.format(torips)]})
    portB = node_factory.get_unused_port()
    l2 = node_factory.get_node(may_fail=True, options={'bind-addr': '127.0.0.1:{}'.format(portB), 'addr': ['statictor:{}/torport=45321/torblob=11234567890123456789012345678901'.format(torips)]})

    assert l1.daemon.is_in_log('45321,127.0.0.1:{}'.format(l1.port))
    assert l2.daemon.is_in_log('x2y4zvh4fn5q3eouuh7nxnc7zeawrqoutljrup2xjtiyxgx3emgkemad.onion:45321,127.0.0.1:{}'.format(l2.port))


def test_routetool(node_factory):
    """Test that route tool can see published channels"""
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    subprocess.run(['devtools/route',
                    os.path.join(l1.daemon.lightning_dir,
                                 TEST_NETWORK,
                                 'gossip_store'),
                    l1.info['id'],
                    l2.info['id']],
                   check=True, timeout=TIMEOUT)


def test_addgossip(node_factory):
    l1, l2 = node_factory.line_graph(2, fundchannel=True, wait_for_announce=True,
                                     opts={'log-level': 'io'})

    # We should get two node_announcements, one channel_announcement, and two
    # channel_update.
    l3 = node_factory.get_node()

    # 0x0100 = channel_announcement
    # 0x0102 = channel_update
    # 0x0101 = node_announcement
    l1.daemon.logsearch_start = 0
    ann = l1.daemon.wait_for_log(r"\[(OUT|IN)\] 0100.*")  # Either direction will suppress the other.

    l2.daemon.logsearch_start = 0
    l2.daemon.wait_for_log(r"\[(OUT|IN)\] 0100.*")

    # Be sure not to get the *private* updates!
    upd1 = l1.daemon.is_in_log(r"\[OUT\] 0102.*", start=l1.daemon.logsearch_start)
    upd2 = l2.daemon.is_in_log(r"\[OUT\] 0102.*", start=l2.daemon.logsearch_start)

    nann1 = l1.daemon.is_in_log(r"\[OUT\] 0101.*")
    nann2 = l2.daemon.is_in_log(r"\[OUT\] 0101.*")

    # Feed them to l3 (Each one starts with PREFIX TIMESTAMP chanid-xxx: [OUT] ...)
    l3.rpc.addgossip(ann.split()[4])

    l3.rpc.addgossip(upd1.split()[4])
    l3.rpc.addgossip(upd2.split()[4])
    l3.rpc.addgossip(nann1.split()[4])
    l3.rpc.addgossip(nann2.split()[4])

    # In this case, it can actually have to wait, since it does scid lookup.
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l3.rpc.listnodes()['nodes']) == 2)

    # Now corrupt an update
    badupdate = upd1.split()[4]
    if badupdate.endswith('f'):
        badupdate = badupdate[:-1] + 'e'
    else:
        badupdate = badupdate[:-1] + 'f'

    with pytest.raises(RpcError, match='Bad signature'):
        l3.rpc.addgossip(badupdate)


def test_topology_leak(node_factory, bitcoind):
    l1, l2, l3 = node_factory.line_graph(3)

    l1.rpc.listchannels()
    mine_funding_to_announce(bitcoind, [l1, l2, l3])

    # Wait until l1 sees all the channels.
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 4)

    # Close and wait for gossip to catchup.
    txid = l2.rpc.close(l3.info['id'])['txid']
    bitcoind.generate_block(13, txid)

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)


def test_parms_listforwards(node_factory):
    """
    Simple test to ensure that the order of the listforwards
    is correct as describe in the documentation.

    This test is written by a issue report in the IR channel,
    it is simple and not useful, but it is good to have to avoid
    simile errors in the future.
    """
    l1, l2 = node_factory.line_graph(2)

    l2.stop()
    l2.daemon.opts['allow-deprecated-apis'] = True
    l2.start()

    forwards_new = l1.rpc.listforwards("settled")["forwards"]
    forwards_dep = l2.rpc.call("listforwards", {"in_channel": "0x1x2", "out_channel": "0x2x3", "status": "settled"})["forwards"]

    assert len(forwards_new) == 0
    assert len(forwards_dep) == 0


def test_close_12_block_delay(node_factory, bitcoind):
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True)

    # Close l1-l2
    txid = l1.rpc.close(l2.info['id'])['txid']
    bitcoind.generate_block(1, txid)

    # But l4 doesn't believe it immediately.
    l4.daemon.wait_for_log("channel .* closing soon due to the funding outpoint being spent")

    # Close l2-l3 one block later.
    txid = l2.rpc.close(l3.info['id'])['txid']
    bitcoind.generate_block(1, txid)
    l4.daemon.wait_for_log("channel .* closing soon due to the funding outpoint being spent")

    # BOLT #7:
    #   - once its funding output has been spent OR reorganized out:
    #    - SHOULD forget a channel after a 12-block delay.

    # That implies 12 blocks *after* spending, i.e. 13 blocks deep!

    # 12 blocks deep, l4 still sees it
    bitcoind.generate_block(10)
    sync_blockheight(bitcoind, [l4])
    assert len(l4.rpc.listchannels(source=l1.info['id'])['channels']) == 1

    # 13 blocks deep does it.
    bitcoind.generate_block(1)
    wait_for(lambda: l4.rpc.listchannels(source=l1.info['id'])['channels'] == [])

    # Other channel still visible.
    assert len(l4.rpc.listchannels(source=l2.info['id'])['channels']) == 1

    # Restart: it remembers channel is dying.
    l4.restart()

    # One more block, it's forgotten too.
    bitcoind.generate_block(1)
    wait_for(lambda: l4.rpc.listchannels(source=l2.info['id'])['channels'] == [])


def test_gossip_not_dying(node_factory, bitcoind):
    l1 = node_factory.get_node()
    l2, l3 = node_factory.line_graph(2, wait_for_announce=True)

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)
    # Wait until it sees all the updates, node announcments.
    wait_for(lambda: len([n for n in l1.rpc.listnodes()['nodes'] if 'alias' in n])
             + len(l1.rpc.listchannels()['channels']) == 4)

    def get_gossip(node):
        out = subprocess.run(['devtools/gossipwith',
                              '--network={}'.format(TEST_NETWORK),
                              '--all-gossip',
                              '--timeout-after=2',
                              '{}@localhost:{}'.format(node.info['id'], node.port)],
                             check=True,
                             timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

        msgs = []
        while len(out):
            l, t = struct.unpack('>HH', out[0:4])
            msg = out[2:2 + l]
            out = out[2 + l:]

            # Ignore pings, gossip_timestamp_filter, query_channel_range
            if t in (18, 263, 265):
                continue
            # channel_announcement node_announcement or channel_update
            assert t == 256 or t == 257 or t == 258
            msgs.append(msg)

        return msgs

    assert len(get_gossip(l1)) == 5

    # Close l2->l3, mine block.
    l2.rpc.close(l3.info['id'])
    bitcoind.generate_block(1, wait_for_mempool=1)

    l1.daemon.wait_for_log("closing soon due to the funding outpoint being spent")

    # We won't gossip the dead channel any more, nor the node_announcements.  But connectd is not explicitly synced, so wait for "a bit".
    time.sleep(1)
    assert get_gossip(l1) == []


def test_dump_own_gossip(node_factory):
    """We *should* send all self-related gossip unsolicited, if we have any"""
    l1, l2 = node_factory.line_graph(2, wait_for_announce=True)

    # Make sure l1 has updates in both directions, and node_announcements
    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l1.rpc.listnodes()['nodes']) == 2)

    # We should get channel_announcement, channel_update, node_announcement.
    # (Plus random pings, timestamp_filter)
    out = subprocess.run(['devtools/gossipwith',
                          '--no-gossip',
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '--network={}'.format(TEST_NETWORK),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port)],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

    # In theory, we could do the node_announcement any time after channel_announcement, but we don't.
    expect = [256,  # channel_announcement
              258,  # channel_update
              258,  # channel_update
              257]  # node_announcement

    while len(out):
        l, t = struct.unpack('>HH', out[0:4])
        out = out[2 + l:]

        # Ignore pings, timestamp_filter, query_channel_range
        if t in (18, 263, 265):
            continue

        assert t == expect[0]
        expect = expect[1:]

    # We should get exactly what we expected.
    assert expect == []


def test_listchannels_deprecated_local(node_factory, bitcoind):
    """Test listchannels shows local/private channels only in deprecated mode"""
    l1, l2, l3 = node_factory.get_nodes(3,
                                        opts=[{}, {'allow-deprecated-apis': True}, {}])
    # This will be in block 103
    node_factory.join_nodes([l1, l2], wait_for_announce=False)
    l1l2 = first_scid(l1, l2)
    # This will be in block 104
    node_factory.join_nodes([l2, l3], wait_for_announce=False)
    l2l3 = first_scid(l2, l3)

    # Non-deprecated nodes say no.
    assert l1.rpc.listchannels() == {'channels': []}
    assert l3.rpc.listchannels() == {'channels': []}
    # Deprecated API lists both sides of local channels:

    vals = [(c['active'], c['public'], c['short_channel_id']) for c in l2.rpc.listchannels()['channels']]
    # Either order
    assert vals == [(True, False, l1l2)] * 2 + [(True, False, l2l3)] * 2 or vals == [(True, False, l2l3)] * 2 + [(True, False, l1l2)] * 2

    # Mine l1-l2 channel so it's public.
    bitcoind.generate_block(4)
    sync_blockheight(bitcoind, [l1, l2, l3])

    wait_for(lambda: len(l1.rpc.listchannels()['channels']) == 2)
    wait_for(lambda: len(l3.rpc.listchannels()['channels']) == 2)

    # l2 shows public one correctly, and private one correctly
    # Either order
    vals = [(c['active'], c['public'], c['short_channel_id']) for c in l2.rpc.listchannels()['channels']]
    assert vals == [(True, True, l1l2)] * 2 + [(True, False, l2l3)] * 2 or vals == [(True, False, l2l3)] * 2 + [(True, True, l1l2)] * 2


def test_gossip_throttle(node_factory, bitcoind, chainparams):
    """Make some gossip, test it gets throttled"""
    l1, l2, l3, l4 = node_factory.line_graph(4, wait_for_announce=True,
                                             opts=[{}, {}, {}, {'dev-throttle-gossip': None}])

    # We expect: self-advertizement (3 messages for l1 and l4) plus
    # 4 node announcements, 3 channel announcements and 6 channel updates.
    # We also expect it to send a timestamp filter message.
    # (We won't take long enough to get a ping!)
    expected = 4 + 4 + 3 + 6 + 1

    # l1 is unlimited
    start_fast = time.time()
    out1 = subprocess.run(['devtools/gossipwith',
                           '--all-gossip',
                           '--hex',
                           '--network={}'.format(TEST_NETWORK),
                           '--max-messages={}'.format(expected),
                           '{}@localhost:{}'.format(l1.info['id'], l1.port)],
                          check=True,
                          timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    time_fast = time.time() - start_fast
    assert time_fast < 2
    # Remove timestamp filter, since timestamp will change!
    out1 = [m for m in out1 if not m.startswith(b'0109')]

    # l4 is throttled
    start_slow = time.time()
    out2 = subprocess.run(['devtools/gossipwith',
                           '--all-gossip',
                           '--hex',
                           '--network={}'.format(TEST_NETWORK),
                           '--max-messages={}'.format(expected),
                           '{}@localhost:{}'.format(l4.info['id'], l4.port)],
                          check=True,
                          timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    time_slow = time.time() - start_slow
    assert time_slow > 3

    # Remove timestamp filter, since timestamp will change!
    out2 = [m for m in out2 if not m.startswith(b'0109')]

    # Contents should be identical (once uniquified, since each
    # doubles-up on its own gossip)
    assert set(out1) == set(out2)

    encoded = subprocess.run(['devtools/mkencoded', '--scids', '00',
                              first_scid(l1, l2),
                              first_scid(l2, l3),
                              first_scid(l3, l4)],
                             check=True,
                             timeout=TIMEOUT,
                             stdout=subprocess.PIPE).stdout.strip().decode()

    query = subprocess.run(['devtools/mkquery',
                            'query_short_channel_ids',
                            chainparams['chain_hash'],
                            encoded,
                            # We want channel announce, updates and node ann.
                            '00', '1F1F1F'],
                           check=True,
                           timeout=TIMEOUT,
                           stdout=subprocess.PIPE).stdout.strip()

    # Queries should also be ratelimited, so compare l1 vs l4.
    start_fast = time.time()
    out3 = subprocess.run(['devtools/gossipwith',
                           '--no-gossip',
                           '--hex',
                           '--network={}'.format(TEST_NETWORK),
                           '--max-messages={}'.format(expected),
                           '{}@localhost:{}'.format(l1.info['id'], l1.port),
                           query],
                          check=True,
                          timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    time_fast = time.time() - start_fast
    assert time_fast < 2
    out3 = [m for m in out3 if not m.startswith(b'0109')]
    assert set(out1) == set(out3)

    start_slow = time.time()
    out4 = subprocess.run(['devtools/gossipwith',
                           '--no-gossip',
                           '--hex',
                           '--network={}'.format(TEST_NETWORK),
                           '--max-messages={}'.format(expected),
                           '{}@localhost:{}'.format(l4.info['id'], l4.port),
                           query],
                          check=True,
                          timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    time_slow = time.time() - start_slow
    assert time_slow > 3
    out4 = [m for m in out4 if not m.startswith(b'0109')]
    assert set(out2) == set(out4)


def test_generate_gossip_store(node_factory):
    l1 = node_factory.get_node(start=False)
    chans = [GenChannel(0, 1),
             GenChannel(0, 2, capacity_sats=5000),
             GenChannel(0, 3,
                        forward=GenChannel.Half(enabled=False,
                                                htlc_min=10,
                                                htlc_max=5000000 - 10,
                                                basefee=10,
                                                propfee=10),
                        reverse=GenChannel.Half(htlc_min=11,
                                                htlc_max=5000000 - 11,
                                                basefee=11,
                                                propfee=11)),
             GenChannel(0, 4)]
    gsfile, nodemap = generate_gossip_store(chans)

    # Set up l1 with this as the gossip_store
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))
    l1.start()

    nodes = [nodemap[i] for i in range(0, 5)]
    expected = []
    chancount = 0
    for c in chans:
        for d in (0, 1):
            # listchannels direction 0 always lesser -> greater.
            if nodes[c.node1] < nodes[c.node2]:
                expected_dir = d
            else:
                expected_dir = d ^ 1
            channel_flags = expected_dir
            if not c.half[d].enabled:
                active = False
                channel_flags |= 2
            else:
                active = True
            if d == 0:
                n1 = nodes[c.node1]
                n2 = nodes[c.node2]
            else:
                n1 = nodes[c.node2]
                n2 = nodes[c.node1]

            expected.append({'source': n1,
                             'destination': n2,
                             'short_channel_id': '{}x{}x{}'.format(c.node1, c.node2, chancount),
                             'direction': expected_dir,
                             'public': True,
                             'amount_msat': c.capacity_sats * 1000,
                             'message_flags': 1,
                             'channel_flags': channel_flags,
                             'active': active,
                             'last_update': 0,
                             'base_fee_millisatoshi': c.half[d].basefee,
                             'fee_per_millionth': c.half[d].propfee,
                             'delay': c.half[d].delay,
                             'htlc_minimum_msat': c.half[d].htlc_min,
                             'htlc_maximum_msat': c.half[d].htlc_max,
                             'features': ''})
        chancount += 1

    # Order is not well-defined, and sets don't like dicts :(
    lchans = sorted(l1.rpc.listchannels()['channels'], key=lambda x: x['source'] + x['destination'])
    expected = sorted(expected, key=lambda x: x['source'] + x['destination'])

    assert lchans == expected


def test_gossip_status(node_factory, chainparams):
    # Since we respond if we have > 100 more than them, we need a big gossmap.
    l1 = node_factory.get_node(start=False)
    chans = [GenChannel(0, i) for i in range(1, 102)]
    gsfile, nodemap = generate_gossip_store(chans)
    shutil.copy(gsfile.name, os.path.join(l1.daemon.lightning_dir, TEST_NETWORK, 'gossip_store'))

    l1.daemon.opts['experimental-gossip-status'] = None
    l1.start()

    assert len(l1.rpc.listchannels()['channels']) == 101 * 2

    # If I say I have 1/102/1, you won't give me anything.
    out = subprocess.run(['devtools/gossipwith',
                          '--no-gossip',
                          '--hex',
                          '--network={}'.format(TEST_NETWORK),
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port),
                          # BOLT-gossip_status #7:
                          # 1. type: 267 (`gossip_status`)
                          # 2. data:
                          #     * [`chain_hash`:`chain_hash`]
                          #     * [`bigsize`:`num_channel_announcements`]
                          #     * [`bigsize`:`num_channel_updates`]
                          #     * [`bigsize`:`num_node_announcements`]
                          '763B' + chainparams['chain_hash'] + '016601'],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()

    # No channel_announcments, channel_updates or node_announcements
    assert [m for m in out if m.startswith(b'0100') or m.startswith(b'0101') or m.startswith(b'0102')] == []

    # If I say I have 0 channel_announcments, you spew gossip...
    out = subprocess.run(['devtools/gossipwith',
                          '--no-gossip',
                          '--hex',
                          '--network={}'.format(TEST_NETWORK),
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port),
                          # BOLT-gossip_status #7:
                          # 1. type: 267 (`gossip_status`)
                          # 2. data:
                          #     * [`chain_hash`:`chain_hash`]
                          #     * [`bigsize`:`num_channel_announcements`]
                          #     * [`bigsize`:`num_channel_updates`]
                          #     * [`bigsize`:`num_node_announcements`]
                          '763B' + chainparams['chain_hash'] + '00CA01'],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    assert len([m for m in out if m.startswith(b'0100') or m.startswith(b'0101') or m.startswith(b'0102')]) == 303

    # If I say I have 101 channel_updates, you spew gossip...
    out = subprocess.run(['devtools/gossipwith',
                          '--no-gossip',
                          '--hex',
                          '--network={}'.format(TEST_NETWORK),
                          '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                          '{}@localhost:{}'.format(l1.info['id'], l1.port),
                          # BOLT-gossip_status #7:
                          # 1. type: 267 (`gossip_status`)
                          # 2. data:
                          #     * [`chain_hash`:`chain_hash`]
                          #     * [`bigsize`:`num_channel_announcements`]
                          #     * [`bigsize`:`num_channel_updates`]
                          #     * [`bigsize`:`num_node_announcements`]
                          '763B' + chainparams['chain_hash'] + '656501'],
                         check=True,
                         timeout=TIMEOUT, stdout=subprocess.PIPE).stdout.split()
    assert len([m for m in out if m.startswith(b'0100') or m.startswith(b'0101') or m.startswith(b'0102')]) == 303
