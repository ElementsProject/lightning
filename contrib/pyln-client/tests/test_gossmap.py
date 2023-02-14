from pyln.client import Gossmap, GossmapNode, GossmapNodeId

import os.path
import lzma


def unxz_data_tmp(src, tmp_path, dst, wmode):
    fulldst = os.path.join(tmp_path, dst)
    with open(fulldst, wmode) as out:
        with lzma.open(os.path.join(os.path.dirname(__file__), "data", src), "rb")as f:
            out.write(f.read())
    return fulldst


def test_gossmap(tmp_path):
    sfile = unxz_data_tmp("gossip_store-part1.xz", tmp_path, "gossip_store", "xb")
    g = Gossmap(sfile)

    chans = len(g.channels)
    nodes = len(g.nodes)

    g.refresh()
    assert chans == len(g.channels)
    assert nodes == len(g.nodes)

    # Now append.
    unxz_data_tmp("gossip_store-part2.xz", tmp_path, "gossip_store", "ab")

    g.refresh()

    # This actually deletes a channel, which deletes a node.
    assert g.get_channel("686386x1093x1") is None
    assert g.get_node('029deaf9d2fba868fe0a124050f0a13e021519a12f41bea34f391fe7533fb3166d') is None
    # The other node is untouched
    assert g.get_node('02e0af3c70bf42343316513e54683b10c01d906c04a05dfcd9479b90d7beed9129')

    # It will notice the new ones.
    assert chans < len(g.channels)
    assert nodes < len(g.nodes)

    # Whole load at the same time gives the same results.
    g2 = Gossmap(sfile)
    assert set(g.channels.keys()) == set(g2.channels.keys())
    assert set(g.nodes.keys()) == set(g2.nodes.keys())

    # Check some details
    channel2 = g.get_channel("686200x1137x0")
    assert g.get_channel("686386x1093x1") is None
    assert channel2.satoshis == 3000000


def test_gossmap_halfchannel(tmp_path):
    """ this test a simple [l1->l2] gossip store that was created by the pyln-testing framework """
    sfile = unxz_data_tmp("gossip_store.simple.xz", tmp_path, "gossip_store", "xb")
    g = Gossmap(sfile)

    l1id = "022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59"
    l2id = "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518"

    # check structure parsed correctly
    assert(len(g.nodes) == 2)
    n1 = g.get_node(l1id)
    n2 = g.get_node(l2id)
    assert n1
    assert n2

    chan = g.get_channel("103x1x1")
    assert chan
    assert chan.node1 == n1
    assert chan.node2 == n2

    half0 = chan.get_direction(0)
    half1 = chan.get_direction(1)
    assert half0
    assert half1
    assert half0.direction == 0
    assert half1.direction == 1
    assert half0.channel == chan
    assert half1.channel == chan
    assert half0.source == n1
    assert half0.destination == n2
    assert half1.source == n2
    assert half1.destination == n1

    # check metadata
    assert half0.timestamp == 1631005020
    assert half1.timestamp == 1631005020
    assert half0.cltv_expiry_delta == 6
    assert half1.cltv_expiry_delta == 6
    assert half0.htlc_minimum_msat == 0
    assert half1.htlc_minimum_msat == 0
    assert half0.htlc_maximum_msat == 990000000
    assert half1.htlc_maximum_msat == 990000000
    assert half0.fee_base_msat == 1
    assert half1.fee_base_msat == 1
    assert half0.fee_proportional_millionths == 10


def test_objects():
    boltz = "026165850492521f4ac8abd9bd8088123446d126f648ca35e60f88177dc149ceb2"
    acinq = "03864ef025fde8fb587d989186ce6a4a186895ee44a926bfc370e2c366597a3f8f"

    boltz_id = GossmapNodeId(bytes.fromhex(boltz))
    acinq_id = GossmapNodeId(bytes.fromhex(acinq))
    assert boltz_id == GossmapNodeId(boltz)

    assert boltz_id < acinq_id
    assert acinq_id > boltz_id
    assert boltz_id != acinq_id
    assert acinq_id != boltz_id
    assert not boltz_id > acinq_id
    assert not acinq_id < boltz_id
    assert not boltz_id == acinq_id
    assert not acinq_id == boltz_id

    boltz_node = GossmapNode(boltz_id)
    acinq_node = GossmapNode(acinq_id)
    assert boltz_node == GossmapNode(boltz)
    assert boltz_node < acinq_node
    assert acinq_node > boltz_node
    assert boltz_node != acinq_node


def test_mesh(tmp_path):
    """This gossip store is a nice mesh created with pyln-testing:

       l1--l2--l3
       |   |   |
       l4--l5--l6
       |   |   |
       l7--l8--l9
    """
    sfile = unxz_data_tmp("gossip_store.mesh-3x3.xz", tmp_path, "gossip_store", "xb")
    g = Gossmap(sfile)
    assert len(g.nodes) == 9
    assert len(g.channels) == 12

    nodeids = ['0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518',
               '022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59',
               '035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d',
               '0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199',
               '032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e',
               '0265b6ab5ec860cd257865d61ef0bbf5b3339c36cbda8b26b74e7f1dca490b6518',
               '0269f9862c311261241e5aee7abe0ec93c88613cc8f3c5f33cb1eea90d2bc4ddb6',
               '03a7fd8070eea99341418fefe0b31086054d09cff64649eec3605db2340631c616',
               '030eeb52087b9dbb27b7aec79ca5249369f6ce7b20a5684ce38d9f4595a21c2fda']
    scid12 = '103x1x0'
    scid14 = '105x1x1'
    scid23 = '107x1x1'
    scid25 = '109x1x1'
    scid36 = '111x1x0'
    scid45 = '113x1x0'
    scid47 = '115x1x1'
    scid56 = '117x1x1'
    scid58 = '119x1x0'
    scid69 = '121x1x1'
    scid78 = '123x1x1'
    scid89 = '125x1x1'
    scids = [scid12, scid14, scid23, scid25, scid36, scid45, scid47, scid56,
             scid58, scid69, scid78, scid89]

    # check all nodes are there
    for nodeid in nodeids:
        node = g.get_node(nodeid)
        assert node
        assert str(node.node_id) == nodeid
        for channel in node.channels:
            assert str(channel.scid) in scids

    # assert all channels are there
    for scid in scids:
        channel = g.get_channel(scid)
        assert channel
        assert str(channel.scid) == scid
        assert channel.half_channels[0]
        assert channel.half_channels[1]
