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
