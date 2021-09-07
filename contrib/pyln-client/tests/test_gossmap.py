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

    # It will notice the new ones.
    assert chans < len(g.channels)
    assert nodes < len(g.nodes)

    # Whole load at the same time gives the same results.
    g2 = Gossmap(sfile)
    assert set(g.channels.keys()) == set(g2.channels.keys())
    assert set(g.nodes.keys()) == set(g2.nodes.keys())

    # Check some details
    channel1 = g.get_channel("686386x1093x1")
    channel2 = g.get_channel("686200x1137x0")
    assert channel1.satoshis == 1000000
    assert channel2.satoshis == 3000000


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
