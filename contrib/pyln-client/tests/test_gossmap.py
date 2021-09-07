from pyln.client import Gossmap

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
