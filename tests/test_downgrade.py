from fixtures import *  # noqa: F401,F403
from utils import (
    TIMEOUT,  # noqa: F401
    first_scid,
    only_one,
    generate_gossip_store,
    GenChannel,
)

import os
import pytest
import subprocess

# From the binary:
# ERROR_DBVERSION = 1
ERROR_DBFAIL = 2
ERROR_USAGE = 3
# ERROR_INTERNAL = 99

PREV_LIGHTNINGD = os.getenv('PREV_LIGHTNINGD')
CLN_PREV_VERSION = os.getenv('CLN_PREV_VERSION')


def direction(src, dst):
    """BOLT 7 direction: 0 means from lesser encoded id"""
    if src < dst:
        return 0
    return 1


def scid_dir(nodemap, node1_idx, node2_idx, chan_idx):
    """Get short_channel_id_dir for a channel in generate_gossip_store format"""
    dir_val = direction(nodemap[node1_idx], nodemap[node2_idx])
    return f"{node1_idx}x{node2_idx}x{chan_idx}/{dir_val}"


def downgrade_cmdline(node):
    # lightning-downgrade understands a subset of the options
    # to lightningd.
    downgrade_opts = []
    for o in node.daemon.opts:
        if o in ('network', 'lightning-dir', 'conf', 'rpc-file', 'wallet'):
            if node.daemon.opts[o] is None:
                downgrade_opts.append(f"--{o}")
            else:
                downgrade_opts.append(f"--{o}={node.daemon.opts[o]}")

    cmd_line = ["tools/lightning-downgrade"] + downgrade_opts
    if os.getenv("VALGRIND") == "1":
        cmd_line = ['valgrind', '-q', '--error-exitcode=7'] + cmd_line
    return cmd_line


def test_downgrade(node_factory, executor):
    # To downgrade before 25.12, we need old-style hsm_secret.
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True, 'old_hsmsecret': True}, wait_for_announce=True)

    bias_scidd = f"{first_scid(l1, l2)}/0"
    # Create a bias for this channel.
    l1.rpc.askrene_bias_channel('xpay', bias_scidd, 1)
    bias = only_one(only_one(l1.rpc.askrene_listlayers('xpay')['layers'])['biases'])
    assert bias['short_channel_id_dir'] == bias_scidd
    assert bias['bias'] == 1

    # Make a payment, which means we update layer information.
    old_inv = l2.rpc.invoice(1000, 'test_downgrade1', 'test_downgrade')
    l1.rpc.xpay(old_inv['bolt11'])

    cmd_line = downgrade_cmdline(l1)

    # No downgrade on live nodes!
    retcode = subprocess.call(cmd_line, timeout=TIMEOUT)
    assert retcode == ERROR_USAGE

    l1.stop()
    subprocess.check_call(cmd_line)

    # Test with old lightningd if it's available.
    old_cln = os.getenv('PREV_LIGHTNINGD')
    if old_cln:
        current_executable = l1.daemon.executable
        l1.daemon.executable = old_cln

        l1.start()

        # Disable schema checking here: the node is OLD!
        l1.rpc.jsonschemas = {}

        # It should connect to l2 no problems, make payment.
        l1.connect(l2)
        inv = l2.rpc.invoice(1000, 'test_downgrade', 'test_downgrade')
        l1.rpc.xpay(inv['bolt11'])

        # It should see the bias!
        bias = only_one(only_one(l1.rpc.askrene_listlayers('xpay')['layers'])['biases'])
        assert bias['short_channel_id_dir'] == bias_scidd
        assert bias['bias'] == 1

        l1.stop()
        l1.daemon.executable = current_executable

    # Another downgrade is a noop.
    assert "Already compatible with " in subprocess.check_output(cmd_line).decode("utf8")

    # Should be able to upgrade without any trouble
    l1.daemon.opts['database-upgrade'] = True
    l1.start()
    # Note: currently a noop, this will break on first database upgrade.
    assert not l1.daemon.is_in_log("Updating database from version 281")

    l1.connect(l2)
    inv2 = l2.rpc.invoice(1000, 'test_downgrade2', 'test_downgrade2')
    l1.rpc.xpay(inv2['bolt11'])

    # bias still present
    bias = only_one(only_one(l1.rpc.askrene_listlayers('xpay')['layers'])['biases'])
    assert bias['short_channel_id_dir'] == bias_scidd
    assert bias['bias'] == 1


def test_downgrade_bias(node_factory, executor):
    """If we have created as node bias, we *can* downgrade this version."""
    l1, l2 = node_factory.line_graph(2, opts={'may_reconnect': True, 'old_hsmsecret': True}, wait_for_announce=True)

    l1.rpc.askrene_bias_node('xpay', l2.info['id'], 'in', 1)
    cmd_line = downgrade_cmdline(l1)

    l1.stop()

    p = subprocess.Popen(cmd_line, stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    _, err = p.communicate(timeout=TIMEOUT)
    assert p.returncode == 0


@pytest.mark.skipif(not CLN_PREV_VERSION, reason="Depends on CLN_PREV_VERSION")
@pytest.mark.skipif(not PREV_LIGHTNINGD, reason="Depends on PREV_LIGHTNINGD")
def test_downgrade_impressions(node_factory, executor):
    """Impressions are added since v26.09, the downgrade tool should remove
    them while the rest of the askrene data remains."""
    cap_msat = 1000_000_000
    gsfile, nodemap = generate_gossip_store(
        [GenChannel(0, 1, capacity_sats=cap_msat // 1000)]
    )
    l1 = node_factory.get_node(
        gossip_store_file=gsfile.name, options={"database-upgrade": True}
    )

    chan_dir = scid_dir(nodemap, 0, 1, 0)
    l1.rpc.askrene_create_layer(layer="test_downgrade", persistent=True)
    expect = {
        "biases": [],
        "channel_updates": [],
        "constraints": [],
        "created_channels": [],
        "disabled_nodes": [],
        "impressions": [],
        "layer": "test_downgrade",
        "node_biases": [],
        "persistent": True,
    }
    ret = l1.rpc.askrene_inform_channel(
        "test_downgrade", chan_dir, 1000000, "succeeded"
    )

    expect["impressions"] = [
        {
            "amount_msat": 1000000,
            "short_channel_id_dir": chan_dir,
            "timestamp": ret["impressions"][0]["timestamp"],
        }
    ]

    ret = l1.rpc.askrene_inform_channel(
        "test_downgrade", chan_dir, 500000, "constrained"
    )
    expect["constraints"] = [
        {
            "maximum_msat": 499999,
            "short_channel_id_dir": chan_dir,
            "timestamp": ret["constraints"][0]["timestamp"],
        }
    ]
    ret = l1.rpc.askrene_inform_channel(
        "test_downgrade", chan_dir, 20000, "unconstrained"
    )
    expect["constraints"].append(
        {
            "minimum_msat": 20000,
            "short_channel_id_dir": chan_dir,
            "timestamp": ret["constraints"][0]["timestamp"],
        }
    )

    A_NODE = "020000000000000000000000000000000000000000000000000000000000000001"
    ret = l1.rpc.askrene_create_channel(
        "test_downgrade", A_NODE, l1.info["id"], "16000000x1x1", "100000000sat"
    )
    expect["created_channels"] = [
        {
            "source": A_NODE,
            "destination": l1.info["id"],
            "short_channel_id": "16000000x1x1",
            "capacity_msat": 100000000000,
        }
    ]

    l1.rpc.askrene_update_channel(
        layer="test_downgrade",
        short_channel_id_dir="16000000x1x1/0",
        enabled=True,
        htlc_minimum_msat=1000,
    )
    expect["channel_updates"] = [
        {
            "enabled": True,
            "htlc_minimum_msat": 1000,
            "short_channel_id_dir": "16000000x1x1/0",
        }
    ]
    ret = l1.rpc.askrene_bias_channel(
        layer="test_downgrade", short_channel_id_dir="16000000x1x1/0", bias=3
    )
    expect["biases"] = [
        {
            "timestamp": ret["biases"][0]["timestamp"],
            "bias": 3,
            "short_channel_id_dir": "16000000x1x1/0",
        }
    ]
    B_NODE = "020000000000000000000000000000000000000000000000000000000000000002"

    l1.rpc.askrene_disable_node(layer="test_downgrade", node=B_NODE)
    expect["disabled_nodes"] = [B_NODE]

    ret = l1.rpc.askrene_bias_node(
        layer="test_downgrade", direction="in", node=A_NODE, bias=-2
    )
    expect["node_biases"] = [
        {
            "in_bias": -2,
            "out_bias": 0,
            "node": A_NODE,
            "timestamp": ret["node_biases"][0]["timestamp"],
        }
    ]
    assert l1.rpc.askrene_listlayers("test_downgrade") == {"layers": [expect]}

    cmd_line = downgrade_cmdline(l1)

    l1.stop()

    p = subprocess.run(cmd_line, timeout=TIMEOUT, capture_output=True, text=True)
    assert p.returncode == 0
    if CLN_PREV_VERSION == "v26.06":
        assert "Downgrade to v26.06 succeeded.  Committing." in p.stdout

    # we need to disable the schema checks, this node uses an old API
    l1.rpc.jsonschemas = {}
    # in the old node the impressions field doesn't even exist
    if CLN_PREV_VERSION == "v26.06":
        del expect["impressions"]
    l1.daemon.executable = PREV_LIGHTNINGD

    l1.start()
    assert l1.rpc.askrene_listlayers("test_downgrade") == {"layers": [expect]}
