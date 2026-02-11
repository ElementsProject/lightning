from fixtures import *  # noqa: F401,F403
from utils import (
    TIMEOUT,  # noqa: F401
    first_scid, only_one,
)

import os
import subprocess

# From the binary:
# ERROR_DBVERSION = 1
ERROR_DBFAIL = 2
ERROR_USAGE = 3
# ERROR_INTERNAL = 99


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
    assert not l1.daemon.is_in_log("Updating database from version 280")

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
