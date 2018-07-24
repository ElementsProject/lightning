from fixtures import *  # noqa: F401,F403

import os
import signal
import unittest

with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"


@unittest.skipIf(not DEVELOPER, "needs --dev-disconnect")
def test_stop_pending_fundchannel(node_factory, executor):
    """Stop the daemon while waiting for an accept_channel

    This used to crash the node, since we were calling unreserve_utxo while
    freeing the daemon, but that needs a DB transaction to be open.

    """
    l1 = node_factory.get_node()
    l2 = node_factory.get_node()

    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We want l2 to stop replying altogether, not disconnect
    os.kill(l2.daemon.proc.pid, signal.SIGSTOP)

    # The fundchannel call will not terminate so run it in a future
    executor.submit(l1.fund_channel, l2, 10**6)
    l1.daemon.wait_for_log('peer_out WIRE_OPEN_CHANNEL')

    l1.rpc.stop()

    # Now allow l2 a clean shutdown
    os.kill(l2.daemon.proc.pid, signal.SIGCONT)
    l2.rpc.stop()
