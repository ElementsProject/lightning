from fixtures import *  # noqa: F401,F403
import pytest
import unittest
from utils import (
    TEST_NETWORK
)


@pytest.mark.openchannel('v1')
@pytest.mark.openchannel('v2')
@unittest.skipIf(TEST_NETWORK != 'regtest', 'elementsd doesnt yet support PSBT features we need')
def test_agressive_restart(node_factory, bitcoind):
    l1, l2 = node_factory.line_graph(2, fundamount=1000000, wait_for_announce=True, opts={'experimental-splicing': None})

    chan_id = l1.get_channel_id(l2)

    for _ in range(20):
        l1.rpc.stfu_channels([chan_id])
        l1.rpc.abort_channels([chan_id])
        l1.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
        l2.daemon.wait_for_log(r'peer_in WIRE_CHANNEL_REESTABLISH')
