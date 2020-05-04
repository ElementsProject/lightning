from pyln.testing.utils import TEST_NETWORK, SLOW_MACHINE, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


def expected_peer_features():
    """Return the expected peer features hexstring for this configuration"""
    # features 1, 3, 7, 9, 11, 13, 15 and 17 (0x02aaa2).
    return "02aaa2"


# With the addition of the keysend plugin, we now send a different set of
# features for the 'node' and the 'peer' feature sets
def expected_node_features():
    """Return the expected node features hexstring for this configuration"""
    # features 1, 3, 7, 9, 11, 13, 15, 17 and 55 (0x8000000002aaa2).
    return "8000000002aaa2"


def expected_channel_features():
    """Return the expected channel features hexstring for this configuration"""
    # experimental OPT_ONION_MESSAGES
    if EXPERIMENTAL_FEATURES:
        return '80000000000000000000000000'
    else:
        return ''
