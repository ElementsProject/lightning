from pyln.testing.utils import TEST_NETWORK, SLOW_MACHINE, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"
# features 1, 3, 7, 9, 11, 13, 15 and 17 (0x02aaa2).
BASE_FEATURES = "02aaa2"
# dual funding is currently 19; will update in the future
# features 1, 3, 7, 9, 11, 13, 15, 17, 19 (0x0aaaa2).
BASE_PLUS_DF = "0aaaa2"


def expected_peer_features():
    """Return the expected peer features hexstring for this configuration"""
    if not EXPERIMENTAL_FEATURES:
        return BASE_FEATURES

    return BASE_PLUS_DF


# With the addition of the keysend plugin, we now send a different set of
# features for the 'node' and the 'peer' feature sets
def expected_node_features():
    """Return the expected node features hexstring for this configuration"""
    if not EXPERIMENTAL_FEATURES:
        return "80000000" + BASE_FEATURES

    return "80000000" + BASE_PLUS_DF
