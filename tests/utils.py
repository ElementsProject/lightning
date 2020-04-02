from pyln.testing.utils import TEST_NETWORK, SLOW_MACHINE, TIMEOUT, VALGRIND, DEVELOPER, DEPRECATED_APIS  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


def expected_features():
    """Return the expected features hexstring for this configuration"""
    # features 1, 3, 7, 9, 11, 13, 15 and 17 (0x02aaa2).
    return "02aaa2"
