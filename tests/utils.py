from pyln.testing.utils import TEST_NETWORK, SLOW_MACHINE, TIMEOUT, VALGRIND, DEVELOPER  # noqa: F401
from pyln.testing.utils import env, only_one, wait_for, write_config, TailableProc, sync_blockheight, wait_channel_quiescent, get_tx_p2wsh_outnum  # noqa: F401


EXPERIMENTAL_FEATURES = env("EXPERIMENTAL_FEATURES", "0") == "1"
COMPAT = env("COMPAT", "1") == "1"


def expected_features():
    """Return the expected features hexstring for this configuration"""
    if EXPERIMENTAL_FEATURES:
        # features 1, 3, 7, 9, 11 and 13 (0x2aa2).
        return "2aa2"
    else:
        # features 1, 3, 7, 11 and 13 (0x28a2).
        return "28a2"
