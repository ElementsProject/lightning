from utils import DEVELOPER, TEST_NETWORK  # noqa: F401,F403
from pyln.testing.fixtures import directory, test_base_dir, test_name, chainparams, node_factory, bitcoind, teardown_checks, db_provider, executor, setup_logging  # noqa: F401,F403
from pyln.testing import utils

import pytest


@pytest.fixture
def node_cls():
    return LightningNode


class LightningNode(utils.LightningNode):
    def __init__(self, *args, **kwargs):
        utils.LightningNode.__init__(self, *args, **kwargs)

        # Yes, we really want to test the local development version, not
        # something in out path.
        self.daemon.executable = 'lightningd/lightningd'
