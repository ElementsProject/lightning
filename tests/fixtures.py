from utils import DEVELOPER, TEST_NETWORK  # noqa: F401,F403
from pyln.testing.fixtures import directory, test_base_dir, test_name, chainparams, node_factory, bitcoind, teardown_checks, throttler, db_provider, executor, setup_logging, jsonschemas  # noqa: F401,F403
from pyln.testing import utils
from utils import COMPAT

import os
import pytest
import re


@pytest.fixture
def node_cls():
    return LightningNode


class LightningNode(utils.LightningNode):
    def __init__(self, *args, **kwargs):
        utils.LightningNode.__init__(self, *args, **kwargs)

        # If we opted into checking the DB statements we will attach the dblog
        # plugin before starting the node
        check_dblog = os.environ.get("TEST_CHECK_DBSTMTS", None) == "1"
        db = os.environ.get("TEST_DB_PROVIDER", "sqlite3")
        if db == 'sqlite3' and check_dblog:
            dblog = os.path.join(os.path.dirname(__file__), 'plugins', 'dblog.py')
            has_dblog = len([o for o in self.daemon.cmd_line if 'dblog.py' in o]) > 0
            if not has_dblog:
                # Add as an expanded option so we don't clobber other options.
                self.daemon.opts['plugin={}'.format(dblog)] = None

        # Yes, we really want to test the local development version, not
        # something in out path.
        self.daemon.executable = 'lightningd/lightningd'


class CompatLevel(object):
    """An object that encapsulates the compat-level of our build.
    """
    def __init__(self):
        makefile = os.path.join(os.path.dirname(__file__), "..", "Makefile")
        lines = [l for l in open(makefile, 'r') if l.startswith('COMPAT_CFLAGS')]
        assert(len(lines) == 1)
        line = lines[0]
        flags = re.findall(r'COMPAT_V([0-9]+)=1', line)
        self.compat_flags = flags

    def __call__(self, version):
        return COMPAT and version in self.compat_flags


@pytest.fixture
def compat():
    return CompatLevel()


def is_compat(version):
    compat = CompatLevel()
    return compat(version)
