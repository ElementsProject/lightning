from utils import TEST_NETWORK, VALGRIND  # noqa: F401,F403
from pyln.testing.fixtures import directory, test_base_dir, test_name, chainparams, node_factory, bitcoind, teardown_checks, db_provider, executor, setup_logging, jsonschemas  # noqa: F401,F403
from pyln.testing import utils
from utils import COMPAT
from pathlib import Path

import os
import pytest
import re


@pytest.fixture
def node_cls():
    return LightningNode


class LightningNode(utils.LightningNode):
    def __init__(self, *args, **kwargs):
        # Yes, we really want to test the local development version, not
        # something in out path.
        self.old_path = os.environ['PATH']
        binpath = Path(__file__).parent / ".." / "lightningd"
        os.environ['PATH'] = f"{binpath}:{self.old_path}"

        utils.LightningNode.__init__(self, *args, **kwargs)

        # We have some valgrind suppressions in the `tests/`
        # directory, so we can add these to the valgrind configuration
        # (not generally true when running pyln-testing, hence why
        # it's being done in this specialization, and not in the
        # library).
        if self.daemon.cmd_line[0] == 'valgrind':
            suppressions_path = Path(__file__).parent / "valgrind-suppressions.txt"
            self.daemon.cmd_prefix += [
                f"--suppressions={suppressions_path}",
                "--gen-suppressions=all"
            ]

        # If we opted into checking the DB statements we will attach the dblog
        # plugin before starting the node
        check_dblog = os.environ.get("TEST_CHECK_DBSTMTS", None) == "1"
        db_type = os.environ.get("TEST_DB_PROVIDER", "sqlite3")
        if db_type == 'sqlite3' and check_dblog:
            dblog = os.path.join(os.path.dirname(__file__), 'plugins', 'dblog.py')
            has_dblog = len([o for o in self.daemon.cmd_line if 'dblog.py' in o]) > 0
            if not has_dblog:
                # Add as an expanded option so we don't clobber other options.
                self.daemon.opts['plugin={}'.format(dblog)] = None
                self.daemon.opts['dblog-file'] = 'dblog.sqlite3'

        # FIXME: make sure bookkeeper is not disabled
        if db_type == 'postgres':
            accts_db = self.db.provider.get_db('', 'accounts', 0)
            self.daemon.opts['bookkeeper-db'] = accts_db.get_dsn()

    def __del__(self):
        os.environ['PATH'] = self.old_path


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
