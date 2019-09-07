from concurrent import futures
from utils import NodeFactory, BitcoinD

import logging
import os
import pytest
import re
import shutil
import sys
import tempfile


with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

VALGRIND = os.getenv("VALGRIND", config['VALGRIND']) == "1"
DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"
TEST_DEBUG = os.getenv("TEST_DEBUG", "0") == "1"


if TEST_DEBUG:
    logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)


# A dict in which we count how often a particular test has run so far. Used to
# give each attempt its own numbered directory, and avoid clashes.
__attempts = {}


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix='ltests-', dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    if os.listdir(directory) == []:
        shutil.rmtree(directory)


@pytest.fixture
def directory(request, test_base_dir, test_name):
    """Return a per-test specific directory.

    This makes a unique test-directory even if a test is rerun multiple times.

    """
    global __attempts
    # Auto set value if it isn't in the dict yet
    __attempts[test_name] = __attempts.get(test_name, 0) + 1
    directory = os.path.join(test_base_dir, "{}_{}".format(test_name, __attempts[test_name]))
    request.node.has_errors = False

    yield directory

    # This uses the status set in conftest.pytest_runtest_makereport to
    # determine whether we succeeded or failed. Outcome can be None if the
    # failure occurs during the setup phase, hence the use to getattr instead
    # of accessing it directly.
    outcome = getattr(request.node, 'rep_call', None).outcome
    failed = not outcome or request.node.has_errors or outcome != 'passed'

    if not failed:
        shutil.rmtree(directory)
    else:
        logging.debug("Test execution failed, leaving the test directory {} intact.".format(directory))


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def bitcoind(directory, teardown_checks):
    bitcoind = BitcoinD(bitcoin_dir=directory)
    try:
        bitcoind.start()
    except Exception:
        bitcoind.stop()
        raise

    info = bitcoind.rpc.getnetworkinfo()

    if info['version'] < 160000:
        bitcoind.rpc.stop()
        raise ValueError("bitcoind is too old. At least version 16000 (v0.16.0)"
                         " is needed, current version is {}".format(info['version']))

    info = bitcoind.rpc.getblockchaininfo()
    # Make sure we have some spendable funds
    if info['blocks'] < 101:
        bitcoind.generate_block(101 - info['blocks'])
    elif bitcoind.rpc.getwalletinfo()['balance'] < 1:
        logging.debug("Insufficient balance, generating 1 block")
        bitcoind.generate_block(1)

    yield bitcoind

    try:
        bitcoind.stop()
    except Exception:
        bitcoind.proc.kill()
    bitcoind.proc.wait()


class TeardownErrors(object):
    def __init__(self):
        self.errors = []
        self.node_errors = []

    def add_error(self, msg):
        self.errors.append(msg)

    def add_node_error(self, node, msg):
        self.node_errors.append((node.daemon.prefix, msg))

    def __str__(self):
        node_errors = [" - {}: {}".format(*e) for e in self.node_errors]
        errors = [" - {}".format(e) for e in self.errors]

        errors = ["\nNode errors:"] + node_errors + ["Global errors:"] + errors
        return "\n".join(errors)

    def has_errors(self):
        return len(self.errors) > 0 or len(self.node_errors) > 0


@pytest.fixture
def teardown_checks(request):
    """A simple fixture to collect errors during teardown.

    We need to collect the errors and raise them as the very last step in the
    fixture tree, otherwise some fixtures may not be cleaned up
    correctly. Require this fixture in all other fixtures that need to either
    cleanup before reporting an error or want to add an error that is to be
    reported.

    """
    errors = TeardownErrors()
    yield errors

    if errors.has_errors():
        # Format a nice list of everything that went wrong and raise an exception
        request.node.has_errors = True
        raise ValueError(str(errors))


@pytest.fixture
def node_factory(request, directory, test_name, bitcoind, executor, teardown_checks):
    nf = NodeFactory(
        test_name,
        bitcoind,
        executor,
        directory=directory,
    )

    yield nf
    ok, errs = nf.killall([not n.may_fail for n in nf.nodes])

    for e in errs:
        teardown_checks.add_error(e)

    def map_node_error(nodes, f, msg):
        for n in nodes:
            if n and f(n):
                teardown_checks.add_node_error(n, msg)

    map_node_error(nf.nodes, printValgrindErrors, "reported valgrind errors")
    map_node_error(nf.nodes, printCrashLog, "had crash.log files")
    map_node_error(nf.nodes, lambda n: not n.allow_broken_log and n.daemon.is_in_log(r'\*\*BROKEN\*\*'), "had BROKEN messages")
    map_node_error(nf.nodes, checkReconnect, "had unexpected reconnections")
    map_node_error(nf.nodes, checkBadGossip, "had bad gossip messages")
    map_node_error(nf.nodes, lambda n: n.daemon.is_in_log('Bad reestablish'), "had bad reestablish")
    map_node_error(nf.nodes, lambda n: n.daemon.is_in_log('bad hsm request'), "had bad hsm requests")
    map_node_error(nf.nodes, checkMemleak, "had memleak messages")

    if not ok:
        teardown_checks.add_error("At least one lightning exited with unexpected non-zero return code")


def getValgrindErrors(node):
    for error_file in os.listdir(node.daemon.lightning_dir):
        if not re.fullmatch(r"valgrind-errors.\d+", error_file):
            continue
        with open(os.path.join(node.daemon.lightning_dir, error_file), 'r') as f:
            errors = f.read().strip()
            if errors:
                return errors, error_file
    return None, None


def printValgrindErrors(node):
    errors, fname = getValgrindErrors(node)
    if errors:
        print("-" * 31, "Valgrind errors", "-" * 32)
        print("Valgrind error file:", fname)
        print(errors)
        print("-" * 80)
    return 1 if errors else 0


def getCrashLog(node):
    if node.may_fail:
        return None, None
    try:
        crashlog = os.path.join(node.daemon.lightning_dir, 'crash.log')
        with open(crashlog, 'r') as f:
            return f.readlines(), crashlog
    except Exception:
        return None, None


def printCrashLog(node):
    errors, fname = getCrashLog(node)
    if errors:
        print("-" * 10, "{} (last 50 lines)".format(fname), "-" * 10)
        print("".join(errors[-50:]))
        print("-" * 80)
    return 1 if errors else 0


def checkReconnect(node):
    # Without DEVELOPER, we can't suppress reconnection.
    if node.may_reconnect or not DEVELOPER:
        return 0
    if node.daemon.is_in_log('Peer has reconnected'):
        return 1
    return 0


def checkBadGossip(node):
    if node.allow_bad_gossip:
        return 0
    # We can get bad gossip order from inside error msgs.
    if node.daemon.is_in_log('Bad gossip order from (?!error)'):
        # This can happen if a node sees a node_announce after a channel
        # is deleted, however.
        if node.daemon.is_in_log('Deleting channel'):
            return 0
        return 1

    # Other 'Bad' messages shouldn't happen.
    if node.daemon.is_in_log(r'gossipd.*Bad (?!gossip order from error)'):
        return 1
    return 0


def checkBroken(node):
    if node.allow_broken_log:
        return 0
    # We can get bad gossip order from inside error msgs.
    if node.daemon.is_in_log(r'\*\*BROKEN\*\*'):
        return 1
    return 0


def checkBadReestablish(node):
    if node.daemon.is_in_log('Bad reestablish'):
        return 1
    return 0


def checkBadHSMRequest(node):
    if node.daemon.is_in_log('bad hsm request'):
        return 1
    return 0


def checkMemleak(node):
    if node.daemon.is_in_log('MEMLEAK:'):
        return 1
    return 0


@pytest.fixture
def executor(teardown_checks):
    ex = futures.ThreadPoolExecutor(max_workers=20)
    yield ex
    ex.shutdown(wait=False)
