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
    directory = tempfile.mkdtemp(prefix='ltests-')
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
    # determine whether we succeeded or failed.
    if not request.node.has_errors and request.node.rep_call.outcome == 'passed':
        shutil.rmtree(directory)
    else:
        logging.debug("Test execution failed, leaving the test directory {} intact.".format(directory))


@pytest.fixture
def test_name(request):
    yield request.function.__name__


@pytest.fixture
def bitcoind(directory):
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
        bitcoind.rpc.stop()
    except Exception:
        bitcoind.proc.kill()
    bitcoind.proc.wait()


@pytest.fixture
def node_factory(request, directory, test_name, bitcoind, executor):
    nf = NodeFactory(test_name, bitcoind, executor, directory=directory)
    yield nf
    err_count = 0
    ok = nf.killall([not n.may_fail for n in nf.nodes])

    def check_errors(request, err_count, msg):
        """Just a simple helper to format a message, set flags on request and then raise
        """
        if err_count:
            request.node.has_errors = True
            raise ValueError(msg.format(err_count))

    if VALGRIND:
        for node in nf.nodes:
            err_count += printValgrindErrors(node)
        check_errors(request, err_count, "{} nodes reported valgrind errors")

    for node in nf.nodes:
        err_count += printCrashLog(node)
    check_errors(request, err_count, "{} nodes had crash.log files")

    for node in nf.nodes:
        err_count += checkReconnect(node)
    check_errors(request, err_count, "{} nodes had unexpected reconnections")

    for node in nf.nodes:
        err_count += checkBadGossipOrder(node)
    check_errors(request, err_count, "{} nodes had bad gossip order")

    for node in nf.nodes:
        err_count += checkBadReestablish(node)
    check_errors(request, err_count, "{} nodes had bad reestablish")

    if not ok:
        request.node.has_errors = True
        raise Exception("At least one lightning exited with unexpected non-zero return code")


def getValgrindErrors(node):
    for error_file in os.listdir(node.daemon.lightning_dir):
        if not re.fullmatch("valgrind-errors.\d+", error_file):
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


def checkBadGossipOrder(node):
    if node.daemon.is_in_log('Bad gossip order from (?!error)') and not node.daemon.is_in_log('Deleting channel'):
        return 1
    return 0


def checkBadReestablish(node):
    if node.daemon.is_in_log('Bad reestablish'):
        return 1
    return 0


@pytest.fixture
def executor():
    ex = futures.ThreadPoolExecutor(max_workers=20)
    yield ex
    ex.shutdown(wait=False)
