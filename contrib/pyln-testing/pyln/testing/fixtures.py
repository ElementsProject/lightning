from concurrent import futures
from pyln.testing.db import SqliteDbProvider, PostgresDbProvider
from pyln.testing.utils import NodeFactory, BitcoinD, ElementsD, env, DEVELOPER, LightningNode, TEST_DEBUG, Throttler
from typing import Dict

import logging
import os
import pytest  # type: ignore
import re
import shutil
import sys
import tempfile


# A dict in which we count how often a particular test has run so far. Used to
# give each attempt its own numbered directory, and avoid clashes.
__attempts: Dict[str, int] = {}


@pytest.fixture(scope="session")
def test_base_dir():
    d = os.getenv("TEST_DIR", "/tmp")

    directory = tempfile.mkdtemp(prefix='ltests-', dir=d)
    print("Running tests in {}".format(directory))

    yield directory

    # Now check if any test directory is left because the corresponding test
    # failed. If there are no such tests we can clean up the root test
    # directory.
    contents = [d for d in os.listdir(directory) if os.path.isdir(os.path.join(directory, d)) and d.startswith('test_')]
    if contents == []:
        shutil.rmtree(directory)
    else:
        print("Leaving base_dir {} intact, it still has test sub-directories with failure details: {}".format(
            directory, contents
        ))


@pytest.fixture(autouse=True)
def setup_logging():
    """Enable logging before a test, and remove all handlers afterwards.

    This "fixes" the issue with pytest swapping out sys.stdout and sys.stderr
    in order to capture the output, but then doesn't wait for the handlers to
    terminate before closing the buffers. It just iterates through all
    loggers, and removes any handlers that might be pointing at sys.stdout or
    sys.stderr.

    """
    if TEST_DEBUG:
        logging.basicConfig(level=logging.DEBUG, stream=sys.stdout)

    yield

    loggers = [logging.getLogger()] + list(logging.Logger.manager.loggerDict.values())
    for logger in loggers:
        handlers = getattr(logger, 'handlers', [])
        for handler in handlers:
            logger.removeHandler(handler)


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

    if not os.path.exists(directory):
        os.makedirs(directory)

    yield directory

    # This uses the status set in conftest.pytest_runtest_makereport to
    # determine whether we succeeded or failed. Outcome can be None if the
    # failure occurs during the setup phase, hence the use to getattr instead
    # of accessing it directly.
    rep_call = getattr(request.node, 'rep_call', None)
    outcome = 'passed' if rep_call is None else rep_call.outcome
    failed = not outcome or request.node.has_errors or outcome != 'passed'

    if not failed:
        try:
            shutil.rmtree(directory)
        except (OSError, Exception):
            files = [os.path.join(dp, f) for dp, dn, fn in os.walk(directory) for f in fn]
            print("Directory still contains files:", files)
            raise
    else:
        logging.debug("Test execution failed, leaving the test directory {} intact.".format(directory))


@pytest.fixture
def test_name(request):
    yield request.function.__name__


network_daemons = {
    'regtest': BitcoinD,
    'liquid-regtest': ElementsD,
}


@pytest.fixture
def node_cls():
    return LightningNode


@pytest.fixture
def bitcoind(directory, teardown_checks):
    chaind = network_daemons[env('TEST_NETWORK', 'regtest')]
    bitcoind = chaind(bitcoin_dir=directory)

    try:
        bitcoind.start()
    except Exception:
        bitcoind.stop()
        raise

    info = bitcoind.rpc.getnetworkinfo()

    # FIXME: include liquid-regtest in this check after elementsd has been
    # updated
    if info['version'] < 200100 and env('TEST_NETWORK') != 'liquid-regtest':
        bitcoind.rpc.stop()
        raise ValueError("bitcoind is too old. At least version 20100 (v0.20.1)"
                         " is needed, current version is {}".format(info['version']))
    elif info['version'] < 160000:
        bitcoind.rpc.stop()
        raise ValueError("elementsd is too old. At least version 160000 (v0.16.0)"
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
def throttler(test_base_dir):
    yield Throttler(test_base_dir)


@pytest.fixture
def node_factory(request, directory, test_name, bitcoind, executor, db_provider, teardown_checks, node_cls, throttler):
    nf = NodeFactory(
        request,
        test_name,
        bitcoind,
        executor,
        directory=directory,
        db_provider=db_provider,
        node_cls=node_cls,
        throttler=throttler,
    )

    yield nf
    ok, errs = nf.killall([not n.may_fail for n in nf.nodes])

    for e in errs:
        teardown_checks.add_error(e)

    def map_node_error(nodes, f, msg):
        for n in nodes:
            if n and f(n):
                teardown_checks.add_node_error(n, msg.format(n=n))

    map_node_error(nf.nodes, printValgrindErrors, "reported valgrind errors")
    map_node_error(nf.nodes, printCrashLog, "had crash.log files")
    map_node_error(nf.nodes, lambda n: not n.allow_broken_log and n.daemon.is_in_log(r'\*\*BROKEN\*\*'), "had BROKEN messages")
    map_node_error(nf.nodes, lambda n: not n.allow_warning and n.daemon.is_in_log(r' WARNING:'), "had warning messages")
    map_node_error(nf.nodes, checkReconnect, "had unexpected reconnections")
    map_node_error(nf.nodes, checkBadGossip, "had bad gossip messages")
    map_node_error(nf.nodes, lambda n: n.daemon.is_in_log('Bad reestablish'), "had bad reestablish")
    map_node_error(nf.nodes, lambda n: n.daemon.is_in_log('bad hsm request'), "had bad hsm requests")
    map_node_error(nf.nodes, lambda n: n.daemon.is_in_log(r'Accessing a null column'), "Accessing a null column")
    map_node_error(nf.nodes, checkMemleak, "had memleak messages")
    map_node_error(nf.nodes, lambda n: n.rc != 0 and not n.may_fail, "Node exited with return code {n.rc}")


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
    if node.daemon.is_in_log('Bad gossip order:'):
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


# Mapping from TEST_DB_PROVIDER env variable to class to be used
providers = {
    'sqlite3': SqliteDbProvider,
    'postgres': PostgresDbProvider,
}


@pytest.fixture
def db_provider(test_base_dir):
    provider = providers[os.getenv('TEST_DB_PROVIDER', 'sqlite3')](test_base_dir)
    provider.start()
    yield provider
    provider.stop()


@pytest.fixture
def executor(teardown_checks):
    ex = futures.ThreadPoolExecutor(max_workers=20)
    yield ex
    ex.shutdown(wait=False)


@pytest.fixture
def chainparams():
    """Return the chainparams for the TEST_NETWORK.

     - chain_hash is in network byte order, not the RPC return order.
     - example_addr doesn't belong to any node in the test (randomly generated)

    """
    chainparams = {
        'regtest': {
            "bip173_prefix": "bcrt",
            "elements": False,
            "name": "regtest",
            "p2sh_prefix": '2',
            "elements": False,
            "example_addr": "bcrt1qeyyk6sl5pr49ycpqyckvmttus5ttj25pd0zpvg",
            "feeoutput": False,
            "chain_hash": '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
        },
        'liquid-regtest': {
            "bip173_prefix": "ert",
            "elements": True,
            "name": "liquid-regtest",
            "p2sh_prefix": 'X',
            "elements": True,
            "example_addr": "ert1qjsesxflhs3632syhcz7llpfx20p5tr0kpllfve",
            "feeoutput": True,
            "chain_hash": "9f87eb580b9e5f11dc211e9fb66abb3699999044f8fe146801162393364286c6",
        }
    }

    return chainparams[env('TEST_NETWORK', 'regtest')]
