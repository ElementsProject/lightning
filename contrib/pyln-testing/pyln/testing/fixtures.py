from concurrent import futures
from pyln.testing.db import SqliteDbProvider, PostgresDbProvider
from pyln.testing.utils import NodeFactory, BitcoinD, ElementsD, env, LightningNode, TEST_DEBUG
from pyln.client import Millisatoshi
from typing import Dict

import json
import jsonschema  # type: ignore
import logging
import os
import pytest  # type: ignore
import re
import shutil
import string
import sys
import tempfile
import time


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
        except OSError:
            # Usually, this means that e.g. valgrind is still running.  Wait
            # a little and retry.
            files = [os.path.join(dp, f) for dp, dn, fn in os.walk(directory) for f in fn]
            print("Directory still contains files: ", files)
            print("... sleeping then retrying")
            time.sleep(10)
            shutil.rmtree(directory)
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


def _extra_validator(is_request: bool):
    """JSON Schema validator with additions for our specialized types"""
    def is_hex(checker, instance):
        """Hex string"""
        if not checker.is_type(instance, "string"):
            return False
        return all(c in string.hexdigits for c in instance)

    def is_u64(checker, instance):
        """64-bit integer"""
        if not checker.is_type(instance, "integer"):
            return False
        return instance >= 0 and instance < 2**64

    def is_u32(checker, instance):
        """32-bit integer"""
        if not checker.is_type(instance, "integer"):
            return False
        return instance >= 0 and instance < 2**32

    def is_u16(checker, instance):
        """16-bit integer"""
        if not checker.is_type(instance, "integer"):
            return False
        return instance >= 0 and instance < 2**16

    def is_u8(checker, instance):
        """8-bit integer"""
        if not checker.is_type(instance, "integer"):
            return False
        return instance >= 0 and instance < 2**8

    def is_short_channel_id(checker, instance):
        """Short channel id"""
        if not checker.is_type(instance, "string"):
            return False
        parts = instance.split("x")
        if len(parts) != 3:
            return False
        # May not be integers
        try:
            blocknum = int(parts[0])
            txnum = int(parts[1])
            outnum = int(parts[2])
        except ValueError:
            return False

        # BOLT #7:
        # ## Definition of `short_channel_id`
        #
        # The `short_channel_id` is the unique description of the funding transaction.
        # It is constructed as follows:
        # 1. the most significant 3 bytes: indicating the block height
        # 2. the next 3 bytes: indicating the transaction index within the block
        # 3. the least significant 2 bytes: indicating the output index that pays to the
        #    channel.
        return (blocknum >= 0 and blocknum < 2**24
                and txnum >= 0 and txnum < 2**24
                and outnum >= 0 and outnum < 2**16)

    def is_short_channel_id_dir(checker, instance):
        """Short channel id with direction"""
        if not checker.is_type(instance, "string"):
            return False
        if not instance.endswith("/0") and not instance.endswith("/1"):
            return False
        return is_short_channel_id(checker, instance[:-2])

    def is_outpoint(checker, instance):
        """Outpoint: txid and outnum"""
        if not checker.is_type(instance, "string"):
            return False
        parts = instance.split(":")
        if len(parts) != 2:
            return False
        if len(parts[0]) != 64 or any(c not in string.hexdigits for c in parts[0]):
            return False
        try:
            outnum = int(parts[1])
        except ValueError:
            return False
        return outnum < 2**32

    def is_feerate(checker, instance):
        """feerate string or number (optionally ending in perkw/perkb)"""
        if checker.is_type(instance, "integer"):
            return True
        if not checker.is_type(instance, "string"):
            return False
        if instance in ("urgent", "normal", "slow", "minimum"):
            return True
        if instance in ("opening", "mutual_close", "unilateral_close", "delayed_to_us", "htlc_resolution", "penalty", "min_acceptable", "max_acceptable"):
            return True
        if not instance.endswith("perkw") and not instance.endswith("perkb"):
            return False

        try:
            int(instance.rpartition("per")[0])
        except ValueError:
            return False
        return True

    def is_pubkey(checker, instance):
        """SEC1 encoded compressed pubkey"""
        if not checker.is_type(instance, "hex"):
            return False
        if len(instance) != 66:
            return False
        return instance[0:2] == "02" or instance[0:2] == "03"

    def is_32byte_hex(self, instance):
        """Fixed size 32 byte hex string

        This matches a variety of hex types: secrets, hashes, txid
        """
        return self.is_type(instance, "hex") and len(instance) == 64

    def is_signature(checker, instance):
        """DER encoded secp256k1 ECDSA signature"""
        if not checker.is_type(instance, "hex"):
            return False
        if len(instance) > 72 * 2:
            return False
        return True

    def is_bip340sig(checker, instance):
        """Hex encoded secp256k1 Schnorr signature"""
        if not checker.is_type(instance, "hex"):
            return False
        if len(instance) != 64 * 2:
            return False
        return True

    def is_msat_request(checker, instance):
        """msat fields can be raw integers, sats, btc."""
        try:
            Millisatoshi(instance)
            return True
        except TypeError:
            return False

    def is_msat_response(checker, instance):
        """A positive integer"""
        return type(instance) is int and instance >= 0

    def is_txid(checker, instance):
        """Bitcoin transaction ID"""
        if not checker.is_type(instance, "hex"):
            return False
        return len(instance) == 64

    def is_outputdesc(checker, instance):
        """Bitcoin-style output object, keys = destination, values = amount"""
        if not checker.is_type(instance, "object"):
            return False
        for k, v in instance.items():
            if not checker.is_type(k, "string"):
                return False
            if v != "all":
                if not is_msat_request(checker, v):
                    return False
        return True

    def is_msat_or_all(checker, instance):
        """msat field, or 'all'"""
        if instance == "all":
            return True
        return is_msat_request(checker, instance)

    def is_msat_or_any(checker, instance):
        """msat field, or 'any'"""
        if instance == "any":
            return True
        return is_msat_request(checker, instance)

    # "msat" for request can be many forms
    if is_request:
        is_msat = is_msat_request
    else:
        is_msat = is_msat_response
    type_checker = jsonschema.Draft7Validator.TYPE_CHECKER.redefine_many({
        "hex": is_hex,
        "hash": is_32byte_hex,
        "secret": is_32byte_hex,
        "u64": is_u64,
        "u32": is_u32,
        "u16": is_u16,
        "u8": is_u8,
        "pubkey": is_pubkey,
        "msat": is_msat,
        "msat_or_all": is_msat_or_all,
        "msat_or_any": is_msat_or_any,
        "txid": is_txid,
        "signature": is_signature,
        "bip340sig": is_bip340sig,
        "short_channel_id": is_short_channel_id,
        "short_channel_id_dir": is_short_channel_id_dir,
        "outpoint": is_outpoint,
        "feerate": is_feerate,
        "outputdesc": is_outputdesc,
    })

    return jsonschema.validators.extend(jsonschema.Draft7Validator,
                                        type_checker=type_checker)


def _load_schema(filename, is_request):
    """Load the schema from @filename and create a validator for it"""
    with open(filename, 'r') as f:
        return _extra_validator(is_request)(json.load(f))


@pytest.fixture(autouse=True)
def jsonschemas():
    """Load schema files if they exist: returns request/response schemas by pairs"""
    try:
        schemafiles = os.listdir('doc/schemas')
    except FileNotFoundError:
        schemafiles = []

    schemas = {}
    for fname in schemafiles:
        if fname.endswith('.schema.json'):
            base = fname.rpartition('.schema')[0]
            is_request = False
            index = 1
        elif fname.endswith('.request.json'):
            base = fname.rpartition('.request')[0]
            is_request = True
            index = 0
        else:
            continue
        if base not in schemas:
            schemas[base] = [None, None]
        schemas[base][index] = _load_schema(os.path.join('doc/schemas', fname),
                                            is_request)
    return schemas


@pytest.fixture
def node_factory(request, directory, test_name, bitcoind, executor, db_provider, teardown_checks, node_cls, jsonschemas):
    nf = NodeFactory(
        request,
        test_name,
        bitcoind,
        executor,
        directory=directory,
        db_provider=db_provider,
        node_cls=node_cls,
        jsonschemas=jsonschemas,
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
    if not ok:
        map_node_error(nf.nodes, prinErrlog, "some node failed unexpected, non-empty errlog file")


def getErrlog(node):
    for error_file in os.listdir(node.daemon.lightning_dir):
        if not re.fullmatch(r"errlog", error_file):
            continue
        with open(os.path.join(node.daemon.lightning_dir, error_file), 'r') as f:
            errors = f.read().strip()
            if errors:
                return errors, error_file
    return None, None


def prinErrlog(node):
    errors, fname = getErrlog(node)
    if errors:
        print("-" * 31, "stderr of node {} captured in {} file".format(node.daemon.prefix, fname), "-" * 32)
        print(errors)
        print("-" * 80)
    return 1 if errors else 0


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
    if node.may_reconnect:
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
            "example_addr": "bcrt1qeyyk6sl5pr49ycpqyckvmttus5ttj25pd0zpvg",
            "feeoutput": False,
            "chain_hash": '06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f',
        },
        'liquid-regtest': {
            "bip173_prefix": "ert",
            "elements": True,
            "name": "liquid-regtest",
            "p2sh_prefix": 'X',
            "example_addr": "ert1qjsesxflhs3632syhcz7llpfx20p5tr0kpllfve",
            "feeoutput": True,
            "chain_hash": "9f87eb580b9e5f11dc211e9fb66abb3699999044f8fe146801162393364286c6",
        }
    }

    return chainparams[env('TEST_NETWORK', 'regtest')]
