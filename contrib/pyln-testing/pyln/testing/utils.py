from bitcoin.core import COIN  # type: ignore
from bitcoin.rpc import RawProxy as BitcoinProxy  # type: ignore
from bitcoin.rpc import JSONRPCError
from contextlib import contextmanager
from pathlib import Path
from pyln.client import RpcError
from pyln.testing.btcproxy import BitcoinRpcProxy
from pyln.testing.gossip import GossipStore
from collections import OrderedDict
from decimal import Decimal
from pyln.client import LightningRpc
from pyln.client import Millisatoshi

import ephemeral_port_reserve  # type: ignore
import json
import logging
import lzma
import math
import os
import random
import re
import shutil
import sqlite3
import string
import struct
import subprocess
import sys
import threading
import time
import warnings

BITCOIND_CONFIG = {
    "regtest": 1,
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
    "fallbackfee": Decimal(1000) / COIN,
}


LIGHTNINGD_CONFIG = OrderedDict({
    "log-level": "debug",
    "cltv-delta": 6,
    "cltv-final": 5,
    "watchtime-blocks": 5,
    "rescan": 1,
    'disable-dns': None,
})

FUNDAMOUNT = 10**6


def env(name, default=None):
    """Access to environment variables

    Allows access to environment variables, falling back to config.vars (part
    of Core Lightning's `./configure` output), and finally falling back to a
    default value.

    """
    fname = 'config.vars'
    if os.path.exists(fname):
        lines = open(fname, 'r').readlines()
        config = dict([(line.rstrip().split('=', 1)) for line in lines])
    else:
        config = {}

    if name in os.environ:
        return os.environ[name]
    elif name in config:
        return config[name]
    else:
        return default


VALGRIND = env("VALGRIND") == "1"
TEST_NETWORK = env("TEST_NETWORK", 'regtest')
TEST_DEBUG = env("TEST_DEBUG", "0") == "1"
SLOW_MACHINE = env("SLOW_MACHINE", "0") == "1"
DEPRECATED_APIS = env("DEPRECATED_APIS", "0") == "1"
TIMEOUT = int(env("TIMEOUT", 180 if SLOW_MACHINE else 60))
EXPERIMENTAL_DUAL_FUND = env("EXPERIMENTAL_DUAL_FUND", "0") == "1"
EXPERIMENTAL_SPLICING = env("EXPERIMENTAL_SPLICING", "0") == "1"


def wait_for(success, timeout=TIMEOUT):
    start_time = time.time()
    interval = 0.25
    while not success():
        time_left = start_time + timeout - time.time()
        if time_left <= 0:
            raise ValueError("Timeout while waiting for {}".format(success))
        time.sleep(min(interval, time_left))
        interval *= 2
        if interval > 5:
            interval = 5


def write_config(filename, opts, regtest_opts=None, section_name='regtest'):
    with open(filename, 'w') as f:
        for k, v in opts.items():
            f.write("{}={}\n".format(k, v))
        if regtest_opts:
            f.write("[{}]\n".format(section_name))
            for k, v in regtest_opts.items():
                f.write("{}={}\n".format(k, v))


def scid_to_int(scid):
    """Convert a 1x2x3 scid to a raw integer"""
    blocknum, txnum, outnum = scid.split("x")

    # BOLT #7:
    # ## Definition of `short_channel_id`
    #
    # The `short_channel_id` is the unique description of the funding transaction.
    # It is constructed as follows:
    # 1. the most significant 3 bytes: indicating the block height
    # 2. the next 3 bytes: indicating the transaction index within the block
    # 3. the least significant 2 bytes: indicating the output index that pays to the
    #    channel.
    return (int(blocknum) << 40) | (int(txnum) << 16) | int(outnum)


def only_one(arr):
    """Many JSON RPC calls return an array; often we only expect a single entry
    """
    assert len(arr) == 1
    return arr[0]


def sync_blockheight(bitcoind, nodes):
    height = bitcoind.rpc.getblockchaininfo()['blocks']
    for n in nodes:
        wait_for(lambda: n.rpc.getinfo()['blockheight'] == height)


def mine_funding_to_announce(bitcoind, nodes, num_blocks=5, wait_for_mempool=0):
    """Mine blocks so a channel can be announced (5, if it's already
mined), but make sure we don't leave nodes behind who will reject the
announcement.  Not needed if there are only two nodes.

    """
    bitcoind.generate_block(num_blocks - 1, wait_for_mempool)
    sync_blockheight(bitcoind, nodes)
    bitcoind.generate_block(1)


def wait_channel_quiescent(n1, n2):
    wait_for(lambda: only_one(n1.rpc.listpeerchannels(n2.info['id'])['channels'])['htlcs'] == [])
    wait_for(lambda: only_one(n2.rpc.listpeerchannels(n1.info['id'])['channels'])['htlcs'] == [])


def get_tx_p2wsh_outnum(bitcoind, tx, amount):
    """Get output number of this tx which is p2wsh of amount"""
    decoded = bitcoind.rpc.decoderawtransaction(tx, True)

    for out in decoded['vout']:
        if out['scriptPubKey']['type'] == 'witness_v0_scripthash':
            if out['value'] == Decimal(amount) / 10**8:
                return out['n']

    return None


unused_port_lock = threading.Lock()
unused_port_set = set()


def reserve_unused_port():
    """Get an unused port: avoids handing out the same port unless it's been
    returned"""
    with unused_port_lock:
        while True:
            port = ephemeral_port_reserve.reserve()
            if port not in unused_port_set:
                break
        unused_port_set.add(port)

    return port


def drop_unused_port(port):
    unused_port_set.remove(port)


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir, verbose=True):
        self.logs = []
        self.env = os.environ.copy()
        self.proc = None
        self.outputDir = outputDir
        if not os.path.exists(outputDir):
            os.makedirs(outputDir)
        # Create and open them.
        self.stdout_filename = os.path.join(outputDir, "log")
        self.stderr_filename = os.path.join(outputDir, "errlog")
        self.stdout_write = open(self.stdout_filename, "wt")
        self.stderr_write = open(self.stderr_filename, "wt")
        self.stdout_read = open(self.stdout_filename, "rt")
        self.stderr_read = open(self.stderr_filename, "rt")
        self.logsearch_start = 0
        self.err_logs = []
        self.prefix = ""

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda line: False

    def start(self, stdin=None, stdout_redir=True, stderr_redir=True):
        """Start the underlying process and start monitoring it. If
        stdout_redir is false, you have to make sure logs go into
        outputDir/log

        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        if stdout_redir:
            stdout = self.stdout_write
        else:
            stdout = None
        if stderr_redir:
            stderr = self.stderr_write
            self.stderr_redir = True
        else:
            stderr = None
            self.stderr_redir = False

        self.proc = subprocess.Popen(self.cmd_line,
                                     stdin=stdin,
                                     stdout=stdout,
                                     stderr=stderr,
                                     env=self.env)

    def stop(self, timeout=10):
        self.proc.terminate()

        # Now give it some time to react to the signal
        rc = self.proc.wait(timeout)

        if rc is None:
            self.proc.kill()

        self.proc.wait()
        return self.proc.returncode

    def kill(self):
        """Kill process without giving it warning."""
        self.proc.kill()
        self.proc.wait()

    def logs_catchup(self):
        """Save the latest stdout / stderr contents; return true if we got anything.
        """
        new_stdout = self.stdout_read.readlines()
        if self.verbose:
            for line in new_stdout:
                sys.stdout.write("{}: {}".format(self.prefix, line))
        self.logs += [l.rstrip() for l in new_stdout]
        new_stderr = self.stderr_read.readlines()
        if self.verbose:
            for line in new_stderr:
                sys.stderr.write("{}-stderr: {}".format(self.prefix, line))
        self.err_logs += [l.rstrip() for l in new_stderr]
        return len(new_stdout) > 0 or len(new_stderr) > 0

    def is_in_log(self, regex, start=0):
        """Look for `regex` in the logs."""

        self.logs_catchup()
        ex = re.compile(regex)
        for l in self.logs[start:]:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return l

        logging.debug("Did not find '%s' in logs", regex)
        return None

    def is_in_stderr(self, regex):
        """Look for `regex` in stderr."""

        assert self.stderr_redir
        self.logs_catchup()
        ex = re.compile(regex)
        for l in self.err_logs:
            if ex.search(l):
                logging.debug("Found '%s' in stderr", regex)
                return l

        logging.debug("Did not find '%s' in stderr", regex)
        return None

    def wait_for_logs(self, regexs, timeout=TIMEOUT):
        """Look for `regexs` in the logs.

        The logs contain tailed stdout of the process. We look for each regex
        in `regexs`, starting from `logsearch_start` which normally is the
        position of the last found entry of a previous wait-for logs call.
        The ordering inside `regexs` doesn't matter.

        We fail if the timeout is exceeded or if the underlying process
        exits before all the `regexs` were found.

        If timeout is None, no time-out is applied.
        """
        logging.debug("Waiting for {} in the logs".format(regexs))
        exs = [re.compile(r) for r in regexs]
        start_time = time.time()
        while True:
            if self.logsearch_start >= len(self.logs):
                if not self.logs_catchup():
                    time.sleep(0.25)

                if timeout is not None and time.time() > start_time + timeout:
                    print("Time-out: can't find {} in logs".format(exs))
                    for r in exs:
                        if self.is_in_log(r):
                            print("({} was previously in logs!)".format(r))
                    raise TimeoutError('Unable to find "{}" in logs.'.format(exs))
                continue

            line = self.logs[self.logsearch_start]
            self.logsearch_start += 1
            for r in exs.copy():
                if r.search(line):
                    logging.debug("Found '%s' in logs", r)
                    exs.remove(r)
                    if len(exs) == 0:
                        return line
                    # Don't match same line with different regexs!
                    break

    def wait_for_log(self, regex, timeout=TIMEOUT):
        """Look for `regex` in the logs.

        Convenience wrapper for the common case of only seeking a single entry.
        """
        return self.wait_for_logs([regex], timeout)


class SimpleBitcoinProxy:
    """Wrapper for BitcoinProxy to reconnect.

    Long wait times between calls to the Bitcoin RPC could result in
    `bitcoind` closing the connection, so here we just create
    throwaway connections. This is easier than to reach into the RPC
    library to close, reopen and reauth upon failure.
    """
    def __init__(self, btc_conf_file, *args, **kwargs):
        self.__btc_conf_file__ = btc_conf_file

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError

        # Create a callable to do the actual call
        proxy = BitcoinProxy(btc_conf_file=self.__btc_conf_file__)

        def f(*args):
            logging.debug("Calling {name} with arguments {args}".format(
                name=name,
                args=args
            ))
            res = proxy._call(name, *args)
            logging.debug("Result for {name} call: {res}".format(
                name=name,
                res=res,
            ))
            return res

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class BitcoinD(TailableProc):

    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=None):
        TailableProc.__init__(self, bitcoin_dir, verbose=False)

        if rpcport is None:
            self.reserved_rpcport = reserve_unused_port()
            rpcport = self.reserved_rpcport
        else:
            self.reserved_rpcport = None

        self.bitcoin_dir = bitcoin_dir
        self.rpcport = rpcport
        self.prefix = 'bitcoind'

        regtestdir = os.path.join(bitcoin_dir, 'regtest')
        if not os.path.exists(regtestdir):
            os.makedirs(regtestdir)

        self.cmd_line = [
            'bitcoind',
            '-datadir={}'.format(bitcoin_dir),
            '-printtoconsole',
            '-server',
            '-logtimestamps',
            '-nolisten',
            '-txindex',
            '-nowallet',
            '-addresstype=bech32',
            '-debug=mempool',
            '-debug=mempoolrej',
            '-debug=rpc',
            '-debug=validation',
        ]
        # For up to and including 0.16.1, this needs to be in main section.
        BITCOIND_CONFIG['rpcport'] = rpcport
        # For after 0.16.1 (eg. 3f398d7a17f136cd4a67998406ca41a124ae2966), this
        # needs its own [regtest] section.
        BITCOIND_REGTEST = {'rpcport': rpcport}
        self.conf_file = os.path.join(bitcoin_dir, 'bitcoin.conf')
        write_config(self.conf_file, BITCOIND_CONFIG, BITCOIND_REGTEST)
        self.rpc = SimpleBitcoinProxy(btc_conf_file=self.conf_file)
        self.proxies = []

    def __del__(self):
        if self.reserved_rpcport is not None:
            drop_unused_port(self.reserved_rpcport)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=TIMEOUT)

        logging.info("BitcoinD started")
        try:
            self.rpc.createwallet("lightningd-tests")
        except JSONRPCError:
            self.rpc.loadwallet("lightningd-tests")

    def stop(self):
        for p in self.proxies:
            p.stop()
        self.rpc.stop()
        return TailableProc.stop(self)

    def get_proxy(self):
        proxy = BitcoinRpcProxy(self)
        self.proxies.append(proxy)
        proxy.start()
        return proxy

    # wait_for_mempool can be used to wait for the mempool before generating blocks:
    # True := wait for at least 1 transation
    # int > 0 := wait for at least N transactions
    # 'tx_id' := wait for one transaction id given as a string
    # ['tx_id1', 'tx_id2'] := wait until all of the specified transaction IDs
    def generate_block(self, numblocks=1, wait_for_mempool=0, to_addr=None, needfeerate=None):
        if wait_for_mempool:
            if isinstance(wait_for_mempool, str):
                wait_for_mempool = [wait_for_mempool]
            if isinstance(wait_for_mempool, list):
                wait_for(lambda: all(txid in self.rpc.getrawmempool() for txid in wait_for_mempool))
            else:
                wait_for(lambda: len(self.rpc.getrawmempool()) >= wait_for_mempool)

        mempool = self.rpc.getrawmempool(True)
        logging.debug("Generating {numblocks}, confirming {lenmempool} transactions: {mempool}".format(
            numblocks=numblocks,
            mempool=mempool,
            lenmempool=len(mempool),
        ))

        # As of 0.16, generate() is removed; use generatetoaddress.
        if to_addr is None:
            to_addr = self.rpc.getnewaddress()

        # We assume all-or-nothing.
        if needfeerate is not None:
            assert numblocks == 1
            # If any tx including ancestors is above the given feerate, mine all.
            for txid, details in mempool.items():
                feerate = float(details['fees']['ancestor']) * 100_000_000 / (float(details['ancestorsize']) * 4 / 1000)
                if feerate >= needfeerate:
                    return self.rpc.generatetoaddress(numblocks, to_addr)
                else:
                    print(f"Feerate {feerate} for {txid} below {needfeerate}")

            # Otherwise, mine none.
            return self.rpc.generateblock(to_addr, [])

        return self.rpc.generatetoaddress(numblocks, to_addr)

    def simple_reorg(self, height, shift=0):
        """
        Reorganize chain by creating a fork at height=[height] and re-mine all mempool
        transactions into [height + shift], where shift >= 0. Returns hashes of generated
        blocks.

        Note that tx's that become invalid at [height] (because coin maturity, locktime
        etc.) are removed from mempool. The length of the new chain will be original + 1
        OR original + [shift], whichever is larger.

        For example: to push tx's backward from height h1 to h2 < h1, use [height]=h2.

        Or to change the txindex of tx's at height h1:
        1. A block at height h2 < h1 should contain a non-coinbase tx that can be pulled
           forward to h1.
        2. Set [height]=h2 and [shift]= h1-h2
        """
        hashes = []
        fee_delta = 1000000
        orig_len = self.rpc.getblockcount()
        old_hash = self.rpc.getblockhash(height)
        final_len = height + shift if height + shift > orig_len else 1 + orig_len
        # TODO: raise error for insane args?

        self.rpc.invalidateblock(old_hash)
        self.wait_for_log(r'InvalidChainFound: invalid block=.*  height={}'.format(height))
        memp = self.rpc.getrawmempool()

        if shift == 0:
            hashes += self.generate_block(1 + final_len - height)
        else:
            for txid in memp:
                # lower priority (to effective feerate=0) so they are not mined
                self.rpc.prioritisetransaction(txid, None, -fee_delta)
            hashes += self.generate_block(shift)

            for txid in memp:
                # restore priority so they are mined
                self.rpc.prioritisetransaction(txid, None, fee_delta)
            hashes += self.generate_block(1 + final_len - (height + shift))
        self.wait_for_log(r'UpdateTip: new best=.* height={}'.format(final_len))
        return hashes

    def getnewaddress(self):
        return self.rpc.getnewaddress()


class ElementsD(BitcoinD):
    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=None):
        config = BITCOIND_CONFIG.copy()
        if 'regtest' in config:
            del config['regtest']

        config['chain'] = 'liquid-regtest'
        BitcoinD.__init__(self, bitcoin_dir, rpcport)

        self.cmd_line = [
            'elementsd',
            '-datadir={}'.format(bitcoin_dir),
            '-printtoconsole',
            '-server',
            '-logtimestamps',
            '-nolisten',
            '-nowallet',
            '-validatepegin=0',
            '-con_blocksubsidy=5000000000',
            '-acceptnonstdtxn=1',  # FIXME Issues such as dust limit interacting with anchors
        ]
        conf_file = os.path.join(bitcoin_dir, 'elements.conf')
        config['rpcport'] = self.rpcport
        BITCOIND_REGTEST = {'rpcport': self.rpcport}
        write_config(conf_file, config, BITCOIND_REGTEST, section_name='liquid-regtest')
        self.conf_file = conf_file
        self.rpc = SimpleBitcoinProxy(btc_conf_file=self.conf_file)
        self.prefix = 'elementsd'

    def getnewaddress(self):
        """Need to get an address and then make it unconfidential
        """
        addr = self.rpc.getnewaddress()
        info = self.rpc.getaddressinfo(addr)
        return info['unconfidential']


class LightningD(TailableProc):
    def __init__(
            self,
            lightning_dir,
            bitcoindproxy,
            port=9735,
            random_hsm=False,
            node_id=0,
            grpc_port=None
    ):
        # We handle our own version of verbose, below.
        TailableProc.__init__(self, lightning_dir, verbose=False)
        self.executable = 'lightningd'
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_prefix = []
        self.disconnect_file = None

        self.rpcproxy = bitcoindproxy
        self.env['CLN_PLUGIN_LOG'] = "cln_plugin=trace,cln_rpc=trace,cln_grpc=trace,debug"

        self.opts = LIGHTNINGD_CONFIG.copy()
        opts = {
            'lightning-dir': lightning_dir,
            'addr': '127.0.0.1:{}'.format(port),
            'allow-deprecated-apis': '{}'.format("true" if DEPRECATED_APIS
                                                 else "false"),
            'network': TEST_NETWORK,
            'ignore-fee-limits': 'false',
            'bitcoin-rpcuser': BITCOIND_CONFIG['rpcuser'],
            'bitcoin-rpcpassword': BITCOIND_CONFIG['rpcpassword'],

            # Make sure we don't touch any existing config files in the user's $HOME
            'bitcoin-datadir': lightning_dir,
        }

        if grpc_port is not None:
            opts['grpc-port'] = grpc_port

        for k, v in opts.items():
            self.opts[k] = v

        if not os.path.exists(os.path.join(lightning_dir, TEST_NETWORK)):
            os.makedirs(os.path.join(lightning_dir, TEST_NETWORK))

        # Last 32-bytes of final part of dir -> seed.
        seed = (bytes(re.search('([^/]+)/*$', lightning_dir).group(1), encoding='utf-8') + bytes(32))[:32]
        if not random_hsm:
            with open(os.path.join(lightning_dir, TEST_NETWORK, 'hsm_secret'), 'wb') as f:
                f.write(seed)
        self.opts['dev-fast-gossip'] = None
        self.opts['dev-bitcoind-poll'] = 1
        self.prefix = 'lightningd-%d' % (node_id)
        # Log to stdout so we see it in failure cases, and log file for TailableProc.
        self.opts['log-file'] = ['-', os.path.join(lightning_dir, "log")]
        self.opts['log-prefix'] = self.prefix + ' '
        # In case you want specific ordering!
        self.early_opts = ['--developer']

    def cleanup(self):
        # To force blackhole to exit, disconnect file must be truncated!
        if self.disconnect_file:
            with open(self.disconnect_file, "w") as f:
                f.truncate()

    @property
    def cmd_line(self):

        opts = []
        for k, v in self.opts.items():
            if v is None:
                opts.append("--{}".format(k))
            elif isinstance(v, list):
                for i in v:
                    opts.append("--{}={}".format(k, i))
            else:
                opts.append("--{}={}".format(k, v))

        return self.cmd_prefix + [self.executable] + self.early_opts + opts

    def start(self, stdin=None, wait_for_initialized=True, stderr_redir=False):
        self.opts['bitcoin-rpcport'] = self.rpcproxy.rpcport
        TailableProc.start(self, stdin, stdout_redir=False, stderr_redir=stderr_redir)
        if wait_for_initialized:
            self.wait_for_log("Server started with public key")
        logging.info("LightningD started")

    def wait(self, timeout=TIMEOUT):
        """Wait for the daemon to stop for up to timeout seconds

        Returns the returncode of the process, None if the process did
        not return before the timeout triggers.
        """
        self.proc.wait(timeout)
        return self.proc.returncode


class PrettyPrintingLightningRpc(LightningRpc):
    """A version of the LightningRpc that pretty-prints calls and results.

    Useful when debugging based on logs, and less painful to the
    eyes. It has some overhead since we re-serialize the request and
    result to json in order to pretty print it.

    Also validates (optional) schemas for us.
    """
    def __init__(self, socket_path, executor=None, logger=logging,
                 patch_json=True, jsonschemas={}):
        super().__init__(
            socket_path,
            executor,
            logger,
            patch_json,
        )
        self.jsonschemas = jsonschemas
        self.check_request_schemas = True

    def call(self, method, payload=None, cmdprefix=None, filter=None):
        id = self.get_json_id(method, cmdprefix)
        schemas = self.jsonschemas.get(method)
        self.logger.debug(json.dumps({
            "id": id,
            "method": method,
            "params": payload,
            "filter": filter,
        }, indent=2))

        # We only check payloads which are dicts, which is what we
        # usually use: there are some cases which tests [] params,
        # which we ignore.
        if schemas and schemas[0] and isinstance(payload, dict) and self.check_request_schemas:
            # fields which are None are explicitly removed, so do that now
            testpayload = {}
            for k, v in payload.items():
                if v is not None:
                    testpayload[k] = v
            schemas[0].validate(testpayload)

        res = LightningRpc.call(self, method, payload, cmdprefix, filter)
        self.logger.debug(json.dumps({
            "id": id,
            "result": res
        }, indent=2))

        # FIXME: if filter set, just remove "required" from schemas?
        if schemas and schemas[1] and filter is None and self._filter is None:
            schemas[1].validate(res)

        return res


class LightningNode(object):
    def __init__(self, node_id, lightning_dir, bitcoind, executor, valgrind, may_fail=False,
                 may_reconnect=False,
                 allow_broken_log=False,
                 allow_warning=False,
                 allow_bad_gossip=False,
                 db=None, port=None, disconnect=None, random_hsm=None, options=None,
                 jsonschemas={},
                 valgrind_plugins=True,
                 **kwargs):
        self.bitcoin = bitcoind
        self.executor = executor
        self.may_fail = may_fail
        self.may_reconnect = may_reconnect
        self.allow_broken_log = allow_broken_log
        self.allow_bad_gossip = allow_bad_gossip
        self.allow_warning = allow_warning
        self.db = db
        self.lightning_dir = Path(lightning_dir)

        # Assume successful exit
        self.rc = 0

        # Ensure we have an RPC we can use to talk to the node
        self._create_rpc(jsonschemas)

        self.gossip_store = GossipStore(Path(lightning_dir, TEST_NETWORK, "gossip_store"))

        self.daemon = LightningD(
            lightning_dir, bitcoindproxy=bitcoind.get_proxy(),
            port=port, random_hsm=random_hsm, node_id=node_id,
            grpc_port=self.grpc_port,
        )

        # If we have a disconnect string, dump it to a file for daemon.
        if disconnect:
            self.daemon.disconnect_file = os.path.join(lightning_dir, TEST_NETWORK, "dev_disconnect")
            with open(self.daemon.disconnect_file, "w") as f:
                f.write("\n".join(disconnect))
            self.daemon.opts["dev-disconnect"] = "dev_disconnect"

        # Various developer options let us be more aggressive
        self.daemon.opts["dev-fail-on-subdaemon-fail"] = None
        # Don't run --version on every subdaemon if we're valgrinding and slow.
        if SLOW_MACHINE and VALGRIND:
            self.daemon.opts["dev-no-version-checks"] = None
        if os.getenv("DEBUG_SUBD"):
            self.daemon.opts["dev-debugger"] = os.getenv("DEBUG_SUBD")
        if valgrind:
            self.daemon.env["LIGHTNINGD_DEV_NO_BACKTRACE"] = "1"
            self.daemon.opts["dev-no-plugin-checksum"] = None
        else:
            # Under valgrind, scanning can access uninitialized mem.
            self.daemon.env["LIGHTNINGD_DEV_MEMLEAK"] = "1"
        if not may_reconnect:
            self.daemon.opts["dev-no-reconnect"] = None
        if EXPERIMENTAL_DUAL_FUND:
            self.daemon.opts["experimental-dual-fund"] = None
        if EXPERIMENTAL_SPLICING:
            self.daemon.opts["experimental-splicing"] = None

        if options is not None:
            self.daemon.opts.update(options)
        dsn = db.get_dsn()
        if dsn is not None:
            self.daemon.opts['wallet'] = dsn
        if valgrind:
            trace_skip_pattern = '*python*,*bitcoin-cli*,*elements-cli*,*cln-*'
            if not valgrind_plugins:
                trace_skip_pattern += ',*plugins*'
            self.daemon.cmd_prefix = [
                'valgrind',
                '-q',
                '--trace-children=yes',
                '--trace-children-skip={}'.format(trace_skip_pattern),
                '--error-exitcode=7',
                '--log-file={}/valgrind-errors.%p'.format(self.daemon.lightning_dir)
            ]
            # Reduce precision of errors, speeding startup and reducing memory greatly:
            if SLOW_MACHINE:
                self.daemon.cmd_prefix += ['--read-inline-info=no']

    def _create_rpc(self, jsonschemas):
        """Prepares anything related to the RPC.
        """
        if os.environ.get('CLN_TEST_GRPC') == '1':
            logging.info("Switching to GRPC based RPC for tests")
            self._create_grpc_rpc()
        else:
            self._create_jsonrpc_rpc(jsonschemas)

    def _create_grpc_rpc(self):
        from pyln.testing import grpc
        self.grpc_port = reserve_unused_port()
        d = self.lightning_dir / TEST_NETWORK
        d.mkdir(parents=True, exist_ok=True)

        # Copy all the certificates and keys into place:
        with (d / "ca.pem").open(mode='wb') as f:
            f.write(grpc.DUMMY_CA_PEM)

        with (d / "ca-key.pem").open(mode='wb') as f:
            f.write(grpc.DUMMY_CA_KEY_PEM)

        # Now the node will actually start up and use them, so we can
        # create the RPC instance.
        self.rpc = grpc.LightningGrpc(
            host='localhost',
            port=self.grpc_port,
            root_certificates=grpc.DUMMY_CA_PEM,
            private_key=grpc.DUMMY_CLIENT_KEY_PEM,
            certificate_chain=grpc.DUMMY_CLIENT_PEM
        )

    def _create_jsonrpc_rpc(self, jsonschemas):
        socket_path = self.lightning_dir / TEST_NETWORK / "lightning-rpc"
        self.grpc_port = None

        self.rpc = PrettyPrintingLightningRpc(
            str(socket_path),
            self.executor,
            jsonschemas=jsonschemas
        )

    @property
    def grpc(self):
        """Tiny helper to return a grpc stub if grpc was configured.
        """
        # Before doing anything let's see if we have a grpc-port at all
        try:
            grpc_port = int(filter(
                lambda v: v[0] == 'grpc-port',
                self.daemon.opts.items()
            ).__next__()[1])
        except Exception:
            raise ValueError("grpc-port is not specified, can't connect over grpc")

        import grpc
        p = Path(self.daemon.lightning_dir) / TEST_NETWORK
        cert, key, ca = [f.open('rb').read() for f in [
            p / 'client.pem',
            p / 'client-key.pem',
            p / "ca.pem"]]
        creds = grpc.ssl_channel_credentials(
            root_certificates=ca,
            private_key=key,
            certificate_chain=cert,
        )

        channel = grpc.secure_channel(
            f"localhost:{grpc_port}",
            creds,
            options=(('grpc.ssl_target_name_override', 'cln'),)
        )
        from pyln import grpc as clnpb
        return clnpb.NodeStub(channel)

    def connect(self, remote_node):
        self.rpc.connect(remote_node.info['id'], '127.0.0.1', remote_node.port)

    def is_connected(self, remote_node):
        return remote_node.info['id'] in [p['id'] for p in self.rpc.listpeers()['peers']]

    def openchannel(self, remote_node, capacity=FUNDAMOUNT, addrtype="bech32", confirm=True, wait_for_announce=True, connect=True):
        addr, wallettxid = self.fundwallet(10 * capacity, addrtype)

        # connect if necessary
        if connect and not self.is_connected(remote_node):
            self.connect(remote_node)

        res = self.rpc.fundchannel(remote_node.info['id'], capacity)

        if confirm or wait_for_announce:
            self.bitcoin.generate_block(1, wait_for_mempool=res['txid'])

        if wait_for_announce:
            self.bitcoin.generate_block(5)
            wait_for(lambda: ['alias' in e for e in self.rpc.listnodes(remote_node.info['id'])['nodes']])

        return {'address': addr, 'wallettxid': wallettxid, 'fundingtx': res['tx']}

    def fundwallet(self, sats, addrtype="bech32", mine_block=True):
        addr = self.rpc.newaddr(addrtype)[addrtype]
        txid = self.bitcoin.rpc.sendtoaddress(addr, sats / 10**8)
        if mine_block:
            self.bitcoin.generate_block(1)
            self.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.format(txid))
        return addr, txid

    def fundbalancedchannel(self, remote_node, total_capacity=FUNDAMOUNT, announce=True):
        '''
        Creates a perfectly-balanced channel, as all things should be.
        '''
        if isinstance(total_capacity, Millisatoshi):
            total_capacity = int(total_capacity.to_satoshi())
        else:
            total_capacity = int(total_capacity)

        self.fundwallet(total_capacity + 10000)

        if remote_node.config('experimental-dual-fund'):
            remote_node.fundwallet(total_capacity + 10000)
            # We cut the total_capacity in half, since the peer's
            # expected to contribute that same amount
            chan_capacity = total_capacity // 2
            total_capacity = chan_capacity * 2
            # Tell the node to equally dual-fund the channel
            remote_node.rpc.call('funderupdate', {'policy': 'match',
                                                  'policy_mod': 100,
                                                  'fuzz_percent': 0})
        else:
            chan_capacity = total_capacity

        # connect if necessary
        if not self.is_connected(remote_node):
            self.connect(remote_node)

        res = self.rpc.fundchannel(remote_node.info['id'], chan_capacity, feerate='slow', minconf=0, announce=announce, push_msat=Millisatoshi(chan_capacity * 500))
        blockid = self.bitcoin.generate_block(1, wait_for_mempool=res['txid'])[0]

        # Generate the scid.
        for i, txid in enumerate(self.bitcoin.rpc.getblock(blockid)['tx']):
            if txid == res['txid']:
                txnum = i

        return '{}x{}x{}'.format(self.bitcoin.rpc.getblockcount(), txnum, res['outnum'])

    def db_query(self, query):
        return self.db.query(query)

    # Assumes node is stopped!
    def db_manip(self, query):
        db = sqlite3.connect(os.path.join(self.daemon.lightning_dir, TEST_NETWORK, "lightningd.sqlite3"))
        db.row_factory = sqlite3.Row
        c = db.cursor()
        c.execute(query)
        db.commit()
        c.close()
        db.close()

    def is_synced_with_bitcoin(self, info=None):
        if info is None:
            info = self.rpc.getinfo()
        return 'warning_bitcoind_sync' not in info and 'warning_lightningd_sync' not in info

    def start(self, wait_for_bitcoind_sync=True, stderr_redir=False):
        self.daemon.start(stderr_redir=stderr_redir)
        # Cache `getinfo`, we'll be using it a lot
        self.info = self.rpc.getinfo()
        # This shortcut is sufficient for our simple tests.
        self.port = self.info['binding'][0]['port']
        self.gossip_store.open()  # Reopen the gossip_store now that we should have one
        if wait_for_bitcoind_sync and not self.is_synced_with_bitcoin(self.info):
            wait_for(lambda: self.is_synced_with_bitcoin())

    def stop(self, timeout=10):
        """ Attempt to do a clean shutdown, but kill if it hangs
        """

        # Tell the daemon to stop
        try:
            # May fail if the process already died
            self.rpc.stop()
        except Exception:
            pass

        self.rc = self.daemon.wait(timeout)

        # If it did not stop be more insistent
        if self.rc is None:
            self.rc = self.daemon.stop()

        self.daemon.cleanup()

        if self.rc != 0 and not self.may_fail:
            raise ValueError("Node did not exit cleanly, rc={}".format(self.rc))
        else:
            return self.rc

    def restart(self, timeout=10, clean=True):
        """Stop and restart the lightning node.

        Keyword arguments:
        timeout: number of seconds to wait for a shutdown
        clean: whether to issue a `stop` RPC command before killing
        """
        if clean:
            self.stop(timeout)
        else:
            self.daemon.stop()

        self.start()

    def fundchannel(self, l2, amount=FUNDAMOUNT, wait_for_active=True,
                    announce_channel=True, **kwargs):
        # Give yourself some funds to work with
        addr = self.rpc.newaddr()['bech32']

        def has_funds_on_addr(addr):
            """Check if the given address has funds in the internal wallet.
            """
            outs = self.rpc.listfunds()['outputs']
            addrs = [o['address'] for o in outs]
            return addr in addrs

        # We should not have funds on that address yet, we just generated it.
        assert(not has_funds_on_addr(addr))

        self.bitcoin.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
        self.bitcoin.generate_block(1)

        # Now we should.
        wait_for(lambda: has_funds_on_addr(addr))

        # connect if necessary
        if not self.is_connected(l2):
            self.connect(l2)

        # Now go ahead and open a channel
        res = self.rpc.fundchannel(l2.info['id'], amount,
                                   announce=announce_channel,
                                   **kwargs)
        blockid = self.bitcoin.generate_block(1, wait_for_mempool=res['txid'])[0]

        for i, txid in enumerate(self.bitcoin.rpc.getblock(blockid)['tx']):
            if txid == res['txid']:
                txnum = i

        scid = "{}x{}x{}".format(self.bitcoin.rpc.getblockcount(),
                                 txnum, res['outnum'])

        if wait_for_active:
            self.wait_local_channel_active(scid)
            l2.wait_local_channel_active(scid)

        return scid, res

    def subd_pid(self, subd, peerid=None):
        """Get the process id of the given subdaemon, eg channeld or gossipd"""
        if peerid:
            ex = re.compile(r'{}-.*{}.*: pid ([0-9]*),'
                            .format(peerid, subd))
        else:
            ex = re.compile('{}-.*: pid ([0-9]*),'.format(subd))
        # Make sure we get latest one if it's restarted!
        for l in reversed(self.daemon.logs):
            group = ex.search(l)
            if group:
                return group.group(1)
        raise ValueError("No daemon {} found".format(subd))

    def channel_state(self, other):
        """Return the state of the channel to the other node.

        Returns None if there is no such peer, or a channel hasn't been funded
        yet.

        """
        peerchannels = self.rpc.listpeerchannels(other.info['id'])['channels']
        if not peerchannels:
            return None
        channel = peerchannels[0]
        return channel['state']

    def get_channel_scid(self, other):
        """Get the short_channel_id for the channel to the other node.
        """
        peerchannels = self.rpc.listpeerchannels(other.info['id'])['channels']
        if not peerchannels:
            return None
        channel = peerchannels[0]
        return channel['short_channel_id']

    def get_channel_id(self, other):
        """Get the channel_id for the channel to the other node.
        """
        channels = self.rpc.listpeerchannels(other.info['id'])['channels']
        if len(channels) == 0:
            return None
        return channels[0]['channel_id']

    def is_local_channel_active(self, scid):
        """Is the local channel @scid usable?"""
        channels = self.rpc.listpeerchannels()['channels']
        return [c['state'] in ('CHANNELD_NORMAL', 'CHANNELD_AWAITING_SPLICE') for c in channels if c.get('short_channel_id') == scid] == [True]

    def wait_local_channel_active(self, scid):
        wait_for(lambda: self.is_local_channel_active(scid))

    def is_channel_active(self, chanid):
        """Does gossip show this channel as enabled both ways?"""
        channels = self.rpc.listchannels(chanid)['channels']
        active = [(c['short_channel_id'], c['channel_flags']) for c in channels if c['active']]
        return (chanid, 0) in active and (chanid, 1) in active

    def wait_for_channel_onchain(self, peerid):
        txid = only_one(self.rpc.listpeerchannels(peerid)['channels'])['scratch_txid']
        wait_for(lambda: txid in self.bitcoin.rpc.getrawmempool())

    def wait_channel_active(self, scid):
        wait_for(lambda: self.is_channel_active(scid))

    # This waits until gossipd sees channel_update in both directions
    # (or for local channels, at least a local announcement)
    def wait_for_channel_updates(self, scids):
        # Could happen in any order...
        self.daemon.wait_for_logs(['Received channel_update for channel {}/0'.format(c)
                                   for c in scids]
                                  + ['Received channel_update for channel {}/1'.format(c)
                                     for c in scids])

    def wait_for_route(self, destination, timeout=TIMEOUT):
        """ Wait for a route to the destination to become available.
        """
        start_time = time.time()
        while time.time() < start_time + timeout:
            try:
                self.rpc.getroute(destination.info['id'], 1, 1)
                return True
            except Exception:
                time.sleep(1)
        if time.time() > start_time + timeout:
            raise ValueError("Error waiting for a route to destination {}".format(destination))

    # This helper waits for all HTLCs to settle
    # `scids` can be a list of strings. If unset wait on all channels.
    def wait_for_htlcs(self, scids=None):
        peers = self.rpc.listpeers()['peers']
        for peer in peers:
            channels = self.rpc.listpeerchannels(peer['id'])['channels']
            for idx, channel in enumerate(channels):
                if scids is not None and channel['short_channel_id'] not in scids:
                    continue
                if 'htlcs' in channel:
                    wait_for(lambda: len(self.rpc.listpeerchannels(peer["id"])['channels'][idx]['htlcs']) == 0)

    # This sends money to a directly connected peer
    def pay(self, dst, amt, label=None):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))

        # check we are connected
        dst_id = dst.info['id']
        assert len(self.rpc.listpeers(dst_id).get('peers')) == 1

        # make an invoice
        inv = dst.rpc.invoice(amt, label, label)
        # FIXME: pre 0.10.1 invoice calls didn't have payment_secret field
        psecret = dst.rpc.decodepay(inv['bolt11'])['payment_secret']
        rhash = inv['payment_hash']
        invoices = dst.rpc.listinvoices(label)['invoices']
        assert len(invoices) == 1 and invoices[0]['status'] == 'unpaid'

        # Pick first normal channel.
        scid = [c['short_channel_id'] for c in self.rpc.listpeerchannels(dst_id)['channels']
                if c['state'] == 'CHANNELD_NORMAL'][0]

        routestep = {
            'amount_msat': amt,
            'id': dst_id,
            'delay': 5,
            'channel': scid
        }

        # sendpay is async now
        self.rpc.sendpay([routestep], rhash, payment_secret=psecret, bolt11=inv['bolt11'])
        # wait for sendpay to comply
        result = self.rpc.waitsendpay(rhash)
        assert(result.get('status') == 'complete')

        # Make sure they're all settled, in case we quickly mine blocks!
        dst.wait_for_htlcs()

    # This helper sends all money to a peer until even 1 msat can't get through.
    def drain(self, peer):
        total = 0
        msat = 4294967295  # Max payment size in some configs
        while msat != 0:
            try:
                logging.debug("Drain step with size={}".format(msat))
                self.pay(peer, msat)
                total += msat
            except RpcError as e:
                logging.debug("Got an exception while draining channel: {}".format(e))
                msat //= 2
        logging.debug("Draining complete after sending a total of {}msats".format(total))
        return total

    # Note: this feeds through the smoother in update_feerate, so changing
    # it on a running daemon may not give expected result!
    def set_feerates(self, feerates, wait_for_effect=True):
        # (bitcoind returns bitcoin per kb, so these are * 4)

        def mock_estimatesmartfee(r):
            params = r['params']
            if params == [2, 'CONSERVATIVE']:
                feerate = feerates[0] * 4
            elif params == [6, 'ECONOMICAL']:
                feerate = feerates[1] * 4
            elif params == [12, 'ECONOMICAL']:
                feerate = feerates[2] * 4
            elif params == [100, 'ECONOMICAL']:
                feerate = feerates[3] * 4
            else:
                warnings.warn("Don't have a feerate set for {}/{}.".format(
                    params[0], params[1],
                ))
                feerate = 42
            return {
                'id': r['id'],
                'error': None,
                'result': {
                    'feerate': Decimal(feerate) / 10**8
                },
            }
        self.daemon.rpcproxy.mock_rpc('estimatesmartfee', mock_estimatesmartfee)

        # Technically, this waits until it's called, not until it's processed.
        # We wait until all four levels have been called.
        if wait_for_effect:
            wait_for(lambda:
                     self.daemon.rpcproxy.mock_counts['estimatesmartfee'] >= 4)

    # force new feerates by restarting and thus skipping slow smoothed process
    # Note: testnode must be created with: opts={'may_reconnect': True}
    def force_feerates(self, rate):
        assert(self.may_reconnect)
        self.set_feerates([rate] * 4, False)
        self.restart()
        self.daemon.wait_for_log('peer_out WIRE_UPDATE_FEE')
        assert(self.rpc.feerates('perkw')['perkw']['opening'] == rate)

    def wait_for_onchaind_txs(self, *args):
        """Wait for onchaind to ask lightningd to create one or more txs.  Each arg is a pair of typename, resolvename.  Returns tuples of the rawtx, txid and number of blocks delay for each pair.
        """
        # Could happen in any order.
        needle = self.daemon.logsearch_start
        ret = ()
        for (name, resolve) in args:
            self.daemon.logsearch_start = needle
            r = self.daemon.wait_for_log('Telling lightningd about {} to resolve {}'
                                         .format(name, resolve))
            blocks = int(re.search(r'\(([-0-9]*) more blocks\)', r).group(1))

            # The next 'Broadcast for onchaind' will be the tx.
            # Now grab the corresponding broadcast lightningd did, to get actual tx:
            r = self.daemon.wait_for_log('Broadcast for onchaind tx')
            rawtx = re.search(r'.* tx ([0-9a-fA-F]*)', r).group(1)
            txid = self.bitcoin.rpc.decoderawtransaction(rawtx, True)['txid']
            ret = ret + ((rawtx, txid, blocks),)
        return ret

    def wait_for_onchaind_tx(self, name, resolve):
        return self.wait_for_onchaind_txs((name, resolve))[0]

    def mine_txid_or_rbf(self, txid, numblocks=1):
        """Wait for a txid to be broadcast, or an rbf.  Return the one actually mined"""
        # Hack so we can mutate the txid: pass it in a list
        def rbf_or_txid_broadcast(txids):
            # RBF onchain txid d4b597505b543a4b8b42ab4d481fd7a533febb7e7df150ca70689e6d046612f7 (fee 6564sat) with txid 979878b8f855d3895d1cd29bd75a60b21492c4842e38099186a8e649bee02c7c (fee 8205sat)
            # We can have noop RBFs: ignore those (increases are logged INFO level)
            line = self.daemon.is_in_log(" INFO    .*RBF (onchain|HTLC) txid {}".format(txids[-1]))
            if line is not None:
                newtxid = re.search(r'with txid ([0-9a-fA-F]*)', line).group(1)
                txids.append(newtxid)
            mempool = self.bitcoin.rpc.getrawmempool()
            return any([t in mempool for t in txids])

        txids = [txid]
        wait_for(lambda: rbf_or_txid_broadcast(txids))
        blocks = self.bitcoin.generate_block(numblocks)

        # It might have snuck an RBF in at the last minute!
        rbf_or_txid_broadcast(txids)

        for tx in self.bitcoin.rpc.getblock(blocks[0])['tx']:
            if tx in txids:
                return tx
        raise ValueError("None of the rbf txs were mined?")

    def wait_for_onchaind_broadcast(self, name, resolve=None):
        """Wait for onchaind to drop tx name to resolve (if any)"""
        if resolve:
            r = self.daemon.wait_for_log('Broadcasting {} .* to resolve {}'
                                         .format(name, resolve))
        else:
            r = self.daemon.wait_for_log('Broadcasting {} .* to resolve '
                                         .format(name))

        rawtx = re.search(r'.* \(([0-9a-fA-F]*)\) ', r).group(1)
        txid = self.bitcoin.rpc.decoderawtransaction(rawtx, True)['txid']

        wait_for(lambda: txid in self.bitcoin.rpc.getrawmempool())

    def query_gossip(self, querytype, *args, filters=[]):
        """Generate a gossip query, feed it into this node and get responses
        in hex"""
        query = subprocess.run(['devtools/mkquery',
                                querytype] + [str(a) for a in args],
                               check=True,
                               timeout=TIMEOUT,
                               stdout=subprocess.PIPE).stdout.strip()
        out = subprocess.run(['devtools/gossipwith',
                              '--features=40',  # OPT_GOSSIP_QUERIES
                              '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) + 1)),
                              '{}@localhost:{}'.format(self.info['id'],
                                                       self.port),
                              query],
                             check=True,
                             timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

        def passes_filters(hmsg, filters):
            for f in filters:
                if hmsg.startswith(f):
                    return False
            return True

        msgs = []
        while len(out):
            length = struct.unpack('>H', out[0:2])[0]
            hmsg = out[2:2 + length].hex()
            if passes_filters(hmsg, filters):
                msgs.append(out[2:2 + length].hex())
            out = out[2 + length:]
        return msgs

    def config(self, config_name):
        try:
            config = self.rpc.listconfigs(config_name)
        except RpcError:
            return None

        config = config['configs'][config_name]
        for valfield in ('set',
                         'value_str', 'value_bool', 'value_int',
                         'values_str', 'values_bool', 'values_int'):
            if valfield in config:
                return config[valfield]
        raise ValueError("Unknown value in config {}".format(config))

    def dev_pay(self, bolt11, amount_msat=None, label=None, riskfactor=None,
                maxfeepercent=None, retry_for=None,
                maxdelay=None, exemptfee=None, dev_use_shadow=True, exclude=[]):
        """Wrapper for rpc.dev_pay which suppresses the request schema"""
        # FIXME? dev options are not in schema
        old_check = self.rpc.check_request_schemas
        self.rpc.check_request_schemas = False
        ret = self.rpc.dev_pay(bolt11, amount_msat, label, riskfactor,
                               maxfeepercent, retry_for,
                               maxdelay, exemptfee, dev_use_shadow, exclude)
        self.rpc.check_request_schemas = old_check
        return ret

    def dev_invoice(self, amount_msat, label, description, expiry=None, fallbacks=None, preimage=None, exposeprivatechannels=None, cltv=None, dev_routes=None):
        """Wrapper for rpc.invoice() with dev-routes option"""
        payload = {
            "amount_msat": amount_msat,
            "label": label,
            "description": description,
            "expiry": expiry,
            "fallbacks": fallbacks,
            "preimage": preimage,
            "exposeprivatechannels": exposeprivatechannels,
            "cltv": cltv,
            "dev-routes": dev_routes,
        }
        # FIXME? dev options are not in schema
        old_check = self.rpc.check_request_schemas
        self.rpc.check_request_schemas = False
        ret = self.rpc.call("invoice", payload)
        self.rpc.check_request_schemas = old_check
        return ret


@contextmanager
def flock(directory: Path):
    """A fair filelock, based on atomic fs operations.
    """
    if not isinstance(directory, Path):
        directory = Path(directory)
    d = directory / Path(".locks")
    os.makedirs(str(d), exist_ok=True)
    fname = None

    while True:
        # Try until we find a filename that doesn't exist yet.
        try:
            fname = d / Path("lock-{}".format(time.time()))
            fd = os.open(str(fname), flags=os.O_CREAT | os.O_EXCL)
            os.close(fd)
            break
        except FileExistsError:
            time.sleep(0.1)

    # So now we have a position in the lock, let's check if we are the
    # next one to go:
    while True:
        files = sorted([f for f in d.iterdir() if f.is_file()])
        # We're queued, so it should at least have us.
        assert len(files) >= 1
        if files[0] == fname:
            break
        time.sleep(0.1)

    # We can continue
    yield fname

    # Remove our file, so the next one can go ahead.
    fname.unlink()


class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, request, testname, bitcoind, executor, directory,
                 db_provider, node_cls, jsonschemas):
        if request.node.get_closest_marker("slow_test") and SLOW_MACHINE:
            self.valgrind = False
        else:
            self.valgrind = VALGRIND
        self.testname = testname
        self.next_id = 1
        self.nodes = []
        self.reserved_ports = []
        self.executor = executor
        self.bitcoind = bitcoind
        self.directory = directory
        self.lock = threading.Lock()
        self.db_provider = db_provider
        self.node_cls = node_cls
        self.jsonschemas = jsonschemas

    def split_options(self, opts):
        """Split node options from cli options

        Some options are used to instrument the node wrapper and some are passed
        to the daemon on the command line. Split them so we know where to use
        them.
        """
        node_opt_keys = [
            'disconnect',
            'may_fail',
            'allow_broken_log',
            'allow_warning',
            'may_reconnect',
            'random_hsm',
            'feerates',
            'wait_for_bitcoind_sync',
            'allow_bad_gossip',
            'start',
        ]
        node_opts = {k: v for k, v in opts.items() if k in node_opt_keys}
        cli_opts = {k: v for k, v in opts.items() if k not in node_opt_keys}
        return node_opts, cli_opts

    def get_node_id(self):
        """Generate a unique numeric ID for a lightning node
        """
        with self.lock:
            node_id = self.next_id
            self.next_id += 1
            return node_id

    def get_nodes(self, num_nodes, opts=None):
        """Start a number of nodes in parallel, each with its own options
        """
        if opts is None:
            # No opts were passed in, give some dummy opts
            opts = [{} for _ in range(num_nodes)]
        elif isinstance(opts, dict):
            # A single dict was passed in, so we use these opts for all nodes
            opts = [opts] * num_nodes

        assert len(opts) == num_nodes

        # Only trace one random node's plugins, to avoid OOM.
        if SLOW_MACHINE:
            valgrind_plugins = [False] * num_nodes
            valgrind_plugins[random.randint(0, num_nodes - 1)] = True
        else:
            valgrind_plugins = [True] * num_nodes

        jobs = []
        for i in range(num_nodes):
            node_opts, cli_opts = self.split_options(opts[i])
            jobs.append(self.executor.submit(
                self.get_node, options=cli_opts,
                node_id=self.get_node_id(), **node_opts,
                valgrind_plugins=valgrind_plugins[i]
            ))

        return [j.result() for j in jobs]

    def get_node(self, node_id=None, options=None, dbfile=None,
                 bkpr_dbfile=None, feerates=(15000, 11000, 7500, 3750),
                 start=True, wait_for_bitcoind_sync=True, may_fail=False,
                 expect_fail=False, cleandir=True, **kwargs):
        node_id = self.get_node_id() if not node_id else node_id
        port = reserve_unused_port()

        lightning_dir = os.path.join(
            self.directory, "lightning-{}/".format(node_id))

        if cleandir and os.path.exists(lightning_dir):
            shutil.rmtree(lightning_dir)

        # Get the DB backend DSN we should be using for this test and this
        # node.
        db = self.db_provider.get_db(os.path.join(lightning_dir, TEST_NETWORK), self.testname, node_id)
        db.provider = self.db_provider
        node = self.node_cls(
            node_id, lightning_dir, self.bitcoind, self.executor, self.valgrind, db=db,
            port=port, options=options, may_fail=may_fail or expect_fail,
            jsonschemas=self.jsonschemas,
            **kwargs
        )

        # Regtest estimatefee are unusable, so override.
        if feerates is not None:
            node.set_feerates(feerates, False)

        self.nodes.append(node)
        self.reserved_ports.append(port)
        if dbfile:
            out = open(os.path.join(node.daemon.lightning_dir, TEST_NETWORK,
                                    'lightningd.sqlite3'), 'xb')
            with lzma.open(os.path.join('tests/data', dbfile), 'rb') as f:
                out.write(f.read())

        if bkpr_dbfile:
            out = open(os.path.join(node.daemon.lightning_dir, TEST_NETWORK,
                                    'accounts.sqlite3'), 'xb')
            with lzma.open(os.path.join('tests/data', bkpr_dbfile), 'rb') as f:
                out.write(f.read())

        if start:
            try:
                node.start(wait_for_bitcoind_sync)
            except Exception:
                if expect_fail:
                    return node
                node.daemon.stop()
                raise
        return node

    def join_nodes(self, nodes, fundchannel=True, fundamount=FUNDAMOUNT, wait_for_announce=False, announce_channels=True) -> None:
        """Given nodes, connect them in a line, optionally funding a channel, wait_for_announce waits for channel and node announcements"""
        assert not (wait_for_announce and not announce_channels), "You've asked to wait for an announcement that's not coming. (wait_for_announce=True,announce_channels=False)"
        connections = [(nodes[i], nodes[i + 1]) for i in range(len(nodes) - 1)]

        for src, dst in connections:
            src.rpc.connect(dst.info['id'], 'localhost', dst.port)

        # If we're returning now, make sure dst all show connections in
        # getpeers.
        if not fundchannel:
            for src, dst in connections:
                dst.daemon.wait_for_log(r'{}-connectd: Handed peer, entering loop'.format(src.info['id']))
            return

        bitcoind = nodes[0].bitcoin
        # If we got here, we want to fund channels
        for src, dst in connections:
            addr = src.rpc.newaddr()['bech32']
            bitcoind.rpc.sendtoaddress(addr, (fundamount + 1000000) / 10**8)

        bitcoind.generate_block(1)
        sync_blockheight(bitcoind, nodes)
        txids = []
        for src, dst in connections:
            txids.append(src.rpc.fundchannel(dst.info['id'], fundamount, announce=announce_channels)['txid'])

        # Confirm all channels and wait for them to become usable
        bitcoind.generate_block(1, wait_for_mempool=txids)
        scids = []
        for src, dst in connections:
            wait_for(lambda: src.channel_state(dst) == 'CHANNELD_NORMAL')
            scid = src.get_channel_scid(dst)
            scids.append(scid)

        # Wait for all channels to be active (locally)
        for i, n in enumerate(scids):
            nodes[i].wait_local_channel_active(scids[i])
            nodes[i + 1].wait_local_channel_active(scids[i])

        if not wait_for_announce:
            return

        bitcoind.generate_block(5)

        # Make sure everyone sees all channels, all other nodes
        for n in nodes:
            for scid in scids:
                n.wait_channel_active(scid)

        # Make sure we have all node announcements, too
        for n in nodes:
            for n2 in nodes:
                wait_for(lambda: 'alias' in only_one(n.rpc.listnodes(n2.info['id'])['nodes']))

    def line_graph(self, num_nodes, fundchannel=True, fundamount=FUNDAMOUNT, wait_for_announce=False, opts=None, announce_channels=True):
        """ Create nodes, connect them and optionally fund channels.
        """
        nodes = self.get_nodes(num_nodes, opts=opts)

        self.join_nodes(nodes, fundchannel, fundamount, wait_for_announce, announce_channels)
        return nodes

    def killall(self, expected_successes):
        """Returns true if every node we expected to succeed actually succeeded"""
        unexpected_fail = False
        err_msgs = []
        for i in range(len(self.nodes)):
            leaks = None
            # leak detection upsets VALGRIND by reading uninitialized mem,
            # and valgrind adds extra fds.
            # If it's dead, we'll catch it below.
            if not self.valgrind:
                try:
                    # This also puts leaks in log.
                    leaks = self.nodes[i].rpc.dev_memleak()['leaks']
                    self.nodes[i].rpc.dev_report_fds()
                except Exception:
                    pass

            try:
                self.nodes[i].stop()
            except Exception:
                if expected_successes[i]:
                    unexpected_fail = True

            if leaks is not None and len(leaks) != 0:
                unexpected_fail = True
                err_msgs.append("Node {} has memory leaks: {}".format(
                    self.nodes[i].daemon.lightning_dir,
                    json.dumps(leaks, sort_keys=True, indent=4)
                ))

        for p in self.reserved_ports:
            drop_unused_port(p)

        return not unexpected_fail, err_msgs
