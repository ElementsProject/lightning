from bitcoin.rpc import RawProxy as BitcoinProxy
from btcproxy import BitcoinRpcProxy
from collections import OrderedDict
from decimal import Decimal
from ephemeral_port_reserve import reserve
from lightning import LightningRpc

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
import threading
import time

BITCOIND_CONFIG = {
    "regtest": 1,
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
}


LIGHTNINGD_CONFIG = OrderedDict({
    "log-level": "debug",
    "cltv-delta": 6,
    "cltv-final": 5,
    "watchtime-blocks": 5,
    "rescan": 1,
    'disable-dns': None,
})

with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"
EXPERIMENTAL_FEATURES = os.getenv("EXPERIMENTAL_FEATURES", config['EXPERIMENTAL_FEATURES']) == "1"

# Gossip can be slow without DEVELOPER.
if DEVELOPER:
    DEFAULT_TIMEOUT = 60
else:
    DEFAULT_TIMEOUT = 180

TIMEOUT = int(os.getenv("TIMEOUT", str(DEFAULT_TIMEOUT)))
VALGRIND = os.getenv("VALGRIND", config['VALGRIND']) == "1"
SLOW_MACHINE = os.getenv("SLOW_MACHINE", "0") == "1"
COMPAT = os.getenv("COMPAT", config['COMPAT']) == "1"


def wait_for(success, timeout=TIMEOUT):
    start_time = time.time()
    interval = 0.25
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
        interval *= 2
        if interval > 5:
            interval = 5
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


def write_config(filename, opts, regtest_opts=None, section_name='regtest'):
    with open(filename, 'w') as f:
        for k, v in opts.items():
            f.write("{}={}\n".format(k, v))
        if regtest_opts:
            f.write("[{}]\n".format(section_name))
            for k, v in regtest_opts.items():
                f.write("{}={}\n".format(k, v))


def only_one(arr):
    """Many JSON RPC calls return an array; often we only expect a single entry
    """
    assert len(arr) == 1
    return arr[0]


def sync_blockheight(bitcoind, nodes):
    height = bitcoind.rpc.getblockchaininfo()['blocks']
    for n in nodes:
        wait_for(lambda: n.rpc.getinfo()['blockheight'] == height)


def wait_channel_quiescent(n1, n2):
    wait_for(lambda: only_one(only_one(n1.rpc.listpeers(n2.info['id'])['peers'])['channels'])['htlcs'] == [])
    wait_for(lambda: only_one(only_one(n2.rpc.listpeers(n1.info['id'])['peers'])['channels'])['htlcs'] == [])


def get_tx_p2wsh_outnum(bitcoind, tx, amount):
    """Get output number of this tx which is p2wsh of amount"""
    decoded = bitcoind.rpc.decoderawtransaction(tx, True)

    for out in decoded['vout']:
        if out['scriptPubKey']['type'] == 'witness_v0_scripthash':
            if out['value'] == Decimal(amount) / 10**8:
                return out['n']

    return None


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir=None, verbose=True):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.env = os.environ.copy()
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda line: False

    def start(self, stdin=None, stdout=None, stderr=None):
        """Start the underlying process and start monitoring it.
        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line,
                                     stdin=stdin,
                                     stdout=stdout if stdout else subprocess.PIPE,
                                     stderr=stderr,
                                     env=self.env)
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.thread.start()
        self.running = True

    def save_log(self):
        if self.outputDir:
            logpath = os.path.join(self.outputDir, 'log')
            with open(logpath, 'w') as f:
                for l in self.logs:
                    f.write(l + '\n')

    def stop(self, timeout=10):
        self.save_log()
        self.proc.terminate()

        # Now give it some time to react to the signal
        rc = self.proc.wait(timeout)

        if rc is None:
            self.proc.kill()

        self.proc.wait()
        self.thread.join()

        return self.proc.returncode

    def kill(self):
        """Kill process without giving it warning."""
        self.proc.kill()
        self.proc.wait()
        self.thread.join()

    def tail(self):
        """Tail the stdout of the process and remember it.

        Stores the lines of output produced by the process in
        self.logs and signals that a new line was read so that it can
        be picked up by consumers.
        """
        for line in iter(self.proc.stdout.readline, ''):
            if len(line) == 0:
                break
            if self.log_filter(line.decode('ASCII')):
                continue
            if self.verbose:
                logging.debug("%s: %s", self.prefix, line.decode().rstrip())
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                self.logs_cond.notifyAll()
        self.running = False
        self.proc.stdout.close()
        if self.proc.stderr:
            self.proc.stderr.close()

    def is_in_log(self, regex, start=0):
        """Look for `regex` in the logs."""

        ex = re.compile(regex)
        for l in self.logs[start:]:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return l

        logging.debug("Did not find '%s' in logs", regex)
        return None

    def wait_for_logs(self, regexs, timeout=TIMEOUT):
        """Look for `regexs` in the logs.

        We tail the stdout of the process and look for each regex in `regexs`,
        starting from last of the previous waited-for log entries (if any).  We
        fail if the timeout is exceeded or if the underlying process
        exits before all the `regexs` were found.

        If timeout is None, no time-out is applied.
        """
        logging.debug("Waiting for {} in the logs".format(regexs))
        exs = [re.compile(r) for r in regexs]
        start_time = time.time()
        pos = self.logsearch_start
        while True:
            if timeout is not None and time.time() > start_time + timeout:
                print("Time-out: can't find {} in logs".format(exs))
                for r in exs:
                    if self.is_in_log(r):
                        print("({} was previously in logs!)".format(r))
                raise TimeoutError('Unable to find "{}" in logs.'.format(exs))
            elif not self.running:
                raise ValueError('Process died while waiting for logs')

            with self.logs_cond:
                if pos >= len(self.logs):
                    self.logs_cond.wait(1)
                    continue

                for r in exs.copy():
                    self.logsearch_start = pos + 1
                    if r.search(self.logs[pos]):
                        logging.debug("Found '%s' in logs", r)
                        exs.remove(r)
                        break
                if len(exs) == 0:
                    return self.logs[pos]
                pos += 1

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
            return proxy._call(name, *args)

        # Make debuggers show <function bitcoin.rpc.name> rather than <function
        # bitcoin.rpc.<lambda>>
        f.__name__ = name
        return f


class BitcoinD(TailableProc):

    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=None):
        TailableProc.__init__(self, bitcoin_dir, verbose=False)

        if rpcport is None:
            rpcport = reserve()

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
            '-addresstype=bech32'
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

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=TIMEOUT)

        logging.info("BitcoinD started")

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
    def generate_block(self, numblocks=1, wait_for_mempool=0):
        if wait_for_mempool:
            if isinstance(wait_for_mempool, str):
                wait_for_mempool = [wait_for_mempool]
            if isinstance(wait_for_mempool, list):
                wait_for(lambda: all(txid in self.rpc.getrawmempool() for txid in wait_for_mempool))
            else:
                wait_for(lambda: len(self.rpc.getrawmempool()) >= wait_for_mempool)
        # As of 0.16, generate() is removed; use generatetoaddress.
        return self.rpc.generatetoaddress(numblocks, self.rpc.getnewaddress())

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
            '-validatepegin=0',
            '-con_blocksubsidy=5000000000',
        ]
        conf_file = os.path.join(bitcoin_dir, 'elements.conf')
        config['rpcport'] = self.rpcport
        BITCOIND_REGTEST = {'rpcport': self.rpcport}
        write_config(conf_file, config, BITCOIND_REGTEST, section_name='liquid-regtest')
        self.conf_file = conf_file
        self.rpc = SimpleBitcoinProxy(btc_conf_file=self.conf_file)
        self.prefix = 'elementsd'

    def generate_block(self, numblocks=1, wait_for_mempool=0):
        if wait_for_mempool:
            if isinstance(wait_for_mempool, str):
                wait_for_mempool = [wait_for_mempool]
            if isinstance(wait_for_mempool, list):
                wait_for(lambda: all(txid in self.rpc.getrawmempool() for txid in wait_for_mempool))
            else:
                wait_for(lambda: len(self.rpc.getrawmempool()) >= wait_for_mempool)
        # As of 0.16, generate() is removed; use generatetoaddress.
        return self.rpc.generate(numblocks)

    def getnewaddress(self):
        """Need to get an address and then make it unconfidential
        """
        addr = self.rpc.getnewaddress()
        info = self.rpc.getaddressinfo(addr)
        return info['unconfidential']


class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoindproxy, port=9735, random_hsm=False, node_id=0):
        TailableProc.__init__(self, lightning_dir)
        self.executable = 'lightningd/lightningd'
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_prefix = []
        self.disconnect_file = None

        self.rpcproxy = bitcoindproxy

        self.opts = LIGHTNINGD_CONFIG.copy()
        opts = {
            'lightning-dir': lightning_dir,
            'addr': '127.0.0.1:{}'.format(port),
            'allow-deprecated-apis': 'false',
            'network': config.get('TEST_NETWORK', 'regtest'),
            'ignore-fee-limits': 'false',
            'bitcoin-rpcuser': BITCOIND_CONFIG['rpcuser'],
            'bitcoin-rpcpassword': BITCOIND_CONFIG['rpcpassword'],
        }

        for k, v in opts.items():
            self.opts[k] = v

        if not os.path.exists(lightning_dir):
            os.makedirs(lightning_dir)

        # Last 32-bytes of final part of dir -> seed.
        seed = (bytes(re.search('([^/]+)/*$', lightning_dir).group(1), encoding='utf-8') + bytes(32))[:32]
        if not random_hsm:
            with open(os.path.join(lightning_dir, 'hsm_secret'), 'wb') as f:
                f.write(seed)
        if DEVELOPER:
            self.opts['dev-fast-gossip'] = None
            self.opts['dev-bitcoind-poll'] = 1
        self.prefix = 'lightningd-%d' % (node_id)

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

        return self.cmd_prefix + [self.executable] + opts

    def start(self, stdin=None, stdout=None, stderr=None,
              wait_for_initialized=True):
        self.opts['bitcoin-rpcport'] = self.rpcproxy.rpcport
        TailableProc.start(self, stdin, stdout, stderr)
        if wait_for_initialized:
            self.wait_for_log("Server started with public key")
        logging.info("LightningD started")

    def wait(self, timeout=10):
        """Wait for the daemon to stop for up to timeout seconds

        Returns the returncode of the process, None if the process did
        not return before the timeout triggers.
        """
        self.proc.wait(timeout)
        return self.proc.returncode


class LightningNode(object):
    def __init__(self, daemon, rpc, btc, executor, may_fail=False,
                 may_reconnect=False, allow_broken_log=False,
                 allow_bad_gossip=False, db=None):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc
        self.executor = executor
        self.may_fail = may_fail
        self.may_reconnect = may_reconnect
        self.allow_broken_log = allow_broken_log
        self.allow_bad_gossip = allow_bad_gossip
        self.db = db

    def connect(self, remote_node):
        self.rpc.connect(remote_node.info['id'], '127.0.0.1', remote_node.daemon.port)

    def is_connected(self, remote_node):
        return remote_node.info['id'] in [p['id'] for p in self.rpc.listpeers()['peers']]

    def openchannel(self, remote_node, capacity, addrtype="p2sh-segwit", confirm=True, wait_for_announce=True, connect=True):
        addr, wallettxid = self.fundwallet(10 * capacity, addrtype)

        if connect and not self.is_connected(remote_node):
            self.connect(remote_node)

        fundingtx = self.rpc.fundchannel(remote_node.info['id'], capacity)

        # Wait for the funding transaction to be in bitcoind's mempool
        wait_for(lambda: fundingtx['txid'] in self.bitcoin.rpc.getrawmempool())

        if confirm or wait_for_announce:
            self.bitcoin.generate_block(1)

        if wait_for_announce:
            self.bitcoin.generate_block(5)

        if confirm or wait_for_announce:
            self.daemon.wait_for_log(
                r'Funding tx {} depth'.format(fundingtx['txid']))
        return {'address': addr, 'wallettxid': wallettxid, 'fundingtx': fundingtx}

    def fundwallet(self, sats, addrtype="p2sh-segwit"):
        addr = self.rpc.newaddr(addrtype)[addrtype]
        txid = self.bitcoin.rpc.sendtoaddress(addr, sats / 10**8)
        self.bitcoin.generate_block(1)
        self.daemon.wait_for_log('Owning output .* txid {} CONFIRMED'.format(txid))
        return addr, txid

    def getactivechannels(self):
        return [c for c in self.rpc.listchannels()['channels'] if c['active']]

    def db_query(self, query):
        return self.db.query(query)

    # Assumes node is stopped!
    def db_manip(self, query):
        db = sqlite3.connect(os.path.join(self.daemon.lightning_dir, "lightningd.sqlite3"))
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

    def start(self, wait_for_bitcoind_sync=True):
        self.daemon.start()
        # Cache `getinfo`, we'll be using it a lot
        self.info = self.rpc.getinfo()
        # This shortcut is sufficient for our simple tests.
        self.port = self.info['binding'][0]['port']
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

        rc = self.daemon.wait(timeout)

        # If it did not stop be more insistent
        if rc is None:
            rc = self.daemon.stop()

        self.daemon.save_log()
        self.daemon.cleanup()

        if rc != 0 and not self.may_fail:
            raise ValueError("Node did not exit cleanly, rc={}".format(rc))
        else:
            return rc

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

    def fund_channel(self, l2, amount, wait_for_active=True):

        # Give yourself some funds to work with
        addr = self.rpc.newaddr()['bech32']
        self.bitcoin.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
        numfunds = len(self.rpc.listfunds()['outputs'])
        self.bitcoin.generate_block(1)
        wait_for(lambda: len(self.rpc.listfunds()['outputs']) > numfunds)

        # Now go ahead and open a channel
        num_tx = len(self.bitcoin.rpc.getrawmempool())
        tx = self.rpc.fundchannel(l2.info['id'], amount)['tx']

        wait_for(lambda: len(self.bitcoin.rpc.getrawmempool()) == num_tx + 1)
        self.bitcoin.generate_block(1)

        # Hacky way to find our output.
        scid = "{}x1x{}".format(self.bitcoin.rpc.getblockcount(),
                                get_tx_p2wsh_outnum(self.bitcoin, tx, amount))

        if wait_for_active:
            # We wait until gossipd sees both local updates, as well as status NORMAL,
            # so it can definitely route through.
            self.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                                       .format(scid),
                                       r'update for channel {}/1 now ACTIVE'
                                       .format(scid),
                                       'to CHANNELD_NORMAL'])
            l2.daemon.wait_for_logs([r'update for channel {}/0 now ACTIVE'
                                     .format(scid),
                                     r'update for channel {}/1 now ACTIVE'
                                     .format(scid),
                                     'to CHANNELD_NORMAL'])
        return scid

    def subd_pid(self, subd):
        """Get the process id of the given subdaemon, eg channeld or gossipd"""
        ex = re.compile(r'lightning_{}.*: pid ([0-9]*),'.format(subd))
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
        peers = self.rpc.listpeers(other.info['id'])['peers']
        if not peers or 'channels' not in peers[0]:
            return None
        channel = peers[0]['channels'][0]
        return channel['state']

    def get_channel_scid(self, other):
        """Get the short_channel_id for the channel to the other node.
        """
        peers = self.rpc.listpeers(other.info['id'])['peers']
        if not peers or 'channels' not in peers[0]:
            return None
        channel = peers[0]['channels'][0]
        return channel['short_channel_id']

    def is_channel_active(self, chanid):
        channels = self.rpc.listchannels()['channels']
        active = [(c['short_channel_id'], c['channel_flags']) for c in channels if c['active']]
        return (chanid, 0) in active and (chanid, 1) in active

    def wait_for_channel_onchain(self, peerid):
        txid = only_one(only_one(self.rpc.listpeers(peerid)['peers'])['channels'])['scratch_txid']
        wait_for(lambda: txid in self.bitcoin.rpc.getrawmempool())

    def wait_channel_active(self, chanid):
        wait_for(lambda: self.is_channel_active(chanid))

    # This waits until gossipd sees channel_update in both directions
    # (or for local channels, at least a local announcement)
    def wait_for_channel_updates(self, scids):
        # Could happen in any order...
        self.daemon.wait_for_logs(['Received channel_update for channel {}/0'.format(c)
                                   for c in scids]
                                  + ['Received channel_update for channel {}/1'.format(c)
                                     for c in scids])

    def wait_for_route(self, destination, timeout=30):
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

    def pay(self, dst, amt, label=None):
        if not label:
            label = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(20))

        rhash = dst.rpc.invoice(amt, label, label)['payment_hash']
        invoices = dst.rpc.listinvoices(label)['invoices']
        assert len(invoices) == 1 and invoices[0]['status'] == 'unpaid'

        routestep = {
            'msatoshi': amt,
            'id': dst.info['id'],
            'delay': 5,
            'channel': '1x1x1'
        }

        def wait_pay():
            # Up to 10 seconds for payment to succeed.
            start_time = time.time()
            while dst.rpc.listinvoices(label)['invoices'][0]['status'] != 'paid':
                if time.time() > start_time + 10:
                    raise TimeoutError('Payment timed out')
                time.sleep(0.1)
        # sendpay is async now
        self.rpc.sendpay([routestep], rhash)
        # wait for sendpay to comply
        self.rpc.waitsendpay(rhash)

    # Note: this feeds through the smoother in update_feerate, so changing
    # it on a running daemon may not give expected result!
    def set_feerates(self, feerates, wait_for_effect=True):
        # (bitcoind returns bitcoin per kb, so these are * 4)

        def mock_estimatesmartfee(r):
            params = r['params']
            if params == [2, 'CONSERVATIVE']:
                feerate = feerates[0] * 4
            elif params == [4, 'ECONOMICAL']:
                feerate = feerates[1] * 4
            elif params == [100, 'ECONOMICAL']:
                feerate = feerates[2] * 4
            else:
                raise ValueError()
            return {
                'id': r['id'],
                'error': None,
                'result': {
                    'feerate': Decimal(feerate) / 10**8
                },
            }
        self.daemon.rpcproxy.mock_rpc('estimatesmartfee', mock_estimatesmartfee)

        # Technically, this waits until it's called, not until it's processed.
        # We wait until all three levels have been called.
        if wait_for_effect:
            wait_for(lambda: self.daemon.rpcproxy.mock_counts['estimatesmartfee'] >= 3)

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

    def query_gossip(self, querytype, *args):
        """Generate a gossip query, feed it into this node and get responses
        in hex"""
        query = subprocess.run(['devtools/mkquery',
                                querytype] + [str(a) for a in args],
                               check=True,
                               timeout=TIMEOUT,
                               stdout=subprocess.PIPE).stdout.strip()
        out = subprocess.run(['devtools/gossipwith',
                              '--timeout-after={}'.format(int(math.sqrt(TIMEOUT) * 1000)),
                              '{}@localhost:{}'.format(self.info['id'],
                                                       self.port),
                              query],
                             check=True,
                             timeout=TIMEOUT, stdout=subprocess.PIPE).stdout

        msgs = []
        while len(out):
            length = struct.unpack('>H', out[0:2])[0]
            msgs.append(out[2:2 + length].hex())
            out = out[2 + length:]
        return msgs


class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, testname, bitcoind, executor, directory, db_provider):
        self.testname = testname
        self.next_id = 1
        self.nodes = []
        self.executor = executor
        self.bitcoind = bitcoind
        self.directory = directory
        self.lock = threading.Lock()
        self.db_provider = db_provider

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
            'may_reconnect',
            'random_hsm',
            'log_all_io',
            'feerates',
            'wait_for_bitcoind_sync',
            'allow_bad_gossip'
        ]
        node_opts = {k: v for k, v in opts.items() if k in node_opt_keys}
        cli_opts = {k: v for k, v in opts.items() if k not in node_opt_keys}
        return node_opts, cli_opts

    def get_next_port(self):
        with self.lock:
            return reserve()

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

        jobs = []
        for i in range(num_nodes):
            node_opts, cli_opts = self.split_options(opts[i])
            jobs.append(self.executor.submit(
                self.get_node, options=cli_opts,
                node_id=self.get_node_id(), **node_opts
            ))

        return [j.result() for j in jobs]

    def get_node(self, disconnect=None, options=None, may_fail=False,
                 may_reconnect=False, random_hsm=False,
                 feerates=(15000, 7500, 3750), start=True, log_all_io=False,
                 dbfile=None, node_id=None, allow_broken_log=False,
                 wait_for_bitcoind_sync=True, allow_bad_gossip=False):
        if not node_id:
            node_id = self.get_node_id()

        port = self.get_next_port()

        lightning_dir = os.path.join(
            self.directory, "lightning-{}/".format(node_id))

        if os.path.exists(lightning_dir):
            shutil.rmtree(lightning_dir)

        socket_path = os.path.join(lightning_dir, "lightning-rpc").format(node_id)
        daemon = LightningD(
            lightning_dir, bitcoindproxy=self.bitcoind.get_proxy(),
            port=port, random_hsm=random_hsm, node_id=node_id
        )
        # If we have a disconnect string, dump it to a file for daemon.
        if disconnect:
            daemon.disconnect_file = os.path.join(lightning_dir, "dev_disconnect")
            with open(daemon.disconnect_file, "w") as f:
                f.write("\n".join(disconnect))
            daemon.opts["dev-disconnect"] = "dev_disconnect"
        if log_all_io:
            assert DEVELOPER
            daemon.env["LIGHTNINGD_DEV_LOG_IO"] = "1"
            daemon.opts["log-level"] = "io"
        if DEVELOPER:
            daemon.opts["dev-fail-on-subdaemon-fail"] = None
            daemon.env["LIGHTNINGD_DEV_MEMLEAK"] = "1"
            if os.getenv("DEBUG_SUBD"):
                daemon.opts["dev-debugger"] = os.getenv("DEBUG_SUBD")
            if VALGRIND:
                daemon.env["LIGHTNINGD_DEV_NO_BACKTRACE"] = "1"
            if not may_reconnect:
                daemon.opts["dev-no-reconnect"] = None

        if options is not None:
            daemon.opts.update(options)

        # Get the DB backend DSN we should be using for this test and this node.
        db = self.db_provider.get_db(lightning_dir, self.testname, node_id)
        dsn = db.get_dsn()
        if dsn is not None:
            daemon.opts['wallet'] = dsn

        rpc = LightningRpc(socket_path, self.executor)

        node = LightningNode(daemon, rpc, self.bitcoind, self.executor, may_fail=may_fail,
                             may_reconnect=may_reconnect, allow_broken_log=allow_broken_log,
                             allow_bad_gossip=allow_bad_gossip, db=db)

        # Regtest estimatefee are unusable, so override.
        node.set_feerates(feerates, False)

        self.nodes.append(node)
        if VALGRIND:
            node.daemon.cmd_prefix = [
                'valgrind',
                '-q',
                '--trace-children=yes',
                '--trace-children-skip=*python*,*bitcoin-cli*,*elements-cli*',
                '--error-exitcode=7',
                '--log-file={}/valgrind-errors.%p'.format(node.daemon.lightning_dir)
            ]

        if dbfile:
            out = open(os.path.join(node.daemon.lightning_dir, 'lightningd.sqlite3'), 'xb')
            with lzma.open(os.path.join('tests/data', dbfile), 'rb') as f:
                out.write(f.read())

        if start:
            try:
                node.start(wait_for_bitcoind_sync)
            except Exception:
                node.daemon.stop()
                raise
        return node

    def line_graph(self, num_nodes, fundchannel=True, fundamount=10**6, wait_for_announce=False, opts=None, announce_channels=True):
        """ Create nodes, connect them and optionally fund channels.
        """
        assert not (wait_for_announce and not announce_channels), "You've asked to wait for an announcement that's not coming. (wait_for_announce=True,announce_channels=False)"
        nodes = self.get_nodes(num_nodes, opts=opts)
        bitcoin = nodes[0].bitcoin
        connections = [(nodes[i], nodes[i + 1]) for i in range(0, num_nodes - 1)]

        for src, dst in connections:
            src.rpc.connect(dst.info['id'], 'localhost', dst.port)

        # If we're returning now, make sure dst all show connections in
        # getpeers.
        if not fundchannel:
            for src, dst in connections:
                dst.daemon.wait_for_log('openingd-{} chan #[0-9]*: Handed peer, entering loop'.format(src.info['id']))
            return nodes

        # If we got here, we want to fund channels
        for src, dst in connections:
            addr = src.rpc.newaddr()['bech32']
            src.bitcoin.rpc.sendtoaddress(addr, (fundamount + 1000000) / 10**8)

        bitcoin.generate_block(1)
        for src, dst in connections:
            wait_for(lambda: len(src.rpc.listfunds()['outputs']) > 0)
            tx = src.rpc.fundchannel(dst.info['id'], fundamount, announce=announce_channels)
            wait_for(lambda: tx['txid'] in bitcoin.rpc.getrawmempool())

        # Confirm all channels and wait for them to become usable
        bitcoin.generate_block(1)
        scids = []
        for src, dst in connections:
            wait_for(lambda: src.channel_state(dst) == 'CHANNELD_NORMAL')
            scid = src.get_channel_scid(dst)
            src.daemon.wait_for_log(r'Received channel_update for channel {scid}/. now ACTIVE'.format(scid=scid))
            scids.append(scid)

        if not wait_for_announce:
            return nodes

        bitcoin.generate_block(5)

        def both_dirs_ready(n, scid):
            resp = n.rpc.listchannels(scid)
            return [a['active'] for a in resp['channels']] == [True, True]

        # Make sure everyone sees all channels: we can cheat and
        # simply check the ends (since it's a line).
        wait_for(lambda: both_dirs_ready(nodes[0], scids[-1]))
        wait_for(lambda: both_dirs_ready(nodes[-1], scids[0]))

        # Make sure we have all node announcements, too (just check ends)
        for n in nodes:
            for end in (nodes[0], nodes[-1]):
                wait_for(lambda: 'alias' in only_one(end.rpc.listnodes(n.info['id'])['nodes']))

        return nodes

    def killall(self, expected_successes):
        """Returns true if every node we expected to succeed actually succeeded"""
        unexpected_fail = False
        err_msgs = []
        for i in range(len(self.nodes)):
            leaks = None
            # leak detection upsets VALGRIND by reading uninitialized mem.
            # If it's dead, we'll catch it below.
            if not VALGRIND:
                try:
                    # This also puts leaks in log.
                    leaks = self.nodes[i].rpc.dev_memleak()['leaks']
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

        return not unexpected_fail, err_msgs
