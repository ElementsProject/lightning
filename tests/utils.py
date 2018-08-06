import logging
import os
import random
import re
import shutil
import sqlite3
import stat
import string
import subprocess
import threading
import time

from bitcoin.rpc import RawProxy as BitcoinProxy
from decimal import Decimal
from ephemeral_port_reserve import reserve
from lightning import LightningRpc


BITCOIND_CONFIG = {
    "regtest": 1,
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
}


LIGHTNINGD_CONFIG = {
    "log-level": "debug",
    "cltv-delta": 6,
    "cltv-final": 5,
    "watchtime-blocks": 5,
    "rescan": 1,
    'disable-dns': None,
}

with open('config.vars') as configfile:
    config = dict([(line.rstrip().split('=', 1)) for line in configfile])

DEVELOPER = os.getenv("DEVELOPER", config['DEVELOPER']) == "1"
TIMEOUT = int(os.getenv("TIMEOUT", "60"))
VALGRIND = os.getenv("VALGRIND", config['VALGRIND']) == "1"


def wait_for(success, timeout=TIMEOUT, interval=0.1):
    start_time = time.time()
    while not success() and time.time() < start_time + timeout:
        time.sleep(interval)
    if time.time() > start_time + timeout:
        raise ValueError("Error waiting for {}", success)


def write_config(filename, opts, regtest_opts=None):
    with open(filename, 'w') as f:
        for k, v in opts.items():
            f.write("{}={}\n".format(k, v))
        if regtest_opts:
            f.write("[regtest]\n")
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


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir=None, verbose=True):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.env = os.environ
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0

        # Should we be logging lines we read from stdout?
        self.verbose = verbose

        # A filter function that'll tell us whether to filter out the line (not
        # pass it to the log matcher and not print it to stdout).
        self.log_filter = lambda line: False

    def start(self):
        """Start the underlying process and start monitoring it.
        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line, stdout=subprocess.PIPE, env=self.env)
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

        if self.proc.returncode:
            raise ValueError("Process '{}' did not cleanly shutdown: return code {}".format(self.proc.pid, rc))

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

        f = lambda *args: proxy._call(name, *args)

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
        ]
        # For up to and including 0.16.1, this needs to be in main section.
        BITCOIND_CONFIG['rpcport'] = rpcport
        # For after 0.16.1 (eg. 3f398d7a17f136cd4a67998406ca41a124ae2966), this
        # needs its own [regtest] section.
        BITCOIND_REGTEST = {'rpcport': rpcport}
        btc_conf_file = os.path.join(bitcoin_dir, 'bitcoin.conf')
        write_config(btc_conf_file, BITCOIND_CONFIG, BITCOIND_REGTEST)
        self.rpc = SimpleBitcoinProxy(btc_conf_file=btc_conf_file)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=TIMEOUT)

        logging.info("BitcoinD started")

    def generate_block(self, numblocks=1):
        # As of 0.16, generate() is removed; use generatetoaddress.
        self.rpc.generatetoaddress(numblocks, self.rpc.getnewaddress())


class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoin_dir, port=9735, random_hsm=False, node_id=0):
        TailableProc.__init__(self, lightning_dir)
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_prefix = []

        self.opts = LIGHTNINGD_CONFIG.copy()
        opts = {
            'bitcoin-datadir': bitcoin_dir,
            'lightning-dir': lightning_dir,
            'addr': '127.0.0.1:{}'.format(port),
            'allow-deprecated-apis': 'false',
            'default-fee-rate': 15000,
            'network': 'regtest',
            'ignore-fee-limits': 'false',
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
            self.opts['dev-broadcast-interval'] = 1000
            self.opts['dev-bitcoind-poll'] = 1
            # lightningd won't announce non-routable addresses by default.
            self.opts['dev-allow-localhost'] = None
        self.prefix = 'lightningd-%d' % (node_id)

        filters = [
            "Unable to estimate",
            "No fee estimate",
            "Connected json input",
            "Forcing fee rate, ignoring estimate",
        ]

        filter_re = re.compile(r'({})'.format("|".join(filters)))
        self.log_filter = lambda line: filter_re.search(line) is not None

    @property
    def cmd_line(self):

        opts = []
        for k, v in sorted(self.opts.items()):
            if v is None:
                opts.append("--{}".format(k))
            elif isinstance(v, list):
                for i in v:
                    opts.append("--{}={}".format(k, i))
            else:
                opts.append("--{}={}".format(k, v))

        return self.cmd_prefix + ['lightningd/lightningd'] + opts

    def start(self):
        TailableProc.start(self)
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
    def __init__(self, daemon, rpc, btc, executor, may_fail=False, may_reconnect=False):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc
        self.executor = executor
        self.may_fail = may_fail
        self.may_reconnect = may_reconnect

    def openchannel(self, remote_node, capacity, addrtype="p2sh-segwit", confirm=True, announce=True):
        addr, wallettxid = self.fundwallet(10 * capacity, addrtype)
        fundingtx = self.rpc.fundchannel(remote_node.info['id'], capacity)

        # Wait for the funding transaction to be in bitcoind's mempool
        wait_for(lambda: fundingtx['txid'] in self.bitcoin.rpc.getrawmempool())

        if confirm or announce:
            self.bitcoin.generate_block(1)

        if announce:
            self.bitcoin.generate_block(5)

        if confirm or announce:
            self.daemon.wait_for_log(
                r'Funding tx {} depth'.format(fundingtx['txid']))
        return {'address': addr, 'wallettxid': wallettxid, 'fundingtx': fundingtx}

    def fundwallet(self, sats, addrtype="p2sh-segwit"):
        addr = self.rpc.newaddr(addrtype)['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, sats / 10**8)
        self.bitcoin.generate_block(1)
        self.daemon.wait_for_log('Owning output .* txid {}'.format(txid))
        return addr, txid

    def getactivechannels(self):
        return [c for c in self.rpc.listchannels()['channels'] if c['active']]

    def db_query(self, query, use_copy=True):
        orig = os.path.join(self.daemon.lightning_dir, "lightningd.sqlite3")
        if use_copy:
            copy = os.path.join(self.daemon.lightning_dir, "lightningd-copy.sqlite3")
            shutil.copyfile(orig, copy)
            db = sqlite3.connect(copy)
        else:
            db = sqlite3.connect(orig)

        db.row_factory = sqlite3.Row
        c = db.cursor()
        c.execute(query)
        rows = c.fetchall()

        result = []
        for row in rows:
            result.append(dict(zip(row.keys(), row)))

        db.commit()
        c.close()
        db.close()
        return result

    # Assumes node is stopped!
    def db_manip(self, query):
        db = sqlite3.connect(os.path.join(self.daemon.lightning_dir, "lightningd.sqlite3"))
        db.row_factory = sqlite3.Row
        c = db.cursor()
        c.execute(query)
        db.commit()
        c.close()
        db.close()

    def start(self):
        self.daemon.start()
        # This shortcut is sufficient for our simple tests.
        self.port = self.rpc.getinfo()['binding'][0]['port']

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

    def fund_channel(self, l2, amount):

        # Give yourself some funds to work with
        addr = self.rpc.newaddr()['address']
        self.bitcoin.rpc.sendtoaddress(addr, (amount + 1000000) / 10**8)
        numfunds = len(self.rpc.listfunds()['outputs'])
        self.bitcoin.generate_block(1)
        wait_for(lambda: len(self.rpc.listfunds()['outputs']) > numfunds)

        # Now go ahead and open a channel
        num_tx = len(self.bitcoin.rpc.getrawmempool())
        tx = self.rpc.fundchannel(l2.info['id'], amount)['tx']

        wait_for(lambda: len(self.bitcoin.rpc.getrawmempool()) == num_tx + 1)
        self.bitcoin.generate_block(1)
        # We wait until gossipd sees local update, as well as status NORMAL,
        # so it can definitely route through.
        self.daemon.wait_for_logs(['update for channel .* now ACTIVE', 'to CHANNELD_NORMAL'])
        l2.daemon.wait_for_logs(['update for channel .* now ACTIVE', 'to CHANNELD_NORMAL'])

        # Hacky way to find our output.
        decoded = self.bitcoin.rpc.decoderawtransaction(tx)
        for out in decoded['vout']:
            # Sometimes a float?  Sometimes a decimal?  WTF Python?!
            if out['scriptPubKey']['type'] == 'witness_v0_scripthash':
                if out['value'] == Decimal(amount) / 10**8 or out['value'] * 10**8 == amount:
                    return "{}:1:{}".format(self.bitcoin.rpc.getblockcount(), out['n'])
        # Intermittent decoding failure.  See if it decodes badly twice?
        decoded2 = self.bitcoin.rpc.decoderawtransaction(tx)
        raise ValueError("Can't find {} payment in {} (1={} 2={})".format(amount, tx, decoded, decoded2))

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
        active = [(c['short_channel_id'], c['flags']) for c in channels if c['active']]
        return (chanid, 0) in active and (chanid, 1) in active

    def wait_channel_active(self, chanid):
        wait_for(lambda: self.is_channel_active(chanid), interval=1)

    # This waits until gossipd sees channel_update in both directions
    # (or for local channels, at least a local announcement)
    def wait_for_routes(self, channel_ids):
        # Could happen in any order...
        self.daemon.wait_for_logs(['Received channel_update for channel {}\\(0\\)'.format(c)
                                   for c in channel_ids] +
                                  ['Received channel_update for channel {}\\(1\\)'.format(c)
                                   for c in channel_ids])

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
            'channel': '1:1:1'
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

    def fake_bitcoind_fail(self, exitcode):
        # Create and rename, for atomicity.
        f = os.path.join(self.daemon.lightning_dir, "bitcoin-cli-fail.tmp")
        with open(f, "w") as text_file:
            text_file.write("%d" % exitcode)
        os.rename(f, os.path.join(self.daemon.lightning_dir, "bitcoin-cli-fail"))

    def fake_bitcoind_unfail(self):
        os.remove(os.path.join(self.daemon.lightning_dir, "bitcoin-cli-fail"))


class NodeFactory(object):
    """A factory to setup and start `lightningd` daemons.
    """
    def __init__(self, testname, bitcoind, executor, directory):
        self.testname = testname
        self.next_id = 1
        self.nodes = []
        self.executor = executor
        self.bitcoind = bitcoind
        self.directory = directory
        self.lock = threading.Lock()

    def split_options(self, opts):
        """Split node options from cli options

        Some options are used to instrument the node wrapper and some are passed
        to the daemon on the command line. Split them so we know where to use
        them.
        """
        node_opt_keys = [
            'disconnect',
            'may_fail',
            'may_reconnect',
            'random_hsm',
            'fake_bitcoin_cli'
        ]
        node_opts = {k: v for k, v in opts.items() if k in node_opt_keys}
        cli_opts = {k: v for k, v in opts.items() if k not in node_opt_keys}
        return node_opts, cli_opts

    def get_next_port(self):
        with self.lock:
            return reserve()

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
            jobs.append(self.executor.submit(self.get_node, options=cli_opts, **node_opts))

        return [j.result() for j in jobs]

    def get_node(self, disconnect=None, options=None, may_fail=False, may_reconnect=False, random_hsm=False,
                 fake_bitcoin_cli=False):
        with self.lock:
            node_id = self.next_id
            self.next_id += 1
        port = self.get_next_port()

        lightning_dir = os.path.join(
            self.directory, "lightning-{}/".format(node_id))

        if os.path.exists(lightning_dir):
            shutil.rmtree(lightning_dir)

        socket_path = os.path.join(lightning_dir, "lightning-rpc").format(node_id)
        daemon = LightningD(
            lightning_dir, self.bitcoind.bitcoin_dir,
            port=port, random_hsm=random_hsm, node_id=node_id
        )
        # If we have a disconnect string, dump it to a file for daemon.
        if disconnect:
            with open(os.path.join(lightning_dir, "dev_disconnect"), "w") as f:
                f.write("\n".join(disconnect))
            daemon.opts["dev-disconnect"] = "dev_disconnect"
        if DEVELOPER:
            daemon.opts["dev-fail-on-subdaemon-fail"] = None
            daemon.env["LIGHTNINGD_DEV_MEMLEAK"] = "1"
            if VALGRIND:
                daemon.env["LIGHTNINGD_DEV_NO_BACKTRACE"] = "1"
            if not may_reconnect:
                daemon.opts["dev-no-reconnect"] = None

        if fake_bitcoin_cli:
            cli = os.path.join(lightning_dir, "fake-bitcoin-cli")
            with open(cli, "w") as text_file:
                text_file.write('#! /bin/sh\n'
                                '! [ -f bitcoin-cli-fail ] || exit `cat bitcoin-cli-fail`\n'
                                'exec bitcoin-cli "$@"\n')
            os.chmod(cli, os.stat(cli).st_mode | stat.S_IEXEC)
            daemon.opts['bitcoin-cli'] = cli

        if options is not None:
            daemon.opts.update(options)

        rpc = LightningRpc(socket_path, self.executor)

        node = LightningNode(daemon, rpc, self.bitcoind, self.executor, may_fail=may_fail,
                             may_reconnect=may_reconnect)
        self.nodes.append(node)
        if VALGRIND:
            node.daemon.cmd_prefix = [
                'valgrind',
                '-q',
                '--trace-children=yes',
                '--trace-children-skip=*bitcoin-cli*',
                '--error-exitcode=7',
                '--log-file={}/valgrind-errors.%p'.format(node.daemon.lightning_dir)
            ]

        try:
            node.start()
        except Exception:
            node.daemon.stop()
            raise

        # Cache `getinfo`, we'll be using it a lot
        node.info = node.rpc.getinfo()
        return node

    def line_graph(self, num_nodes, fundchannel=True, fundamount=10**6, announce=False, opts=None):
        """ Create nodes, connect them and optionally fund channels.
        """
        nodes = self.get_nodes(num_nodes, opts=opts)
        bitcoin = nodes[0].bitcoin
        connections = [(nodes[i], nodes[i + 1]) for i in range(0, num_nodes - 1)]

        for src, dst in connections:
            src.rpc.connect(dst.info['id'], 'localhost', dst.port)

        if not fundchannel:
            return nodes

        # If we got here, we want to fund channels
        for src, dst in connections:
            addr = src.rpc.newaddr()['address']
            src.bitcoin.rpc.sendtoaddress(addr, (fundamount + 1000000) / 10**8)

        bitcoin.generate_block(1)
        for src, dst in connections:
            wait_for(lambda: len(src.rpc.listfunds()['outputs']) > 0)
            tx = src.rpc.fundchannel(dst.info['id'], fundamount)
            wait_for(lambda: tx['txid'] in bitcoin.rpc.getrawmempool())

        # Confirm all channels and wait for them to become usable
        bitcoin.generate_block(1)
        for src, dst in connections:
            wait_for(lambda: src.channel_state(dst) == 'CHANNELD_NORMAL')
            scid = src.get_channel_scid(dst)
            src.daemon.wait_for_log(r'Received channel_update for channel {scid}\(.\) now ACTIVE'.format(scid=scid))

        if not announce:
            return nodes

        bitcoin.generate_block(5)
        return nodes

    def killall(self, expected_successes):
        """Returns true if every node we expected to succeed actually succeeded"""
        unexpected_fail = False
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
                raise Exception("Node {} has memory leaks: {}"
                                .format(self.nodes[i].daemon.lightning_dir, leaks))

        return not unexpected_fail
