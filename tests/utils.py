import binascii
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time

from bitcoin.rpc import RawProxy as BitcoinProxy


BITCOIND_CONFIG = {
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
    "rpcport": 18332,
}


LIGHTNINGD_CONFIG = {
    "bitcoind-poll": "1s",
    "log-level": "debug",
    "cltv-delta": 6,
    "cltv-final": 5,
    "locktime-blocks": 5,
}

DEVELOPER = os.getenv("DEVELOPER", "0") == "1"


def write_config(filename, opts):
    with open(filename, 'w') as f:
        for k, v in opts.items():
            f.write("{}={}\n".format(k, v))


class TailableProc(object):
    """A monitorable process that we can start, stop and tail.

    This is the base class for the daemons. It allows us to directly
    tail the processes and react to their output.
    """

    def __init__(self, outputDir=None):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.env = os.environ
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0

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
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                logging.debug("%s: %s", self.prefix, line.decode().rstrip())
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

    def wait_for_logs(self, regexs, timeout=60):
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

    def wait_for_log(self, regex, timeout=60):
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

    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=18332):
        TailableProc.__init__(self, bitcoin_dir)

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
            '-regtest',
            '-logtimestamps',
            '-nolisten',
        ]
        BITCOIND_CONFIG['rpcport'] = rpcport
        btc_conf_file = os.path.join(regtestdir, 'bitcoin.conf')
        write_config(os.path.join(bitcoin_dir, 'bitcoin.conf'), BITCOIND_CONFIG)
        write_config(btc_conf_file, BITCOIND_CONFIG)
        self.rpc = SimpleBitcoinProxy(btc_conf_file=btc_conf_file)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=60)

        logging.info("BitcoinD started")

    def generate_block(self, numblocks=1):
        # As of 0.16, generate() is removed; use generatetoaddress.
        self.rpc.generatetoaddress(numblocks, self.rpc.getnewaddress())

# lightning-1 => 0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518 aka JUNIORBEAM #0266e4
# lightning-2 => 022d223620a359a47ff7f7ac447c85c46c923da53389221a0054c11c1e3ca31d59 aka SILENTARTIST #022d22
# lightning-3 => 035d2b1192dfba134e10e540875d366ebc8bc353d5aa766b80c090b39c3a5d885d aka HOPPINGFIRE #035d2b
# lightning-4 => 0382ce59ebf18be7d84677c2e35f23294b9992ceca95491fcf8a56c6cb2d9de199 aka JUNIORFELONY #0382ce
# lightning-5 => 032cf15d1ad9c4a08d26eab1918f732d8ef8fdc6abb9640bf3db174372c491304e aka SOMBERFIRE #032cf1


class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoin_dir, port=9735, random_hsm=False):
        TailableProc.__init__(self, lightning_dir)
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_prefix = []

        self.opts = LIGHTNINGD_CONFIG.copy()
        opts = {
            'bitcoin-datadir': bitcoin_dir,
            'lightning-dir': lightning_dir,
            'port': port,
            'allow-deprecated-apis': 'false',
            'override-fee-rates': '15000/7500/1000',
            'network': 'regtest',
            'ignore-fee-limits': 'false',
        }

        for k, v in opts.items():
            self.opts[k] = v

        # Last 32-bytes of final part of dir -> seed.
        seed = (bytes(re.search('([^/]+)/*$', lightning_dir).group(1), encoding='utf-8') + bytes(32))[:32]
        if DEVELOPER:
            self.opts['dev-broadcast-interval'] = 1000
            if not random_hsm:
                self.opts['dev-hsm-seed'] = binascii.hexlify(seed).decode('ascii')
        self.prefix = 'lightningd(%d)' % (port)

        if not os.path.exists(lightning_dir):
            os.makedirs(lightning_dir)

    @property
    def cmd_line(self):

        opts = []
        for k, v in sorted(self.opts.items()):
            if v is None:
                opts.append("--{}".format(k))
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
    def __init__(self, daemon, rpc, btc, executor, may_fail=False):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc
        self.executor = executor
        self.may_fail = may_fail

    # Use batch if you're doing more than one async.
    def connect(self, remote_node, capacity, async=False):
        # Collect necessary information
        addr = self.rpc.newaddr()['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, capacity)
        tx = self.bitcoin.rpc.gettransaction(txid)
        start_size = self.bitcoin.rpc.getmempoolinfo()['size']

        def call_connect():
            try:
                self.rpc.connect('127.0.0.1', remote_node.daemon.port, tx['hex'], async=False)
            except Exception:
                pass
        t = threading.Thread(target=call_connect)
        t.daemon = True
        t.start()

        def wait_connected():
            # Up to 10 seconds to get tx into mempool.
            start_time = time.time()
            while self.bitcoin.rpc.getmempoolinfo()['size'] == start_size:
                if time.time() > start_time + 10:
                    raise TimeoutError('No new transactions in mempool')
                time.sleep(0.1)

            self.bitcoin.generate_block(1)

            # fut.result(timeout=5)

            # Now wait for confirmation
            self.daemon.wait_for_log(" to CHANNELD_NORMAL|STATE_NORMAL")
            remote_node.daemon.wait_for_log(" to CHANNELD_NORMAL|STATE_NORMAL")

        if async:
            return self.executor.submit(wait_connected)
        else:
            return wait_connected()

    def openchannel(self, remote_node, capacity, addrtype="p2sh-segwit"):
        addr, wallettxid = self.fundwallet(capacity, addrtype)
        fundingtx = self.rpc.fundchannel(remote_node.info['id'], capacity)
        self.daemon.wait_for_log('sendrawtx exit 0, gave')
        self.bitcoin.generate_block(6)
        self.daemon.wait_for_log('to CHANNELD_NORMAL|STATE_NORMAL')
        return {'address': addr, 'wallettxid': wallettxid, 'fundingtx': fundingtx}

    def fundwallet(self, sats, addrtype="p2sh-segwit"):
        addr = self.rpc.newaddr(addrtype)['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, sats / 10**6)
        self.bitcoin.generate_block(1)
        self.daemon.wait_for_log('Owning output .* txid {}'.format(txid))
        return addr, txid

    def getactivechannels(self):
        return [c for c in self.rpc.listchannels()['channels'] if c['active']]

    def db_query(self, query):
        from shutil import copyfile
        orig = os.path.join(self.daemon.lightning_dir, "lightningd.sqlite3")
        copy = os.path.join(self.daemon.lightning_dir, "lightningd-copy.sqlite3")
        copyfile(orig, copy)

        db = sqlite3.connect(copy)
        db.row_factory = sqlite3.Row
        c = db.cursor()
        c.execute(query)
        rows = c.fetchall()

        result = []
        for row in rows:
            result.append(dict(zip(row.keys(), row)))

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

        self.daemon.start()
