from bitcoin.rpc import RawProxy as BitcoinProxy
from lightning import LightningRpc

import logging
import os
import re
import sqlite3
import subprocess
import threading
import time


BITCOIND_CONFIG = {
    "rpcuser": "rpcuser",
    "rpcpassword": "rpcpass",
    "rpcport": 18332,
}


LIGHTNINGD_CONFIG = {
    "bitcoind-poll": "1s",
    "log-level": "debug",
    "deadline-blocks": 5,
    "min-htlc-expiry": 6,
    "locktime-blocks": 6,
}


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
        self.cmd_line = None
        self.running = False
        self.proc = None
        self.outputDir = outputDir
        self.logsearch_start = 0
        
    def start(self):
        """Start the underlying process and start monitoring it.
        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line, stdout=subprocess.PIPE)
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.thread.start()
        self.running = True

    def stop(self):
        self.proc.terminate()
        self.proc.kill()
        self.proc.wait()
        self.thread.join()
        if self.outputDir:
            logpath = os.path.join(self.outputDir, 'log')
            with open(logpath, 'w') as f:
                for l in self.logs:
                    f.write(l + '\n')

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

    def is_in_log(self, regex):
        """Look for `regex` in the logs."""

        ex = re.compile(regex)
        for l in self.logs:
            if ex.search(l):
                logging.debug("Found '%s' in logs", regex)
                return True

        logging.debug("Did not find '%s' in logs", regex)
        return False

    def wait_for_logs(self, regexs, timeout=60):
        """Look for `regexs` in the logs.

        We tail the stdout of the process and look for each regex in `regexs`,
        starting from last of the previous waited-for log entries (if any).  We
        fail if the timeout is exceeded or if the underlying process
        exits before all the `regexs` were found.

        """
        logging.debug("Waiting for {} in the logs".format(regexs))
        exs = {re.compile(r) for r in regexs}
        start_time = time.time()
        pos = self.logsearch_start
        initial_pos = len(self.logs)
        while True:
            if time.time() > start_time + timeout:
                print("Can't find {} in logs".format(exs))
                with self.logs_cond:
                    for i in range(initial_pos, len(self.logs)):
                        print("  " + self.logs[i])
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
                    if r.search(self.logs[pos]):
                        logging.debug("Found '%s' in logs", r)
                        exs.remove(r)
                    self.logsearch_start = pos+1
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
    def __init__(self, url):
        self.url = url

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError

        # Create a callable to do the actual call
        f = lambda *args: BitcoinProxy(self.url)._call(name, *args)

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
        write_config(os.path.join(bitcoin_dir, 'bitcoin.conf'), BITCOIND_CONFIG)
        write_config(os.path.join(regtestdir, 'bitcoin.conf'), BITCOIND_CONFIG)
        self.rpc = SimpleBitcoinProxy(
            "http://rpcuser:rpcpass@127.0.0.1:{}".format(self.rpcport))

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=10)

        logging.info("BitcoinD started")


class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoin_dir, port=9735):
        TailableProc.__init__(self, lightning_dir)
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_line = [
            'lightningd/lightningd',
            '--bitcoin-datadir={}'.format(bitcoin_dir),
            '--lightning-dir={}'.format(lightning_dir),
            '--port={}'.format(port),
            '--disable-irc',
            '--network=regtest',
            '--dev-broadcast-interval=1000',
        ]

        self.cmd_line += ["--{}={}".format(k, v) for k, v in LIGHTNINGD_CONFIG.items()]
        self.prefix = 'lightningd'

        if not os.path.exists(lightning_dir):
            os.makedirs(lightning_dir)

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Creating IPv6 listener on port")
        logging.info("LightningD started")

    def stop(self):
        TailableProc.stop(self)
        logging.info("LightningD stopped")

class LightningNode(object):
    def __init__(self, daemon, rpc, btc, executor):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc
        self.executor = executor

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
            except:
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

            self.bitcoin.rpc.generate(1)

            #fut.result(timeout=5)

            # Now wait for confirmation
            self.daemon.wait_for_log("-> CHANNELD_NORMAL|STATE_NORMAL")
            remote_node.daemon.wait_for_log("-> CHANNELD_NORMAL|STATE_NORMAL")

        if async:
            return self.executor.submit(wait_connected)
        else:
            return wait_connected()

    def openchannel(self, remote_node, capacity):
        addr = self.rpc.newaddr()['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, capacity / 10**6)
        tx = self.bitcoin.rpc.getrawtransaction(txid)
        self.rpc.addfunds(tx)
        self.rpc.fundchannel(remote_node.info['id'], capacity)
        self.daemon.wait_for_log('sendrawtx exit 0, gave')
        time.sleep(1)
        self.bitcoin.rpc.generate(6)
        self.daemon.wait_for_log('-> CHANNELD_NORMAL|STATE_NORMAL')

    def db_query(self, query):
        db = sqlite3.connect(os.path.join(self.daemon.lightning_dir, "lightningd.sqlite3"))
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
