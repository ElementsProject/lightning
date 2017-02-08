from bitcoin.rpc import RawProxy as BitcoinProxy
from lightning import LightningRpc

import logging
import os
import re
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

    def __init__(self):
        self.logs = []
        self.logs_cond = threading.Condition(threading.RLock())
        self.thread = threading.Thread(target=self.tail)
        self.thread.daemon = True
        self.cmd_line = None
        self.running = False
        self.proc = None
        
    def start(self):
        """Start the underlying process and start monitoring it.
        """
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line, stdout=subprocess.PIPE)
        self.thread.start()
        self.running = True

    def stop(self):
        self.proc.terminate()
        self.proc.kill()

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
    
    def wait_for_log(self, regex, offset=1000, timeout=60):
        """Look for `regex` in the logs.

        We tail the stdout of the process and look for `regex`,
        starting from `offset` lines in the past. We fail if the
        timeout is exceeded or if the underlying process exits before
        the `regex` was found. The reason we start `offset` lines in
        the past is so that we can issue a command and not miss its
        effects.

        """
        logging.debug("Waiting for '%s' in the logs", regex)
        ex = re.compile(regex)
        start_time = time.time()
        pos = max(len(self.logs) - offset, 0)
        while True:
            
            if time.time() > start_time + timeout:
                raise TimeoutError('Unable to find "{}" in logs.'.format(regex))
            elif not self.running:
                raise ValueError('Process died while waiting for logs')

            with self.logs_cond:
                if pos >= len(self.logs):
                    self.logs_cond.wait(1)
                    continue

                if ex.search(self.logs[pos]):
                    logging.debug("Found '%s' in logs", regex)
                    return self.logs[pos]
                pos += 1


class BitcoinD(TailableProc):

    def __init__(self, bitcoin_dir="/tmp/bitcoind-test", rpcport=18332):
        TailableProc.__init__(self)
        
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
            '-debug',
            '-logtimestamps',
            '-nolisten',
        ]
        BITCOIND_CONFIG['rpcport'] = rpcport
        write_config(os.path.join(bitcoin_dir, 'bitcoin.conf'), BITCOIND_CONFIG)
        write_config(os.path.join(regtestdir, 'bitcoin.conf'), BITCOIND_CONFIG)
        self.rpc = BitcoinProxy(
            "http://rpcuser:rpcpass@127.0.0.1:{}".format(self.rpcport))

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Done loading", timeout=10)

        logging.info("BitcoinD started")


class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoin_dir, port=9735):
        TailableProc.__init__(self)
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_line = [
            'lightningd/lightningd',
            '--bitcoin-datadir={}'.format(bitcoin_dir),
            '--lightning-dir={}'.format(lightning_dir),
            '--port={}'.format(port),
            '--disable-irc',
            '--bitcoind-regtest',
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

class LegacyLightningD(LightningD):
    def __init__(self, *args, **kwargs):
        LightningD.__init__(self, *args, **kwargs)
        self.cmd_line[0] = 'daemon/lightningd'

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("Hello world!")
        logging.info("LightningD started")


class LightningNode(object):
    def __init__(self, daemon, rpc, btc, executor):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc
        self.executor = executor

    def connect(self, remote_node, capacity, async=False):
        # Collect necessary information
        addr = self.rpc.newaddr()['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, capacity)
        tx = self.bitcoin.rpc.gettransaction(txid)

        def call_connect():
            self.rpc.connect('127.0.0.1', remote_node.daemon.port, tx['hex'], async=False)
        t = threading.Thread(target=call_connect)
        t.daemon = True
        t.start()
        
        def wait_connected():
            # TODO(cdecker) Monitor the mempool to see if its time to generate yet.
            time.sleep(5)
        
            # The sleep should have given bitcoind time to add the tx to its mempool
            self.bitcoin.rpc.generate(1)

            #fut.result(timeout=5)

            # Now wait for confirmation
            self.daemon.wait_for_log("STATE_NORMAL")
            remote_node.daemon.wait_for_log("STATE_NORMAL")

        if async:
            return self.executor.submit(wait_connected)
        else:
            return wait_connected()
