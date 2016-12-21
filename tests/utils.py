from bitcoinrpc.authproxy import AuthServiceProxy
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

    def __init__(self):
        self.logs = []
        self.logs_cond = threading.Condition(threading.Lock())
        self.thread = threading.Thread(target=self.tail)
        self.cmd_line = None
        self.running = False
        self.proc = None
        
    def start(self):
        logging.debug("Starting '%s'", " ".join(self.cmd_line))
        self.proc = subprocess.Popen(self.cmd_line, stdout=subprocess.PIPE)
        self.thread.start()
        self.running = True

    def stop(self):
        self.proc.terminate()
        self.proc.kill()

    def tail(self):
        for line in iter(self.proc.stdout.readline, ''):
            if len(line) == 0:
                break
            with self.logs_cond:
                self.logs.append(str(line.rstrip()))
                logging.debug("%s: '%s'", self.prefix, line.rstrip())
                self.logs_cond.notifyAll()
        self.running = False
    
    def wait_for_log(self, regex, offset=1000, timeout=60):
        """ Look for `regex` in the logs.
        """
        logging.debug("Waiting for '%s' in the logs", regex)
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

                if re.search(regex, self.logs[pos]):
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
            '/usr/bin/bitcoind',
            '-datadir={}'.format(bitcoin_dir),
            '-printtoconsole',
            '-server',
            '-regtest',
            '-debug',
            '-nolisten',
        ]
        BITCOIND_CONFIG['rpcport'] = rpcport
        write_config(os.path.join(bitcoin_dir, 'bitcoin.conf'), BITCOIND_CONFIG)
        write_config(os.path.join(regtestdir, 'bitcoin.conf'), BITCOIND_CONFIG)
        
        self.rpc = AuthServiceProxy("http://rpcuser:rpcpass@127.0.0.1:{}".format(rpcport))

    def start(self):
        TailableProc.start(self)
        self.wait_for_log("dnsseed thread exit", timeout=10)
        logging.info("BitcoinD started")

class LightningD(TailableProc):
    def __init__(self, lightning_dir, bitcoin_dir, port=9735):
        TailableProc.__init__(self)
        self.lightning_dir = lightning_dir
        self.port = port
        self.cmd_line = [
            'daemon/lightningd',
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
        self.wait_for_log("Hello world!")
        logging.info("LightningD started")

    def stop(self):
        TailableProc.stop(self)
        logging.info("LightningD stopped")

class LightningNode(object):
    def __init__(self, daemon, rpc, btc):
        self.rpc = rpc
        self.daemon = daemon
        self.bitcoin = btc

    def connect(self, remote_node, capacity):
        # Collect necessary information
        addr = self.rpc.newaddr()['address']
        txid = self.bitcoin.rpc.sendtoaddress(addr, capacity)
        tx = self.bitcoin.rpc.gettransaction(txid)

        # Now actually connect
        self.rpc.connect('127.0.0.1', remote_node.daemon.port, tx['hex'], async=True)

        # TODO(cdecker) Monitor the mempool to see if its time to generate yet.
        time.sleep(5)
        
        # The sleep should have given bitcoind time to add the tx to its mempool
        self.bitcoin.rpc.generate(1)

        # Now wait for confirmation
        self.daemon.wait_for_log("STATE_NORMAL")
        remote_node.daemon.wait_for_log("STATE_NORMAL")
