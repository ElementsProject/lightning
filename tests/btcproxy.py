""" A bitcoind proxy that allows instrumentation and canned responses
"""
from flask import Flask, request
from bitcoin.rpc import JSONRPCError
from bitcoin.rpc import RawProxy as BitcoinProxy
from utils import BitcoinD
from cheroot.wsgi import Server
from cheroot.wsgi import PathInfoDispatcher

import decimal
import json
import logging
import os
import threading


class DecimalEncoder(json.JSONEncoder):
    """By default json.dumps does not handle Decimals correctly, so we override it's handling
    """
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return str(o)
        return super(DecimalEncoder, self).default(o)


class ProxiedBitcoinD(BitcoinD):
    def __init__(self, bitcoin_dir, proxyport=0):
        BitcoinD.__init__(self, bitcoin_dir, rpcport=None)
        self.app = Flask("BitcoindProxy")
        self.app.add_url_rule("/", "API entrypoint", self.proxy, methods=['POST'])
        self.proxyport = proxyport

    def proxy(self):
        r = json.loads(request.data.decode('ASCII'))
        conf_file = os.path.join(self.bitcoin_dir, 'bitcoin.conf')
        brpc = BitcoinProxy(btc_conf_file=conf_file)

        try:
            reply = {
                "result": brpc._call(r['method'], *r['params']),
                "error": None,
                "id": r['id']
            }
        except JSONRPCError as e:
            reply = {
                "error": e.error,
                "id": r['id']
            }
        return json.dumps(reply, cls=DecimalEncoder)

    def start(self):
        d = PathInfoDispatcher({'/': self.app})
        self.server = Server(('0.0.0.0', self.proxyport), d)
        self.proxy_thread = threading.Thread(target=self.server.start)
        self.proxy_thread.daemon = True
        self.proxy_thread.start()
        BitcoinD.start(self)

        # Now that bitcoind is running on the real rpcport, let's tell all
        # future callers to talk to the proxyport. We use the bind_addr as a
        # signal that the port is bound and accepting connections.
        while self.server.bind_addr[1] == 0:
            pass
        self.proxiedport = self.rpcport
        self.rpcport = self.server.bind_addr[1]
        logging.debug("bitcoind reverse proxy listening on {}, forwarding to {}".format(
            self.rpcport, self.proxiedport
        ))

    def stop(self):
        BitcoinD.stop(self)
        self.server.stop()
        self.proxy_thread.join()


# The main entrypoint is mainly used to test the proxy. It is not used during
# lightningd testing.
if __name__ == "__main__":
    p = ProxiedBitcoinD(bitcoin_dir='/tmp/bitcoind-test/', proxyport=5000)
    p.start()
    p.proxy_thread.join()
