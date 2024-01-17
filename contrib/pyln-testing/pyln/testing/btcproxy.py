""" A bitcoind proxy that allows instrumentation and canned responses
"""
from flask import Flask, request  # type: ignore
from bitcoin.rpc import JSONRPCError  # type: ignore
from bitcoin.rpc import RawProxy as BitcoinProxy  # type: ignore
from cheroot.wsgi import Server  # type: ignore
from cheroot.wsgi import PathInfoDispatcher  # type: ignore

import decimal
import flask  # type: ignore
import json
import logging
import threading


class DecimalEncoder(json.JSONEncoder):
    """By default json.dumps does not handle Decimals correctly, so we override it's handling
    """
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return "{:.8f}".format(float(o))
        return super(DecimalEncoder, self).default(o)


class BitcoinRpcProxy(object):
    def __init__(self, bitcoind, rpcport=0):
        self.app = Flask("BitcoindProxy")
        self.app.add_url_rule("/", "API entrypoint", self.proxy, methods=['POST'])
        self.rpcport = rpcport
        self.mocks = {}
        self.mock_counts = {}
        self.bitcoind = bitcoind
        self.request_count = 0

    def _handle_request(self, r):
        brpc = BitcoinProxy(btc_conf_file=self.bitcoind.conf_file)
        method = r['method']

        # If we have set a mock for this method reply with that instead of
        # forwarding the request.
        if method in self.mocks and self.mocks[method] is dict:
            ret = {}
            ret['id'] = r['id']
            ret['error'] = None
            ret['result'] = self.mocks[method]
            self.mock_counts[method] += 1
            return ret
        elif method in self.mocks and callable(self.mocks[method]):
            self.mock_counts[method] += 1
            return self.mocks[method](r)

        try:
            reply = {
                "result": brpc._call(r['method'], *r['params']),
                "error": None,
                "id": r['id']
            }
        except JSONRPCError as e:
            reply = {
                "error": e.error,
                "code": -32603,
                "id": r['id']
            }
        self.request_count += 1
        return reply

    def proxy(self):
        r = json.loads(request.data.decode('ASCII'))

        if isinstance(r, list):
            reply = [self._handle_request(subreq) for subreq in r]
        else:
            reply = self._handle_request(r)

        response = flask.Response(json.dumps(reply, cls=DecimalEncoder))
        response.headers['Content-Type'] = 'application/json'
        return response

    def start(self):
        d = PathInfoDispatcher({'/': self.app})
        self.server = Server(('0.0.0.0', self.rpcport), d)
        self.proxy_thread = threading.Thread(target=self.server.start)
        self.proxy_thread.daemon = True
        self.proxy_thread.start()

        # Now that bitcoind is running on the real rpcport, let's tell all
        # future callers to talk to the proxyport. We use the bind_addr as a
        # signal that the port is bound and accepting connections.
        while self.server.bind_addr[1] == 0:
            pass
        self.rpcport = self.server.bind_addr[1]
        logging.debug("BitcoinRpcProxy proxying incoming port {} to {}".format(self.rpcport, self.bitcoind.rpcport))

    def stop(self):
        self.server.stop()
        self.proxy_thread.join()
        logging.debug("BitcoinRpcProxy shut down after processing {} requests".format(self.request_count))

    def mock_rpc(self, method, response=None):
        """Mock the response to a future RPC call of @method

        The response can either be a dict with the full JSON-RPC response, or a
        function that returns such a response. If the response is None the mock
        is removed and future calls will be passed through to bitcoind again.

        """
        if response is not None:
            self.mocks[method] = response
            self.mock_counts[method] = 0
        elif method in self.mocks:
            del self.mocks[method]
