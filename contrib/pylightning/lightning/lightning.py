from concurrent import futures

import io
import json
import logging
import socket
import sys
import threading

class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None):
        self.socket_path = socket_path
        self.decoder = json.JSONDecoder()
        self.executor = executor

    def _writeobj(self, sock, obj):
        s = json.dumps(obj)
        sock.sendall(bytearray(s, 'UTF-8'))

    def _readobj(self, sock):
        buff = b''
        while True:
            try:
                b = sock.recv(1024)
                buff += b
                if len(b) == 0:
                    return {'error': 'Connection to RPC server lost.'}
                # Convert late to UTF-8 so glyphs split across recvs do not
                # impact us
                objs, _ = self.decoder.raw_decode(buff.decode("UTF-8"))
                return objs
            except ValueError:
                # Probably didn't read enough 
                pass

    def __getattr__(self, name):
        """Intercept any call that is not explicitly defined and call _call

        We might still want to define the actual methods in the subclasses for
        documentation purposes.
        """
        name = name.replace('_', '-')
        def wrapper(*args, **kwargs):
            return self._call(name, args)
        return wrapper

    def _call(self, method, args):
        logging.debug("Calling %s with arguments %r", method, args)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self._writeobj(sock, {
            "method": method,
            "params": args,
            "id": 0
        })
        resp = self._readobj(sock)
        sock.close()

        logging.debug("Received response for %s call: %r", method, resp)
        if 'error' in resp:
            raise ValueError("RPC call failed: {}".format(resp['error']))
        elif 'result' not in resp:
            raise ValueError("Malformed response, 'result' missing.")
        return resp['result']


class LightningRpc(UnixDomainSocketRpc):
    """RPC client for the `lightningd` daemon.

    This RPC client connects to the `lightningd` daemon through a unix
    domain socket and passes calls through. Since some of the calls
    are blocking, the corresponding python methods include an `async`
    keyword argument. If `async` is set to true then the method
    returns a future immediately, instead of blocking indefinitely.

    This implementation is thread safe in that it locks the socket
    between calls, but it does not (yet) support concurrent calls.
    """

    def getpeer(self, peer_id, log_level=None):
        """Get info about a specific peer, optionally with its log.
        """
        if log_level:
            peers = self.getpeers(log_level)['peers']
        else:
            peers = self.getpeers()['peers']
        for p in peers:
            if p['peerid'] == peer_id:
                return p
        return None

    def getlog(self, level=None):
        args = []
        if level is not None:
            args.append(level)
        return self._call("getlog", args)

    def dev_add_route(self, src, dst, base, var, delay, minblocks):
        """ Add a route from src to dst using the given parameters.

        Add route from {src} to {dst}, {base} rate in msatoshi, {var} rate in
        msatoshi, {delay} blocks delay and {minblocks} minimum timeout
        """
        return self._call("dev-add-route", [src, dst, base, var, delay, minblocks])


class LegacyLightningRpc(UnixDomainSocketRpc):
    def getchannels(self):
        """List all known channels.
        """
        return self._call("getchannels", [])['channels']

    def getnodes(self):
        """List all known nodes in the network.
        """
        return self._call("getnodes", [])

    def getlog(self, level=None):
        """Get logs, with optional level: [io|debug|info|unusual]
        """
        return self._call("getlog", [level])

    def getpeers(self):
        """Return a list of peers.
        """
        return self._call("getpeers", [])

    def getroute(self, destination, amount, riskfactor=1):
        """Return route to `destination` for `amount` milli satoshis, using `riskfactor`
        """
        return self._call("getroute", [destination, amount, riskfactor])['route']

    def getinfo(self):
        """Get general information about this node"""
        return self._call("getinfo", [])

    def invoice(self, amount, label, paymentKey=None):
        """Create a new invoice.

        Create invoice for `amount` millisatoshi with
        `label`. Optionally you can specify the `paymentKey`,
        otherwise a random one will be generated. The `label` has to
        be unique.
        """
        args = [amount, label]
        if paymentKey is not None:
            args.append(paymentKey)
        return self._call("invoice", args)

    def waitinvoice(self, label=None, async=False):
        """Wait for the next invoice to be paid, after `label` (if supplied)
        """
        args = []
        if label is not None:
            args.append(label)
        def call():
            return self._call("waitinvoice", args)
        if async:
            return self.executor.submit(call)
        else:
            return call()

    def sendpay(self, route, paymenthash):
        """Send along `route` in return for preimage of `paymenthash`
        """
        return self._call("sendpay", [route, paymenthash])

    def pay(self, destination, amount, paymenthash):
        """Shorthand for `getroute` and `sendpay`

        Sends `amount` millisatoshi to `destination` for invoice matching `paymenthash`
        """
        route = self.getroute(destination, amount, 1)
        return self.sendpay(route, paymenthash)

    def dev_rhash(self, secret):
        res = self._call("dev-rhash", [secret])
        print(res)
        return self._call("dev-rhash", [secret])['rhash']

    def dev_newhtlc(self, peerid, amount, expiry, rhash):
        return self._call("dev-newhtlc", [peerid, amount, expiry, rhash])

    def dev_add_route(self, src, dst, base_fee, fee_rate, delay, minblocks):
        return self._call("dev-add-route", [src, dst, base_fee, fee_rate, delay, minblocks])

    def connect(self, hostname, port, fundingtxhex, async=False):
        """Connect to a `host` at `port` using `fundingtxhex` to fund
        """
        def call_connect():
            return self._call("connect", [hostname, port, fundingtxhex])

        if not async:
            return call_connect()
        else:
            return self.executor.submit(call_connect)

    def newaddr(self):
        """Get a new address to fund a channel
        """
        return self._call("newaddr", [])

if __name__ == "__main__":
    l1 = LightningRpc("/tmp/lightning1/lightning-rpc")
    l1.connect_rpc()
    l5 = LightningRpc("/tmp/lightning5/lightning-rpc")
    l5.connect_rpc()

    import random

    info5 = l5.getinfo()
    print(info5)
    invoice = l5.invoice(100, "lbl{}".format(random.random()))
    print(invoice)
    route = l1.getroute(info5['id'], 100, 1)
    print(route)
    print(l1.sendpay(route, invoice['rhash']))
