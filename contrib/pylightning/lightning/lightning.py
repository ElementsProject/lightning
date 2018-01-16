from concurrent import futures

import json
import logging
import socket

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
            peers = self.listpeers(peer_id, log_level)['peers']
        else:
            peers = self.listpeers(peer_id)['peers']
        if len(peers) == 0:
            return None
        return peers[0]

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



if __name__ == "__main__":
    l1 = LightningRpc("/tmp/lightning1/lightning-rpc")
    l5 = LightningRpc("/tmp/lightning5/lightning-rpc")

    import random

    info5 = l5.getinfo()
    print(info5)
    invoice = l5.invoice(100, "lbl{}".format(random.random()), "testpayment")
    print(invoice)
    route = l1.getroute(info5['id'], 100, 1)
    print(route)
    print(l1.sendpay(route['route'], invoice['payment_hash']))
