import io
import json
import logging
import socket
import sys
import threading

class LightningRpc(object):
    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.socket = None
        self.buff = b''
        self.decoder = json.JSONDecoder()

    def connect_rpc(self):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.connect(self.socket_path)

    def _writeobj(self, obj):
        s = json.dumps(obj)
        self.socket.sendall(bytearray(s, 'UTF-8'))

    def _readobj(self):
        while True:
            try:
                self.buff += self.socket.recv(1024)
                # Convert late to UTF-8 so glyphs split across recvs do not
                # impact us
                objs, end = self.decoder.raw_decode(self.buff.decode("UTF-8"))

                # Strip any trailing newline, it'd confuse the decoder on the
                # next round.
                self.buff = self.buff[end:].strip()
                return objs
            except ValueError:
                # Probably didn't read enough 
                pass

    def _call(self, method, args):
        logging.debug("Calling %s with arguments %r", method, args)
        self._writeobj({
            "method": method,
            "params": args,
            "id": 0
        })
        resp = self._readobj()
        logging.debug("Received response for %s call: %r", method, resp)
        if 'error' in resp:
            raise ValueError("RPC call failed: {}".format(resp['error']))
        elif 'result' not in resp:
            raise ValueError("Malformed response, 'result' missing.")
        return resp['result']

    def getchannels(self):
        return self._call("getchannels", [])['channels']

    def getnodes(self):
        return self._call("getnodes", [])

    def getlog(self):
        return self._call("getlog", [])

    def getpeers(self):
        return self._call("getpeers", [])

    def getroute(self, destination, amount, riskfactor=1):
        return self._call("getroute", [destination, amount, riskfactor])['route']

    def getinfo(self):
        return self._call("getinfo", [])

    def invoice(self, amount, label):
        return self._call("invoice", [amount, label])

    def waitinvoice(self, label=None):
        args = []
        if label is not None:
            args.append(label)
        return self._call("waitinvoice", args)

    def awaitpayment(self, label):
        return self._call("awaitpayment", [label])

    def sendpay(self, route, paymenthash):
        return self._call("sendpay", [route, paymenthash])

    def pay(self, destination, amount, paymenthash):
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

    def getpeer(self, remote_id):
        peers = self.getpeers()


    def connect(self, hostname, port, fundingtxhex, async=False):
        def call_connect():
            return self._call("connect", [hostname, port, fundingtxhex])
        if not async:
            return call_connect()
        else:
            t = threading.Thread(target=call_connect)
            t.daemon = True
            t.start()
            return None

    def newaddr(self):
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
