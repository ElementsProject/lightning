from concurrent import futures

import json
import logging
import socket


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None):
        self.socket_path = socket_path
        self.decoder = json.JSONDecoder()
        self.executor = executor

    @staticmethod
    def _writeobj(sock, obj):
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

        def wrapper(*args, **_):
            return self._call(name, args)
        return wrapper

    def _call(self, method, args=None):
        logging.debug("Calling %s with arguments %r", method, args)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self._writeobj(sock, {
            "method": method,
            "params": args or (),
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
    """
    RPC client for the `lightningd` daemon.

    This RPC client connects to the `lightningd` daemon through a unix
    domain socket and passes calls through. Since some of the calls
    are blocking, the corresponding python methods include an `async`
    keyword argument. If `async` is set to true then the method
    returns a future immediately, instead of blocking indefinitely.

    This implementation is thread safe in that it locks the socket
    between calls, but it does not (yet) support concurrent calls.
    """

    def getpeer(self, peer_id, logs=None):
        """
        Show peer with {peer_id}, if {level} is set, include {log}s
        """
        args = [peer_id]
        logs is not None and args.append(logs)
        res = self.listpeers(peer_id, logs)
        return res.get('peers') and res['peers'][0] or None

    def dev_blockheight(self):
        """
        Show current block height
        """
        return self._call("dev-blockheight")

    def dev_setfees(self, immediate, normal=None, slow=None):
        """
        Set feerate in satoshi-per-kw for {immediate}, {normal} and {slow}
        (each is optional, when set, separate by spaces) and show the value of those three feerates
        """
        args = [immediate]
        normal is not None and args.append(normal)
        slow is not None and args.append(slow)
        return self._call("dev-setfees", args=args)

    def listnodes(self, node_id=None):
        """
        Show all nodes in our local network view
        """
        return self._call("listnodes", args=node_id and [node_id])

    def getroute(self, peer_id, msatoshi, riskfactor, cltv=None):
        """
        Show route to {peer_id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9)
        """
        args = [peer_id, msatoshi, riskfactor]
        cltv is not None and args.append(cltv)
        return self._call("getroute", args=args)

    def listchannels(self, short_channel_id=None):
        """
        Show all known channels
        """
        return self._call("listchannels", args=short_channel_id and [short_channel_id])

    def invoice(self, msatoshi, label, description, expiry=None):
        """
        Create an invoice for {msatoshi} with {label} and {description} with optional {expiry} seconds (default 1 hour)
        """
        args = [msatoshi, label, description]
        expiry is not None and args.append(expiry)
        return self._call("invoice", args=args)

    def listinvoices(self, label=None):
        """
        Show invoice {label} (or all, if no {label})
        """
        return self._call("listinvoices", args=label and [label])

    def delinvoice(self, label, status):
        """
        Delete unpaid invoice {label} with {status}
        """
        return self._call("delinvoice", args=[label, status])

    def waitanyinvoice(self, lastpay_index=None):
        """
        Wait for the next invoice to be paid, after {lastpay_index} (if supplied)
        """
        return self._call("waitanyinvoice", args=lastpay_index and [lastpay_index])

    def waitinvoice(self, label):
        """
        Wait for an incoming payment matching the invoice with {label}
        """
        return self._call("waitinvoice", args=[label])

    def decodepay(self, bolt11, description=None):
        """
        Decode {bolt11}, using {description} if necessary
        """
        args = [bolt11]
        description is not None and args.append(description)
        return self._call("decodepay", args=args)

    def help(self):
        """
        Show available commands
        """
        return self._call("help")

    def stop(self):
        """
        Shut down the lightningd process
        """
        return self._call("stop")

    def getlog(self, level=None):
        """
        Show logs, with optional log {level} (info|unusual|debug|io)
        """
        return self._call("getlog", args=level and [level])

    def dev_rhash(self, secret):
        """
        Show SHA256 of {secret}
        """
        return self._call("dev-rhash", [secret])

    def dev_crash(self):
        """
        Crash lightningd by calling fatal()
        """
        return self._call("dev-crash")

    def getinfo(self):
        """
        Show information about this node
        """
        return self._call("getinfo")

    def sendpay(self, route, rhash):
        """
        Send along {route} in return for preimage of {rhash}
        """
        return self._call("sendpay", args=[route, rhash])

    def pay(self, bolt11, msatoshi=None, description=None, riskfactor=None):
        """
        Send payment specified by {bolt11} with optional {msatoshi} (if and only if {bolt11} does not have amount),
        {description} (required if {bolt11} uses description hash) and {riskfactor} (default 1.0)
        """
        args = [bolt11]
        msatoshi is not None and args.append(msatoshi)
        description is not None and args.append(description)
        riskfactor is not None and args.append(riskfactor)
        return self._call("pay", args=args)

    def listpayments(self):
        """
        Show outgoing payments
        """
        return self._call("listpayments")

    def connect(self, peer_id, host=None, port=None):
        """
        Connect to {peer_id} at {host} and {port}
        """
        args = [peer_id]
        host is not None and args.append(host)
        port is not None and args.append(port)
        return self._call("connect", args=args)

    def listpeers(self, peer_id=None, logs=None):
        """
        Show current peers, if {level} is set, include {log}s"
        """
        args = peer_id is not None and [peer_id] or []
        logs is not None and args.append(logs)
        return self._call("listpeers", args=args)

    def fundchannel(self, peer_id, satoshi):
        """
        Fund channel with {id} using {satoshi} satoshis"
        """
        return self._call("fundchannel", args=[peer_id, satoshi])

    def close(self, peer_id):
        """
        Close the channel with peer {peer_id}
        """
        return self._call("close", args=[peer_id])

    def dev_sign_last_tx(self, peer_id):
        """
        Sign and show the last commitment transaction with peer {id}
        """
        return self._call("dev-sign-last-tx", args=[peer_id])

    def dev_fail(self, peer_id):
        """
        Fail with peer {peer_id}
        """
        return self._call("dev-fail", args=[peer_id])

    def dev_reenable_commit(self, peer_id):
        """
        Re-enable the commit timer on peer {peer_id}
        """
        return self._call("dev-reenable-commit", args=[peer_id])

    def dev_ping(self, peer_id, length, pongbytes):
        """
        Send {peer_id} a ping of length {length} asking for {pongbytes}"
        """
        return self._call("dev-ping", args=[peer_id, length, pongbytes])

    def dev_memdump(self):
        """
        Show memory objects currently in use
        """
        return self._call("dev-memdump")

    def dev_memleak(self):
        """
        Show unreferenced memory objects
        """
        return self._call("dev-memleak")

    def withdraw(self, destination, satoshi):
        """
        Send to {destination} address {satoshi} (or 'all') amount via Bitcoin transaction
        """
        return self._call("withdraw", args=[destination, satoshi])

    def newaddr(self):
        """
        Get a new address to fund a channel
        """
        return self._call("newaddr")

    def listfunds(self):
        """
        Show funds available for opening channels
        """
        return self._call("listfunds")
