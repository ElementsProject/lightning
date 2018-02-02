import json
import logging
import socket


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None, logger=logging):
        self.socket_path = socket_path
        self.decoder = json.JSONDecoder()
        self.executor = executor
        self.logger = logger

    @staticmethod
    def _writeobj(sock, obj):
        s = json.dumps(obj)
        sock.sendall(bytearray(s, "UTF-8"))

    def _readobj(self, sock):
        buff = b""
        while True:
            try:
                b = sock.recv(1024)
                buff += b
                if len(b) == 0:
                    return {"error": "Connection to RPC server lost."}
                # Convert late to UTF-8 so glyphs split across recvs do not
                # impact us
                objs, _ = self.decoder.raw_decode(buff.decode("UTF-8"))
                return objs
            except ValueError:
                # Probably didn"t read enough
                pass

    def __getattr__(self, name):
        """Intercept any call that is not explicitly defined and call _call

        We might still want to define the actual methods in the subclasses for
        documentation purposes.
        """
        name = name.replace("_", "-")

        def wrapper(*args, **_):
            return self._call(name, args)
        return wrapper

    def _call(self, method, args=None):
        self.logger.debug("Calling %s with arguments %r", method, args)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self._writeobj(sock, {
            "method": method,
            "params": args or (),
            "id": 0
        })
        resp = self._readobj(sock)
        sock.close()

        self.logger.debug("Received response for %s call: %r", method, resp)
        if "error" in resp:
               raise ValueError(
                "RPC call failed: {}, method: {}, args: {}".format(
                    resp["error"],
                    method,
                    args
                ))
        elif "result" not in resp:
            raise ValueError("Malformed response, \"result\" missing.")
        return resp["result"]


class LightningRpc(UnixDomainSocketRpc):
    """
    RPC client for the `lightningd` daemon.

    This RPC client connects to the `lightningd` daemon through a unix
    domain socket and passes calls through. Since some of the calls
    are blocking, the corresponding python methods include an `async`
    keyword argument. If `async` is set to true then the met hod
    returns a future immediately, instead of blocking indefinitely.

    This implementation is thread safe in that it locks the socket
    between calls, but it does not (yet) support concurrent calls.

    Methods accept both keyword \ positional arguments or a json payload.
    i.e.
        client.getpeer("a_peer_id", level="debug")
        client.getpeer(id="a_peer_id", level="debug")
        client.getpeer("a_peer_id, "debug")
        client.getpeer({"peer_id": "a_peer_id, "logs": "debug"})
    """

    @staticmethod
    def _get_payload(args, kwargs, *required, optionals=()):
        if len(args) == 1 and isinstance(args[0], dict):
            return args[0]
        try:
            payload = {required[i]: args[i] for i in range(0, len(required))}
            if len(args) > len(required):
                for i, optional in enumerate(optionals[:len(args)-len(required)]):
                    payload.update({optional: args[len(required):][i]})
            payload.update(kwargs)
        except (IndexError, KeyError) as e:
            raise ValueError(
                "Wrong arguments, required args: [ {} ] , optionals: [ {} ].".format(
                    ", ".join(required), ", ".join(optionals),
                )
            ) from e
        return payload

    def getpeer(self, *args, **kwargs):
        """
        Show peer with {id}, if {level} is set, include {log}s
        """
        res = self.listpeers(
            self._get_payload(args, kwargs, "id", optionals=("level",))
        )
        return res.get("peers") and res["peers"][0] or None

    def dev_blockheight(self):
        """
        Show current block height
        """
        return self._call("dev-blockheight")

    def dev_setfees(self, *args, **kwargs):
        """
        Set feerate in satoshi-per-kw for {immediate}, {normal} and {slow}
        (each is optional, when set, separate by spaces) and show the value of those three feerates
        """
        return self._call(
            "dev-setfees",
            args=self._get_payload(args, kwargs, "immediate", optionals=("normal", "slow"))
        )

    def listnodes(self, *args, **kwargs):
        """
        Show all nodes in our local network view, filter on node {id} if provided
        """
        return self._call(
            "listnodes",
            args=self._get_payload(args, kwargs, optionals=("id",))
        )

    def getroute(self, *args, **kwargs):
        """
        Show route to {id} for {msatoshi}, using {riskfactor} and optional {cltv} (default 9)
        """
        return self._call(
            "getroute",
            args=self._get_payload(args, kwargs, "id", "msatoshi", "riskfactor", optionals=("cltv",))
        )

    def listchannels(self, *args, **kwargs):
        """
        Show all known channels, accept optional {short_channel_id}
        """
        return self._call(
            "listchannels",
            args=self._get_payload(args, kwargs, optionals=("short_channel_id",))
        )

    def invoice(self, *args, **kwargs):
        """
        Create an invoice for {msatoshi} with {label} and {description} with optional {expiry} seconds (default 1 hour)
        """
        return self._call(
            "invoice",
            self._get_payload(args, kwargs, "msatoshi", "label", "description", optionals=("expiry",))
        )

    def listinvoices(self, *args, **kwargs):
        """
        Show invoice {label} (or all, if no {label))
        """
        return self._call(
            "listinvoices",
            self._get_payload(args, kwargs, optionals=("label",))
        )

    def delinvoice(self, *args, **kwargs):
        """
        Delete unpaid invoice {label} with {status}
        """
        return self._call(
            "delinvoice",
            self._get_payload(args, kwargs, "label", "status")
        )

    def waitanyinvoice(self, *args, **kwargs):
        """
        Wait for the next invoice to be paid, after {lastpay_index} (if supplied)
        """
        return self._call(
            "waitanyinvoice",
            args=self._get_payload(args, kwargs, optionals=("lastpay_index",))
        )

    def waitinvoice(self, *args, **kwargs):
        """
        Wait for an incoming payment matching the invoice with {label}
        """
        return self._call(
            "waitinvoice",
            args=self._get_payload(args, kwargs, "label")
        )

    def decodepay(self, *args, **kwargs):
        """
        Decode {bolt11}, using {description} if necessary
        """
        return self._call(
            "decodepay",
            args=self._get_payload(args, kwargs, "bolt11", optionals=("description",))
        )

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

    def getlog(self, *args, **kwargs):
        """
        Show logs, with optional log {level} (info|unusual|debug|io)
        """
        return self._call(
            "getlog",
            args=self._get_payload(args, kwargs, optionals=("level",))
        )

    def dev_rhash(self, *args, **kwargs):
        """
        Show SHA256 of {secret}
        """
        return self._call(
            "dev-rhash",
            args=self._get_payload(args, kwargs, "secret")
        )

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

    def sendpay(self, *args, **kwargs):
        """
        Send along {route} in return for preimage of {rhash}
        """
        return self._call(
            "sendpay",
            args=self._get_payload(args, kwargs, "route", "rhash")
        )

    def pay(self, *args, **kwargs):
        """
        Send payment specified by {bolt11} with optional {msatoshi} (if and only if {bolt11} does not have amount),
        {description} (required if {bolt11} uses description hash) and {riskfactor} (default 1.0)
        """
        return self._call(
            "pay",
            args=self._get_payload(args, kwargs, "bolt11", optionals=("msatoshi", "description", "riskfactor"))
        )

    def listpayments(self, *args, **kwargs):
        """
        Show outgoing payments, regarding {bolt11} or {payment_hash} if set
        Can only specify one of {bolt11} or {payment_hash}
        """
        return self._call(
            "listpayments",
            args=self._get_payload(args, kwargs, optionals=("bolt11", "payment_hash"))
        )

    def connect(self, *args, **kwargs):
        """
        Connect to {peer_id} at {host} and {port}
        """
        return self._call(
            "connect",
            args=self._get_payload(args, kwargs, "id", optionals=("host", "port"))
        )

    def listpeers(self, *args, **kwargs):
        """
        Show current peers, if {level} is set, include {log}s"
        """
        return self._call(
            "listpeers",
            args=self._get_payload(args, kwargs, optionals=("id", "level"))
        )

    def fundchannel(self, *args, **kwargs):
        """
        Fund channel with {id} using {satoshi} satoshis"
        """
        return self._call(
            "fundchannel",
            args=self._get_payload(args, kwargs, "id", "satoshi")
        )

    def close(self, *args, **kwargs):
        """
        Close the channel with peer {id}
        """
        return self._call(
            "close",
            args=self._get_payload(args, kwargs, "id")
        )

    def dev_sign_last_tx(self, *args, **kwargs):
        """
        Sign and show the last commitment transaction with peer {id}
        """
        return self._call(
            "dev-sign-last-tx",
            args=self._get_payload(args, kwargs, "id")
        )

    def dev_fail(self, *args, **kwargs):
        """
        Fail with peer {peer_id}
        """
        return self._call(
            "dev-fail",
            args=self._get_payload(args, kwargs, "id")
        )

    def dev_reenable_commit(self, *args, **kwargs):
        """
        Re-enable the commit timer on peer {id}
        """
        return self._call(
            "dev-reenable-commit",
            args=self._get_payload(args, kwargs, "id")
        )

    def dev_ping(self, *args, **kwargs):
        """
        Send {peer_id} a ping of length {len} asking for {pongbytes}"
        """
        return self._call(
            "dev-ping",
            args=self._get_payload(args, kwargs, "id", "len", "pongbytes")
        )

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

    def withdraw(self, *args, **kwargs):
        """
        Send to {destination} address {satoshi} (or "all") amount via Bitcoin transaction
        """
        return self._call(
            "withdraw",
            args=self._get_payload(args, kwargs, "destination", "satoshi")
        )

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

    def dev_rescan_outputs(self):
        """
        Synchronize the state of our funds with bitcoind
        """
        return self._call("dev-rescan-outputs")
