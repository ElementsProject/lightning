from decimal import Decimal
import json
import logging
import socket

__version__ = "0.0.7.1"


class RpcError(ValueError):
    def __init__(self, method, payload, error):
        super(ValueError, self).__init__("RPC call failed: method: {}, payload: {}, error: {}"
                                         .format(method, payload, error))

        self.method = method
        self.payload = payload
        self.error = error


class Millisatoshi:
    """
    A subtype to represent thousandths of a satoshi.

    Many JSON API fields are expressed in millisatoshis: these automatically get
    turned into Millisatoshi types.  Converts to and from int.
    """
    def __init__(self, v):
        """
        Takes either a string ending in 'msat', 'sat', 'btc' or an integer.
        """
        if isinstance(v, str):
            if v.endswith("msat"):
                self.millisatoshis = int(v[0:-4])
            elif v.endswith("sat"):
                self.millisatoshis = Decimal(v[0:-3]) * 1000
            elif v.endswith("btc"):
                self.millisatoshis = Decimal(v[0:-3]) * 1000 * 10**8
            if self.millisatoshis != int(self.millisatoshis):
                raise ValueError("Millisatoshi must be a whole number")
        elif isinstance(v, Millisatoshi):
            self.millisatoshis = v.millisatoshis
        elif int(v) == v:
            self.millisatoshis = v
        else:
            raise TypeError("Millisatoshi must be string with msat/sat/btc suffix or int")

        if self.millisatoshis < 0:
            raise ValueError("Millisatoshi must be >= 0")

    def __repr__(self):
        """
        Appends the 'msat' as expected for this type.
        """
        return str(self.millisatoshis) + "msat"

    def to_satoshi(self):
        """
        Return a Decimal representing the number of satoshis
        """
        return Decimal(self.millisatoshis) / 1000

    def to_btc(self):
        """
        Return a Decimal representing the number of bitcoin
        """
        return Decimal(self.millisatoshis) / 1000 / 10**8

    def to_satoshi_str(self):
        """
        Return a string of form 1234sat or 1234.567sat.
        """
        if self.millisatoshis % 1000:
            return '{:.3f}sat'.format(self.to_satoshi())
        else:
            return '{:.0f}sat'.format(self.to_satoshi())

    def to_btc_str(self):
        """
        Return a string of form 12.34567890btc or 12.34567890123btc.
        """
        if self.millisatoshis % 1000:
            return '{:.8f}btc'.format(self.to_btc())
        else:
            return '{:.11f}btc'.format(self.to_btc())

    def to_json(self):
        return self.__repr__()

    def __int__(self):
        return self.millisatoshis

    def __lt__(self, other):
        return self.millisatoshis < other.millisatoshis

    def __le__(self, other):
        return self.millisatoshis <= other.millisatoshis

    def __eq__(self, other):
        return self.millisatoshis == other.millisatoshis

    def __gt__(self, other):
        return self.millisatoshis > other.millisatoshis

    def __ge__(self, other):
        return self.millisatoshis >= other.millisatoshis

    def __add__(self, other):
        return Millisatoshi(int(self) + int(other))

    def __sub__(self, other):
        return Millisatoshi(int(self) - int(other))

    def __mul__(self, other):
        return Millisatoshi(int(self) * other)

    def __truediv__(self, other):
        return Millisatoshi(int(self) / other)

    def __floordiv__(self, other):
        return Millisatoshi(int(self) // other)

    def __mod__(self, other):
        return Millisatoshi(int(self) % other)


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None, logger=logging, encoder_cls=json.JSONEncoder, decoder=json.JSONDecoder()):
        self.socket_path = socket_path
        self.encoder_cls = encoder_cls
        self.decoder = decoder
        self.executor = executor
        self.logger = logger

        # Do we require the compatibility mode?
        self._compat = True
        self.next_id = 0

    def _writeobj(self, sock, obj):
        s = json.dumps(obj, cls=self.encoder_cls)
        sock.sendall(bytearray(s, 'UTF-8'))

    def _readobj_compat(self, sock, buff=b''):
        if not self._compat:
            return self._readobj(sock, buff)
        while True:
            try:
                b = sock.recv(max(1024, len(buff)))
                buff += b

                if b'\n\n' in buff:
                    # The next read will use the non-compatible read instead
                    self._compat = False

                if len(b) == 0:
                    return {'error': 'Connection to RPC server lost.'}
                if b' }\n' not in buff:
                    continue
                # Convert late to UTF-8 so glyphs split across recvs do not
                # impact us
                buff = buff.decode("UTF-8")
                objs, len_used = self.decoder.raw_decode(buff)
                buff = buff[len_used:].lstrip().encode("UTF-8")
                return objs, buff
            except ValueError:
                # Probably didn't read enough
                buff = buff.lstrip().encode("UTF-8")

    def _readobj(self, sock, buff=b''):
        """Read a JSON object, starting with buff; returns object and any buffer left over"""
        while True:
            parts = buff.split(b'\n\n', 1)
            if len(parts) == 1:
                # Didn't read enough.
                b = sock.recv(max(1024, len(buff)))
                buff += b
                if len(b) == 0:
                    return {'error': 'Connection to RPC server lost.'}, buff
            else:
                buff = parts[1]
                obj, _ = self.decoder.raw_decode(parts[0].decode("UTF-8"))
                return obj, buff

    def __getattr__(self, name):
        """Intercept any call that is not explicitly defined and call @call

        We might still want to define the actual methods in the subclasses for
        documentation purposes.
        """
        name = name.replace('_', '-')

        def wrapper(*args, **kwargs):
            if len(args) != 0 and len(kwargs) != 0:
                raise RpcError("Cannot mix positional and non-positional arguments")
            elif len(args) != 0:
                return self.call(name, payload=args)
            else:
                return self.call(name, payload=kwargs)
        return wrapper

    def call(self, method, payload=None):
        self.logger.debug("Calling %s with payload %r", method, payload)

        if payload is None:
            payload = {}
        # Filter out arguments that are None
        if isinstance(payload, dict):
            payload = {k: v for k, v in payload.items() if v is not None}

        # FIXME: we open a new socket for every readobj call...
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self._writeobj(sock, {
            "method": method,
            "params": payload,
            "id": self.next_id,
        })
        self.next_id += 1
        resp, _ = self._readobj_compat(sock)
        sock.close()

        self.logger.debug("Received response for %s call: %r", method, resp)
        if "error" in resp:
            raise RpcError(method, payload, resp['error'])
        elif "result" not in resp:
            raise ValueError("Malformed response, \"result\" missing.")
        return resp["result"]


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

    class LightningJSONEncoder(json.JSONEncoder):
        def default(self, o):
            try:
                return o.to_json()
            except NameError:
                pass
            return json.JSONEncoder.default(self, o)

    class LightningJSONDecoder(json.JSONDecoder):
        def __init__(self, *, object_hook=None, parse_float=None, parse_int=None, parse_constant=None, strict=True, object_pairs_hook=None):
            self.object_hook_next = object_hook
            super().__init__(object_hook=self.millisatoshi_hook, parse_float=parse_float, parse_int=parse_int, parse_constant=parse_constant, strict=strict, object_pairs_hook=object_pairs_hook)

        @staticmethod
        def replace_amounts(obj):
            """
            Recursively replace _msat fields with appropriate values with Millisatoshi.
            """
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.endswith('msat'):
                        if isinstance(v, str) and v.endswith('msat'):
                            obj[k] = Millisatoshi(v)
                        # Special case for array of msat values
                        elif isinstance(v, list) and all(isinstance(e, str) and e.endswith('msat') for e in v):
                            obj[k] = [Millisatoshi(e) for e in v]
                    else:
                        obj[k] = LightningRpc.LightningJSONDecoder.replace_amounts(v)
            elif isinstance(obj, list):
                obj = [LightningRpc.LightningJSONDecoder.replace_amounts(e) for e in obj]

            return obj

        def millisatoshi_hook(self, obj):
            obj = LightningRpc.LightningJSONDecoder.replace_amounts(obj)
            if self.object_hook_next:
                obj = self.object_hook_next(obj)
            return obj

    def __init__(self, socket_path, executor=None, logger=logging):
        super().__init__(socket_path, executor, logging, self.LightningJSONEncoder, self.LightningJSONDecoder())

    def getpeer(self, peer_id, level=None):
        """
        Show peer with {peer_id}, if {level} is set, include {log}s
        """
        payload = {
            "id": peer_id,
            "level": level
        }
        res = self.call("listpeers", payload)
        return res.get("peers") and res["peers"][0] or None

    def listnodes(self, node_id=None):
        """
        Show all nodes in our local network view, filter on node {id}
        if provided
        """
        payload = {
            "id": node_id
        }
        return self.call("listnodes", payload)

    def getroute(self, node_id, msatoshi, riskfactor, cltv=9, fromid=None, fuzzpercent=None, seed=None, exclude=[]):
        """
        Show route to {id} for {msatoshi}, using {riskfactor} and optional
        {cltv} (default 9). If specified search from {fromid} otherwise use
        this node as source. Randomize the route with up to {fuzzpercent}
        (0.0 -> 100.0, default 5.0) using {seed} as an arbitrary-size string
        seed. {exclude} is an optional array of scid/direction to exclude.
        """
        payload = {
            "id": node_id,
            "msatoshi": msatoshi,
            "riskfactor": riskfactor,
            "cltv": cltv,
            "fromid": fromid,
            "fuzzpercent": fuzzpercent,
            "seed": seed,
            "exclude": exclude
        }
        return self.call("getroute", payload)

    def listchannels(self, short_channel_id=None, source=None):
        """
        Show all known channels, accept optional {short_channel_id} or {source}
        """
        payload = {
            "short_channel_id": short_channel_id,
            "source": source
        }
        return self.call("listchannels", payload)

    def invoice(self, msatoshi, label, description, expiry=None, fallbacks=None, preimage=None, exposeprivatechannels=None):
        """
        Create an invoice for {msatoshi} with {label} and {description} with
        optional {expiry} seconds (default 1 hour)
        """
        payload = {
            "msatoshi": msatoshi,
            "label": label,
            "description": description,
            "expiry": expiry,
            "fallbacks": fallbacks,
            "preimage": preimage,
            "exposeprivatechannels": exposeprivatechannels
        }
        return self.call("invoice", payload)

    def listinvoices(self, label=None):
        """
        Show invoice {label} (or all, if no {label))
        """
        payload = {
            "label": label
        }
        return self.call("listinvoices", payload)

    def delinvoice(self, label, status):
        """
        Delete unpaid invoice {label} with {status}
        """
        payload = {
            "label": label,
            "status": status
        }
        return self.call("delinvoice", payload)

    def waitanyinvoice(self, lastpay_index=None):
        """
        Wait for the next invoice to be paid, after {lastpay_index}
        (if supplied)
        """
        payload = {
            "lastpay_index": lastpay_index
        }
        return self.call("waitanyinvoice", payload)

    def waitinvoice(self, label):
        """
        Wait for an incoming payment matching the invoice with {label}
        """
        payload = {
            "label": label
        }
        return self.call("waitinvoice", payload)

    def decodepay(self, bolt11, description=None):
        """
        Decode {bolt11}, using {description} if necessary
        """
        payload = {
            "bolt11": bolt11,
            "description": description
        }
        return self.call("decodepay", payload)

    def help(self, command=None):
        """
        Show available commands, or just {command} if supplied.
        """
        payload = {
            "command": command,
        }
        return self.call("help", payload)

    def stop(self):
        """
        Shut down the lightningd process
        """
        return self.call("stop")

    def getlog(self, level=None):
        """
        Show logs, with optional log {level} (info|unusual|debug|io)
        """
        payload = {
            "level": level
        }
        return self.call("getlog", payload)

    def dev_rhash(self, secret):
        """
        Show SHA256 of {secret}
        """
        payload = {
            "secret": secret
        }
        return self.call("dev-rhash", payload)

    def dev_crash(self):
        """
        Crash lightningd by calling fatal()
        """
        return self.call("dev-crash")

    def dev_query_scids(self, id, scids):
        """
        Ask peer for a particular set of scids
        """
        payload = {
            "id": id,
            "scids": scids
        }
        return self.call("dev-query-scids", payload)

    def getinfo(self):
        """
        Show information about this node
        """
        return self.call("getinfo")

    def sendpay(self, route, payment_hash, description=None, msatoshi=None):
        """
        Send along {route} in return for preimage of {payment_hash}
        """
        payload = {
            "route": route,
            "payment_hash": payment_hash,
            "description": description,
            "msatoshi": msatoshi,
        }
        return self.call("sendpay", payload)

    def waitsendpay(self, payment_hash, timeout=None):
        """
        Wait for payment for preimage of {payment_hash} to complete
        """
        payload = {
            "payment_hash": payment_hash,
            "timeout": timeout
        }
        return self.call("waitsendpay", payload)

    def pay(self, bolt11, msatoshi=None, label=None, riskfactor=None, description=None):
        """
        Send payment specified by {bolt11} with {msatoshi}
        (ignored if {bolt11} has an amount), optional {label}
        and {riskfactor} (default 1.0)
        """
        payload = {
            "bolt11": bolt11,
            "msatoshi": msatoshi,
            "label": label,
            "riskfactor": riskfactor,
            # Deprecated.
            "description": description,
        }
        return self.call("pay", payload)

    def listpayments(self, bolt11=None, payment_hash=None):
        """
        Show outgoing payments, regarding {bolt11} or {payment_hash} if set
        Can only specify one of {bolt11} or {payment_hash}
        """
        assert not (bolt11 and payment_hash)
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash
        }
        return self.call("listpayments", payload)

    def connect(self, peer_id, host=None, port=None):
        """
        Connect to {peer_id} at {host} and {port}
        """
        payload = {
            "id": peer_id,
            "host": host,
            "port": port
        }
        return self.call("connect", payload)

    def listpeers(self, peerid=None, level=None):
        """
        Show current peers, if {level} is set, include {log}s"
        """
        payload = {
            "id": peerid,
            "level": level,
        }
        return self.call("listpeers", payload)

    def fundchannel(self, node_id, satoshi, feerate=None, announce=True, minconf=None):
        """
        Fund channel with {id} using {satoshi} satoshis
        with feerate of {feerate} (uses default feerate if unset).
        If {announce} is False, don't send channel announcements.
        Only select outputs with {minconf} confirmations
        """
        payload = {
            "id": node_id,
            "satoshi": satoshi,
            "feerate": feerate,
            "announce": announce,
            "minconf": minconf,
        }
        return self.call("fundchannel", payload)

    def close(self, peer_id, force=None, timeout=None):
        """
        Close the channel with peer {id}, forcing a unilateral
        close if {force} is True, and timing out with {timeout}
        seconds.
        """
        payload = {
            "id": peer_id,
            "force": force,
            "timeout": timeout
        }
        return self.call("close", payload)

    def dev_sign_last_tx(self, peer_id):
        """
        Sign and show the last commitment transaction with peer {id}
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-sign-last-tx", payload)

    def dev_fail(self, peer_id):
        """
        Fail with peer {peer_id}
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-fail", payload)

    def dev_reenable_commit(self, peer_id):
        """
        Re-enable the commit timer on peer {id}
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-reenable-commit", payload)

    def ping(self, peer_id, length=128, pongbytes=128):
        """
        Send {peer_id} a ping of length {len} asking for {pongbytes}"
        """
        payload = {
            "id": peer_id,
            "len": length,
            "pongbytes": pongbytes
        }
        return self.call("ping", payload)

    def dev_memdump(self):
        """
        Show memory objects currently in use
        """
        return self.call("dev-memdump")

    def dev_memleak(self):
        """
        Show unreferenced memory objects
        """
        return self.call("dev-memleak")

    def withdraw(self, destination, satoshi, feerate=None, minconf=None):
        """
        Send to {destination} address {satoshi} (or "all")
        amount via Bitcoin transaction. Only select outputs
        with {minconf} confirmations
        """
        payload = {
            "destination": destination,
            "satoshi": satoshi,
            "feerate": feerate,
            "minconf": minconf,
        }
        return self.call("withdraw", payload)

    def newaddr(self, addresstype=None):
        """Get a new address of type {addresstype} of the internal wallet.
        """
        return self.call("newaddr", {"addresstype": addresstype})

    def listfunds(self):
        """
        Show funds available for opening channels
        """
        return self.call("listfunds")

    def listforwards(self):
        """List all forwarded payments and their information
        """
        return self.call("listforwards")

    def dev_rescan_outputs(self):
        """
        Synchronize the state of our funds with bitcoind
        """
        return self.call("dev-rescan-outputs")

    def dev_forget_channel(self, peerid, force=False):
        """ Forget the channel with id=peerid
        """
        return self.call(
            "dev-forget-channel",
            payload={"id": peerid, "force": force}
        )

    def disconnect(self, peer_id, force=False):
        """
        Disconnect from peer with {peer_id}, optional {force} even if has active channel
        """
        payload = {
            "id": peer_id,
            "force": force,
        }
        return self.call("disconnect", payload)

    def feerates(self, style, urgent=None, normal=None, slow=None):
        """
        Supply feerate estimates manually.
        """
        payload = {
            "style": style,
            "urgent": urgent,
            "normal": normal,
            "slow": slow
        }
        return self.call("feerates", payload)
