import json
import logging
import os
import socket
from contextlib import contextmanager
from decimal import Decimal
from json import JSONEncoder
from math import floor, log10
from typing import Optional, Union


def _patched_default(self, obj):
    return getattr(obj.__class__, "to_json", _patched_default.default)(obj)


def monkey_patch_json(patch=True):
    is_patched = JSONEncoder.default == _patched_default

    if patch and not is_patched:
        _patched_default.default = JSONEncoder.default  # Save unmodified
        JSONEncoder.default = _patched_default  # Replace it.
    elif not patch and is_patched:
        JSONEncoder.default = _patched_default.default


class RpcError(ValueError):
    def __init__(self, method: str, payload: dict, error: str):
        super(ValueError, self).__init__(
            "RPC call failed: method: {}, payload: {}, error: {}".format(
                method, payload, error
            )
        )

        self.method = method
        self.payload = payload
        self.error = error


class Millisatoshi:
    """
    A subtype to represent thousandths of a satoshi.

    Many JSON API fields are expressed in millisatoshis: these automatically
    get turned into Millisatoshi types. Converts to and from int.
    """
    def __init__(self, v: Union[int, str, Decimal]):
        """
        Takes either a string ending in 'msat', 'sat', 'btc' or an integer.
        """
        if isinstance(v, str):
            if v.endswith("msat"):
                parsed = Decimal(v[0:-4])
            elif v.endswith("sat"):
                parsed = Decimal(v[0:-3]) * 1000
            elif v.endswith("btc"):
                parsed = Decimal(v[0:-3]) * 1000 * 10**8
            else:
                raise TypeError(
                    "Millisatoshi must be string with msat/sat/btc suffix or"
                    " int"
                )
            if parsed != int(parsed):
                raise ValueError("Millisatoshi must be a whole number")
            self.millisatoshis = int(parsed)

        elif isinstance(v, Millisatoshi):
            self.millisatoshis = v.millisatoshis

        elif int(v) == v:
            self.millisatoshis = int(v)

        elif isinstance(v, float):
            raise TypeError("Millisatoshi by float is currently not supported")

        else:
            raise TypeError(
                "Millisatoshi must be string with msat/sat/btc suffix or int"
            )

        if self.millisatoshis < 0:
            raise ValueError("Millisatoshi must be >= 0")

    def __repr__(self) -> str:
        """
        Appends the 'msat' as expected for this type.
        """
        return str(self.millisatoshis) + "msat"

    def to_satoshi(self) -> Decimal:
        """
        Return a Decimal representing the number of satoshis.
        """
        return Decimal(self.millisatoshis) / 1000

    def to_whole_satoshi(self) -> int:
        """
        Return an int respresenting the number of satoshis;
        rounded up to the nearest satoshi
        """
        return (self.millisatoshis + 999) // 1000

    def to_btc(self) -> Decimal:
        """
        Return a Decimal representing the number of bitcoin.
        """
        return Decimal(self.millisatoshis) / 1000 / 10**8

    def to_satoshi_str(self) -> str:
        """
        Return a string of form 1234sat or 1234.567sat.
        """
        if self.millisatoshis % 1000:
            return '{:.3f}sat'.format(self.to_satoshi())
        else:
            return '{:.0f}sat'.format(self.to_satoshi())

    def to_btc_str(self) -> str:
        """
        Return a string of form 12.34567890btc or 12.34567890123btc.
        """
        if self.millisatoshis % 1000:
            return '{:.11f}btc'.format(self.to_btc())
        else:
            return '{:.8f}btc'.format(self.to_btc())

    def to_approx_str(self, digits: int = 3) -> str:
        """Returns the shortmost string using common units representation.

        Rounds to significant `digits`. Default: 3
        """
        def round_to_n(x: int, n: int) -> float:
            return round(x, -int(floor(log10(x))) + (n - 1))
        result = self.to_satoshi_str()

        # we try to increase digits to check if we did loose out on precision
        # without gaining a shorter string, since this is a rarely used UI
        # function, performance is not an issue. Adds at least one iteration.
        while True:
            # first round everything down to effective digits
            amount_rounded = round_to_n(self.millisatoshis, digits)
            # try different units and take shortest resulting normalized string
            amounts_str = [
                "%gbtc" % (amount_rounded / 1000 / 10**8),
                "%gsat" % (amount_rounded / 1000),
                "%gmsat" % (amount_rounded),
            ]
            test_result = min(amounts_str, key=len)

            # check result and do another run if necessary
            if test_result == result:
                return result
            elif not result or len(test_result) <= len(result):
                digits = digits + 1
                result = test_result
            else:
                return result

    def to_json(self) -> str:
        return self.__repr__()

    def __int__(self) -> int:
        return self.millisatoshis

    def __lt__(self, other: 'Millisatoshi') -> bool:
        return self.millisatoshis < other.millisatoshis

    def __le__(self, other: 'Millisatoshi') -> bool:
        return self.millisatoshis <= other.millisatoshis

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Millisatoshi):
            return self.millisatoshis == other.millisatoshis
        elif isinstance(other, int):
            return self.millisatoshis == other
        else:
            return False

    def __gt__(self, other: 'Millisatoshi') -> bool:
        return self.millisatoshis > other.millisatoshis

    def __ge__(self, other: 'Millisatoshi') -> bool:
        return self.millisatoshis >= other.millisatoshis

    def __add__(self, other: 'Millisatoshi') -> 'Millisatoshi':
        return Millisatoshi(int(self) + int(other))

    def __sub__(self, other: 'Millisatoshi') -> 'Millisatoshi':
        return Millisatoshi(int(self) - int(other))

    def __mul__(self, other: Union[int, float]) -> 'Millisatoshi':
        if isinstance(other, Millisatoshi):
            raise TypeError("Resulting unit msat^2 is not supported")
        return Millisatoshi(floor(self.millisatoshis * other))

    def __truediv__(self, other: Union[int, float, 'Millisatoshi']) -> Union['Millisatoshi', float]:
        if isinstance(other, Millisatoshi):
            return self.millisatoshis / other.millisatoshis
        return Millisatoshi(floor(self.millisatoshis / other))

    def __floordiv__(self, other: Union[int, float, 'Millisatoshi']) -> Union['Millisatoshi', int]:
        if isinstance(other, Millisatoshi):
            return self.millisatoshis // other.millisatoshis
        return Millisatoshi(floor(self.millisatoshis // float(other)))

    def __mod__(self, other: Union[float, int]) -> 'Millisatoshi':
        return Millisatoshi(int(self.millisatoshis % other))

    def __radd__(self, other: 'Millisatoshi') -> 'Millisatoshi':
        return Millisatoshi(int(self) + int(other))


class UnixSocket(object):
    """A wrapper for socket.socket that is specialized to unix sockets.

    Some OS implementations impose restrictions on the Unix sockets.

     - On linux OSs the socket path must be shorter than the in-kernel buffer
       size (somewhere around 100 bytes), thus long paths may end up failing
       the `socket.connect` call.

    This is a small wrapper that tries to work around these limitations.

    """

    def __init__(self, path: str):
        self.path = path
        self.sock: Optional[socket.SocketType] = None
        self.connect()

    def connect(self) -> None:
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.connect(str(self.path))
        except OSError as e:
            self.close()

            if (e.args[0] == "AF_UNIX path too long" and os.uname()[0] == "Linux"):
                # If this is a Linux system we may be able to work around this
                # issue by opening our directory and using `/proc/self/fd/` to
                # get a short alias for the socket file.
                #
                # This was heavily inspired by the Open vSwitch code see here:
                # https://github.com/openvswitch/ovs/blob/master/python/ovs/socket_util.py

                dirname = os.path.dirname(self.path)
                basename = os.path.basename(self.path)

                # Open an fd to our home directory, that we can then find
                # through `/proc/self/fd` and access the contents.
                dirfd = os.open(dirname, os.O_DIRECTORY | os.O_RDONLY)
                short_path = "/proc/self/fd/%d/%s" % (dirfd, basename)
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(short_path)
            else:
                # There is no good way to recover from this.
                raise

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def sendall(self, b: bytes) -> None:
        if self.sock is None:
            raise socket.error("not connected")

        self.sock.sendall(b)

    def recv(self, length: int) -> bytes:
        if self.sock is None:
            raise socket.error("not connected")

        return self.sock.recv(length)

    def __del__(self) -> None:
        self.close()


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None, logger=logging, encoder_cls=json.JSONEncoder, decoder=json.JSONDecoder()):
        self.socket_path = socket_path
        self.encoder_cls = encoder_cls
        self.decoder = decoder
        self.executor = executor
        self.logger = logger
        self._notify = None

        self.next_id = 1

    def _writeobj(self, sock, obj):
        s = json.dumps(obj, ensure_ascii=False, cls=self.encoder_cls)
        sock.sendall(bytearray(s, 'UTF-8'))

    def _readobj(self, sock, buff=b''):
        """Read a JSON object, starting with buff; returns object and any buffer left over."""
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
        """Intercept any call that is not explicitly defined and call @call.

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
        sock = UnixSocket(self.socket_path)
        this_id = self.next_id
        self.next_id += 0
        buf = b''

        if self._notify is not None:
            # Opt into the notifications support
            self._writeobj(sock, {
                "jsonrpc": "2.0",
                "method": "notifications",
                "id": 0,
                "params": {
                    "enable": True
                },
            })
            # FIXME: Notification schema support?
            _, buf = self._readobj(sock, buf)

        request = {
            "jsonrpc": "2.0",
            "method": method,
            "params": payload,
            "id": this_id,
        }

        self._writeobj(sock, request)
        while True:
            resp, buf = self._readobj(sock, buf)
            id = resp.get("id", None)
            meth = resp.get("method", None)

            if meth == 'message' and self._notify is not None:
                n = resp['params']
                self._notify(
                    message=n.get('message', None),
                    progress=n.get('progress', None),
                    request=request
                )
                continue

            if meth is None or id is None:
                break

        self.logger.debug("Received response for %s call: %r", method, resp)
        if 'id' in resp and resp['id'] != this_id:
            raise ValueError("Malformed response, id is not {}: {}.".format(this_id, resp))
        sock.close()

        if not isinstance(resp, dict):
            raise ValueError("Malformed response, response is not a dictionary %s." % resp)
        elif "error" in resp:
            raise RpcError(method, payload, resp['error'])
        elif "result" not in resp:
            raise ValueError("Malformed response, \"result\" missing.")
        return resp["result"]

    @contextmanager
    def notify(self, fn):
        """Register a notification callback to use for a set of RPC calls.

        This is a context manager and should be used like this:

        ```python
        def fn(message, progress, request, **kwargs):
            print(message)

        with rpc.notify(fn):
            rpc.somemethod()
        ```

        The `fn` function will be called once for each notification
        the is sent by `somemethod`. This is a context manager,
        meaning that multiple commands can share the same context, and
        the same notification function.

        """
        old = self._notify
        self._notify = fn
        yield
        self._notify = old


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
        def __init__(self, *, object_hook=None, parse_float=None,
                     parse_int=None, parse_constant=None,
                     strict=True, object_pairs_hook=None,
                     patch_json=True):
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

    def __init__(self, socket_path, executor=None, logger=logging,
                 patch_json=True):
        super().__init__(
            socket_path,
            executor,
            logger,
            self.LightningJSONEncoder,
            self.LightningJSONDecoder()
        )

        if patch_json:
            monkey_patch_json(patch=True)

    def addgossip(self, message):
        """
        Inject this (hex-encoded) gossip message.
        """
        payload = {
            "message": message,
        }
        return self.call("addgossip", payload)

    def autocleaninvoice(self, cycle_seconds=None, expired_by=None):
        """
        Sets up automatic cleaning of expired invoices. {cycle_seconds} sets
        the cleaning frequency in seconds (defaults to 3600) and {expired_by}
        sets the minimum time an invoice should have been expired for to be
        cleaned in seconds (defaults to 86400).
        """
        payload = {
            "cycle_seconds": cycle_seconds,
            "expired_by": expired_by
        }
        return self.call("autocleaninvoice", payload)

    def check(self, command_to_check, **kwargs):
        """
        Checks if a command is valid without running it.
        """
        payload = {"command_to_check": command_to_check}
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("check", payload)

    def close(self, peer_id, unilateraltimeout=None, destination=None,
              fee_negotiation_step=None, force_lease_closed=None, feerange=None):
        """
        Close the channel with peer {id}, forcing a unilateral
        close after {unilateraltimeout} seconds if non-zero, and
        the to-local output will be sent to {destination}.

        If channel funds have been leased to the peer and the
        lease has not yet expired, you can force a close with
        {force_lease_closed}. Note that your funds will still be
        locked until the lease expires.
        """
        payload = {
            "id": peer_id,
            "unilateraltimeout": unilateraltimeout,
            "destination": destination,
            "fee_negotiation_step": fee_negotiation_step,
            "force_lease_closed": force_lease_closed,
            "feerange": feerange,
        }
        return self.call("close", payload)

    def connect(self, peer_id, host=None, port=None):
        """
        Connect to {peer_id} at {host} and {port}.
        """
        payload = {
            "id": peer_id,
            "host": host,
            "port": port
        }
        return self.call("connect", payload)

    def decodepay(self, bolt11, description=None):
        """
        Decode {bolt11}, using {description} if necessary.
        """
        payload = {
            "bolt11": bolt11,
            "description": description
        }
        return self.call("decodepay", payload)

    def delexpiredinvoice(self, maxexpirytime=None):
        """
        Delete all invoices that have expired on or before the given {maxexpirytime}.
        """
        payload = {
            "maxexpirytime": maxexpirytime
        }
        return self.call("delexpiredinvoice", payload)

    def delinvoice(self, label, status):
        """
        Delete unpaid invoice {label} with {status}.
        """
        payload = {
            "label": label,
            "status": status
        }
        return self.call("delinvoice", payload)

    def dev_crash(self):
        """
        Crash lightningd by calling fatal().
        """
        payload = {
            "subcommand": "crash"
        }
        return self.call("dev", payload)

    def dev_fail(self, peer_id):
        """
        Fail with peer {peer_id}.
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-fail", payload)

    def dev_forget_channel(self, peerid, force=False):
        """ Forget the channel with id=peerid.
        """
        return self.call(
            "dev-forget-channel",
            payload={"id": peerid, "force": force}
        )

    def dev_memdump(self):
        """
        Show memory objects currently in use.
        """
        return self.call("dev-memdump")

    def dev_memleak(self):
        """
        Show unreferenced memory objects.
        """
        return self.call("dev-memleak")

    def dev_pay(self, bolt11, msatoshi=None, label=None, riskfactor=None,
                maxfeepercent=None, retry_for=None,
                maxdelay=None, exemptfee=None, use_shadow=True, exclude=[]):
        """
        A developer version of `pay`, with the possibility to deactivate
        shadow routing (used for testing).
        """
        payload = {
            "bolt11": bolt11,
            "msatoshi": msatoshi,
            "label": label,
            "riskfactor": riskfactor,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "use_shadow": use_shadow,
            "exclude": exclude,
        }
        return self.call("pay", payload)

    def dev_reenable_commit(self, peer_id):
        """
        Re-enable the commit timer on peer {id}.
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-reenable-commit", payload)

    def dev_rescan_outputs(self):
        """
        Synchronize the state of our funds with bitcoind.
        """
        return self.call("dev-rescan-outputs")

    def dev_rhash(self, secret):
        """
        Show SHA256 of {secret}
        """
        payload = {
            "subcommand": "rhash",
            "secret": secret
        }
        return self.call("dev", payload)

    def dev_sign_last_tx(self, peer_id):
        """
        Sign and show the last commitment transaction with peer {id}.
        """
        payload = {
            "id": peer_id
        }
        return self.call("dev-sign-last-tx", payload)

    def dev_slowcmd(self, msec=None):
        """
        Torture test for slow commands, optional {msec}.
        """
        payload = {
            "subcommand": "slowcmd",
            "msec": msec
        }
        return self.call("dev", payload)

    def disconnect(self, peer_id, force=False):
        """
        Disconnect from peer with {peer_id}, optional {force} even if has active channel.
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

    def fundchannel(self, node_id, amount, feerate=None, announce=True, minconf=None, utxos=None, push_msat=None, close_to=None, request_amt=None, compact_lease=None):
        """
        Fund channel with {id} using {amount} satoshis with feerate
        of {feerate} (uses default feerate if unset).
        If {announce} is False, don't send channel announcements.
        Only select outputs with {minconf} confirmations.
        If {utxos} is specified (as a list of 'txid:vout' strings),
        fund a channel from these specifics utxos.
        {close_to} is a valid Bitcoin address.

        {request_amt} is the lease amount to request from the peer. Only
        valid if peer is advertising a liquidity ad + supports v2 channel opens
        (dual-funding)
        """
        payload = {
            "id": node_id,
            "amount": amount,
            "feerate": feerate,
            "announce": announce,
            "minconf": minconf,
            "utxos": utxos,
            "push_msat": push_msat,
            "close_to": close_to,
            "request_amt": request_amt,
            "compact_lease": compact_lease,
        }
        return self.call("fundchannel", payload)

    def fundchannel_start(self, node_id, amount, feerate=None, announce=True, close_to=None):
        """
        Start channel funding with {id} for {amount} satoshis
        with feerate of {feerate} (uses default feerate if unset).
        If {announce} is False, don't send channel announcements.
        Returns a Bech32 {funding_address} for an external wallet
        to create a funding transaction for. Requires a call to
        'fundchannel_complete' to complete channel establishment
        with peer.
        """
        payload = {
            "id": node_id,
            "amount": amount,
            "feerate": feerate,
            "announce": announce,
            "close_to": close_to,
        }
        return self.call("fundchannel_start", payload)

    def fundchannel_cancel(self, node_id):
        """
        Cancel a 'started' fundchannel with node {id}.
        """
        payload = {
            "id": node_id,
        }
        return self.call("fundchannel_cancel", payload)

    def fundchannel_complete(self, node_id, psbt):
        """
        Complete channel establishment with {id}, using {psbt}.
        """
        payload = {
            "id": node_id,
            "psbt": psbt,
        }
        return self.call("fundchannel_complete", payload)

    def getinfo(self):
        """
        Show information about this node.
        """
        return self.call("getinfo")

    def getlog(self, level=None):
        """
        Show logs, with optional log {level} (info|unusual|debug|io).
        """
        payload = {
            "level": level
        }
        return self.call("getlog", payload)

    def getpeer(self, peer_id, level=None):
        """
        Show peer with {peer_id}, if {level} is set, include {log}s.
        """
        payload = {
            "id": peer_id,
            "level": level
        }
        res = self.call("listpeers", payload)
        return res.get("peers") and res["peers"][0] or None

    def getroute(self, node_id, msatoshi, riskfactor, cltv=9, fromid=None, fuzzpercent=None, exclude=[], maxhops=20):
        """
        Show route to {id} for {msatoshi}, using {riskfactor} and optional
        {cltv} (default 9). If specified search from {fromid} otherwise use
        this node as source. Randomize the route with up to {fuzzpercent}
        (0.0 -> 100.0, default 5.0). {exclude} is an optional array of
        scid/direction or node-id to exclude. Limit the number of hops in the
        route to {maxhops}.
        """
        payload = {
            "id": node_id,
            "msatoshi": msatoshi,
            "riskfactor": riskfactor,
            "cltv": cltv,
            "fromid": fromid,
            "fuzzpercent": fuzzpercent,
            "exclude": exclude,
            "maxhops": maxhops
        }
        return self.call("getroute", payload)

    def help(self, command=None):
        """
        Show available commands, or just {command} if supplied.
        """
        payload = {
            "command": command,
        }
        return self.call("help", payload)

    def invoice(self, msatoshi, label, description, expiry=None, fallbacks=None, preimage=None, exposeprivatechannels=None, cltv=None):
        """
        Create an invoice for {msatoshi} with {label} and {description} with
        optional {expiry} seconds (default 1 week).
        """
        payload = {
            "msatoshi": msatoshi,
            "label": label,
            "description": description,
            "expiry": expiry,
            "fallbacks": fallbacks,
            "preimage": preimage,
            "exposeprivatechannels": exposeprivatechannels,
            "cltv": cltv,
        }
        return self.call("invoice", payload)

    def listchannels(self, short_channel_id=None, source=None, destination=None):
        """
        Show all known channels or filter by optional
        {short_channel_id}, {source} or {destination}.
        """
        payload = {
            "short_channel_id": short_channel_id,
            "source": source,
            "destination": destination
        }
        return self.call("listchannels", payload)

    def listconfigs(self, config=None):
        """List this node's config.
        """
        payload = {
            "config": config
        }
        return self.call("listconfigs", payload)

    def listforwards(self, status=None, in_channel=None, out_channel=None):
        """List all forwarded payments and their information matching
        forward {status}, {in_channel} and {out_channel}.
        """
        payload = {
            "status": status,
            "in_channel": in_channel,
            "out_channel": out_channel,
        }
        return self.call("listforwards", payload)

    def listfunds(self, spent=None):
        """
        Show funds available for opening channels
        or both unspent and spent funds if {spent} is True.
        """

        payload = {
            "spent": spent
        }
        return self.call("listfunds", payload)

    def listtransactions(self):
        """
        Show wallet history.
        """
        return self.call("listtransactions")

    def listinvoices(self, label=None, payment_hash=None, invstring=None, offer_id=None):
        """Query invoices

        Show invoice matching {label}, {payment_hash}, {invstring} or {offer_id}
        (or all, if no filters are present).

        """
        payload = {
            "label": label,
            "payment_hash": payment_hash,
            "invstring": invstring,
            "offer_id": offer_id,
        }
        return self.call("listinvoices", payload)

    def listnodes(self, node_id=None):
        """
        Show all nodes in our local network view, filter on node {id}
        if provided.
        """
        payload = {
            "id": node_id
        }
        return self.call("listnodes", payload)

    def listpays(self, bolt11=None, payment_hash=None, status=None):
        """
        Show outgoing payments, regarding {bolt11} or {payment_hash} if set
        Can only specify one of {bolt11} or {payment_hash}. It is possible
        filter the payments by {status}.
        """
        assert not (bolt11 and payment_hash)
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "status": status
        }
        return self.call("listpays", payload)

    def listpeers(self, peerid=None, level=None):
        """
        Show current peers, if {level} is set, include {log}s".
        """
        payload = {
            "id": peerid,
            "level": level,
        }
        return self.call("listpeers", payload)

    def listsendpays(self, bolt11=None, payment_hash=None, status=None):
        """Show all sendpays results, or only for `bolt11` or `payment_hash`."""
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "status": status
        }
        return self.call("listsendpays", payload)

    def multifundchannel(self, destinations, feerate=None, minconf=None, utxos=None, minchannels=None, **kwargs):
        """
        Fund channels to an array of {destinations},
        each entry of which is a dict of node {id}
        and {amount} to fund, and optionally whether
        to {announce} and how much {push_msat} to
        give outright to the node.
        You may optionally specify {feerate},
        {minconf} depth, and the {utxos} set to use
        for the single transaction that funds all
        the channels.
        """
        payload = {
            "destinations": destinations,
            "feerate": feerate,
            "minconf": minconf,
            "utxos": utxos,
            "minchannels": minchannels,
        }
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("multifundchannel", payload)

    def multiwithdraw(self, outputs, feerate=None, minconf=None, utxos=None, **kwargs):
        """
        Send to {outputs}
        via Bitcoin transaction. Only select outputs
        with {minconf} confirmations.
        """
        payload = {
            "outputs": outputs,
            "feerate": feerate,
            "minconf": minconf,
            "utxos": utxos,
        }
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("multiwithdraw", payload)

    def newaddr(self, addresstype=None):
        """Get a new address of type {addresstype} of the internal wallet.
        """
        return self.call("newaddr", {"addresstype": addresstype})

    def pay(self, bolt11, msatoshi=None, label=None, riskfactor=None,
            maxfeepercent=None, retry_for=None,
            maxdelay=None, exemptfee=None, exclude=[]):
        """
        Send payment specified by {bolt11} with {msatoshi}
        (ignored if {bolt11} has an amount), optional {label}
        and {riskfactor} (default 1.0).
        """
        payload = {
            "bolt11": bolt11,
            "msatoshi": msatoshi,
            "label": label,
            "riskfactor": riskfactor,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "exclude": exclude,
        }
        return self.call("pay", payload)

    def openchannel_init(self, node_id, channel_amount, psbt, feerate=None, funding_feerate=None, announce=True, close_to=None, request_amt=None, *args, **kwargs):
        """Initiate an openchannel with a peer """
        payload = {
            "id": node_id,
            "amount": channel_amount,
            "initialpsbt": psbt,
            "commitment_feerate": feerate,
            "funding_feerate": funding_feerate,
            "announce": announce,
            "close_to": close_to,
            "request_amt": request_amt,
        }
        return self.call("openchannel_init", payload)

    def openchannel_signed(self, channel_id, signed_psbt, *args, **kwargs):
        """ Send the funding transaction signatures to the peer, finish
            the channel open """
        payload = {
            "channel_id": channel_id,
            "signed_psbt": signed_psbt,
        }
        return self.call("openchannel_signed", payload)

    def openchannel_update(self, channel_id, psbt, *args, **kwargs):
        """Update an openchannel with a peer """
        payload = {
            "channel_id": channel_id,
            "psbt": psbt,
        }
        return self.call("openchannel_update", payload)

    def openchannel_bump(self, channel_id, amount, initialpsbt, funding_feerate=None):
        """ Initiate an RBF for an in-progress open """
        payload = {
            "channel_id": channel_id,
            "amount": amount,
            "initialpsbt": initialpsbt,
            "funding_feerate": funding_feerate,
        }
        return self.call("openchannel_bump", payload)

    def openchannel_abort(self, channel_id):
        """ Abort a channel open """
        payload = {
            "channel_id": channel_id,
        }
        return self.call("openchannel_abort", payload)

    def paystatus(self, bolt11=None):
        """Detail status of attempts to pay {bolt11} or any."""
        payload = {
            "bolt11": bolt11
        }
        return self.call("paystatus", payload)

    def ping(self, peer_id, length=128, pongbytes=128):
        """
        Send {peer_id} a ping of length {len} asking for {pongbytes}.
        """
        payload = {
            "id": peer_id,
            "len": length,
            "pongbytes": pongbytes
        }
        return self.call("ping", payload)

    def plugin_start(self, plugin, **kwargs):
        """
        Adds a plugin to lightningd.
        """
        payload = {
            "subcommand": "start",
            "plugin": plugin,
        }
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("plugin", payload)

    def plugin_startdir(self, directory):
        """
        Adds all plugins from a directory to lightningd.
        """
        payload = {
            "subcommand": "startdir",
            "directory": directory
        }
        return self.call("plugin", payload)

    def plugin_stop(self, plugin):
        """
        Stops a lightningd plugin, will fail if plugin is not dynamic.
        """
        payload = {
            "subcommand": "stop",
            "plugin": plugin
        }
        return self.call("plugin", payload)

    def plugin_list(self):
        """
        Lists all plugins lightningd knows about.
        """
        payload = {
            "subcommand": "list"
        }
        return self.call("plugin", payload)

    def plugin_rescan(self):
        payload = {
            "subcommand": "rescan"
        }
        return self.call("plugin", payload)

    def sendpay(self, route, payment_hash, label=None, msatoshi=None, bolt11=None, payment_secret=None, partid=None, groupid=None):
        """
        Send along {route} in return for preimage of {payment_hash}.
        """
        payload = {
            "route": route,
            "payment_hash": payment_hash,
            "label": label,
            "msatoshi": msatoshi,
            "bolt11": bolt11,
            "payment_secret": payment_secret,
            "partid": partid,
            "groupid": groupid,
        }
        return self.call("sendpay", payload)

    def sendonion(
            self, onion, first_hop, payment_hash, label=None,
            shared_secrets=None, partid=None, bolt11=None, msatoshi=None,
            destination=None
    ):
        """Send an outgoing payment using the specified onion.

        This method allows sending a payment using an externally
        generated routing onion, with optional metadata to facilitate
        internal handling, but not required.

        """
        payload = {
            "onion": onion,
            "first_hop": first_hop,
            "payment_hash": payment_hash,
            "label": label,
            "shared_secrets": shared_secrets,
            "partid": partid,
            "bolt11": bolt11,
            "msatoshi": msatoshi,
            "destination": destination,
        }
        return self.call("sendonion", payload)

    def setchannelfee(self, id, base=None, ppm=None, enforcedelay=None):
        """
        Set routing fees for a channel/peer {id} (or 'all'). {base} is a value in millisatoshi
        that is added as base fee to any routed payment. {ppm} is a value added proportionally
        per-millionths to any routed payment volume in satoshi. {enforcedelay} is the number of seconds before enforcing this change.
        """
        payload = {
            "id": id,
            "base": base,
            "ppm": ppm,
            "enforcedelay": enforcedelay,
        }
        return self.call("setchannelfee", payload)

    def stop(self):
        """
        Shut down the lightningd process.
        """
        return self.call("stop")

    def waitanyinvoice(self, lastpay_index=None, timeout=None, **kwargs):
        """
        Wait for the next invoice to be paid, after {lastpay_index}
        (if supplied).
        Fail after {timeout} seconds has passed without an invoice
        being paid.
        """
        payload = {
            "lastpay_index": lastpay_index,
            "timeout": timeout
        }
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("waitanyinvoice", payload)

    def waitblockheight(self, blockheight, timeout=None):
        """
        Wait for the blockchain to reach the specified block height.
        """
        payload = {
            "blockheight": blockheight,
            "timeout": timeout
        }
        return self.call("waitblockheight", payload)

    def waitinvoice(self, label):
        """
        Wait for an incoming payment matching the invoice with {label}.
        """
        payload = {
            "label": label
        }
        return self.call("waitinvoice", payload)

    def waitsendpay(self, payment_hash, timeout=None, partid=None, groupid=None):
        """
        Wait for payment for preimage of {payment_hash} to complete.
        """
        payload = {
            "payment_hash": payment_hash,
            "timeout": timeout,
            "partid": partid,
            "groupid": groupid,
        }
        return self.call("waitsendpay", payload)

    def withdraw(self, destination, satoshi, feerate=None, minconf=None, utxos=None):
        """
        Send to {destination} address {satoshi} (or "all")
        amount via Bitcoin transaction. Only select outputs
        with {minconf} confirmations.
        """
        payload = {
            "destination": destination,
            "satoshi": satoshi,
            "feerate": feerate,
            "minconf": minconf,
            "utxos": utxos,
        }

        return self.call("withdraw", payload)

    def txprepare(self, outputs, feerate=None, minconf=None, utxos=None):
        """
        Prepare a Bitcoin transaction which sends to [outputs].
        The format of output is like [{address1: amount1},
        {address2: amount2}], or [{address: "all"}]).
        Only select outputs with {minconf} confirmations.

        Outputs will be reserved until you call txdiscard or txsend, or
        lightningd restarts.
        """
        payload = {
            "outputs": outputs,
            "feerate": feerate,
            "minconf": minconf,
            "utxos": utxos,
        }
        return self.call("txprepare", payload)

    def txdiscard(self, txid):
        """
        Cancel a Bitcoin transaction returned from txprepare. The outputs
        it was spending are released for other use.
        """
        payload = {
            "txid": txid
        }
        return self.call("txdiscard", payload)

    def txsend(self, txid):
        """
        Sign and broadcast a Bitcoin transaction returned from txprepare.
        """
        payload = {
            "txid": txid
        }
        return self.call("txsend", payload)

    def reserveinputs(self, psbt, exclusive=True, reserve=None):
        """
        Reserve any inputs in this psbt.
        """
        payload = {
            "psbt": psbt,
            "exclusive": exclusive,
            "reserve": reserve,
        }
        return self.call("reserveinputs", payload)

    def unreserveinputs(self, psbt, reserve=None):
        """
        Unreserve (or reduce reservation) on any UTXOs in this psbt were previously reserved.
        """
        payload = {
            "psbt": psbt,
            "reserve": reserve,
        }
        return self.call("unreserveinputs", payload)

    def fundpsbt(self, satoshi, feerate, startweight, minconf=None, reserve=True, locktime=None, min_witness_weight=None, excess_as_change=False):
        """
        Create a PSBT with inputs sufficient to give an output of satoshi.
        """
        payload = {
            "satoshi": satoshi,
            "feerate": feerate,
            "startweight": startweight,
            "minconf": minconf,
            "reserve": reserve,
            "locktime": locktime,
            "min_witness_weight": min_witness_weight,
            "excess_as_change": excess_as_change,
        }
        return self.call("fundpsbt", payload)

    def utxopsbt(self, satoshi, feerate, startweight, utxos, reserve=True, reservedok=False, locktime=None, min_witness_weight=None, excess_as_change=False):
        """
        Create a PSBT with given inputs, to give an output of satoshi.
        """
        payload = {
            "satoshi": satoshi,
            "feerate": feerate,
            "startweight": startweight,
            "utxos": utxos,
            "reserve": reserve,
            "reservedok": reservedok,
            "locktime": locktime,
            "min_witness_weight": min_witness_weight,
            "excess_as_change": excess_as_change,
        }
        return self.call("utxopsbt", payload)

    def signpsbt(self, psbt, signonly=None):
        """
        Add internal wallet's signatures to PSBT
        """
        payload = {
            "psbt": psbt,
            "signonly": signonly,
        }
        return self.call("signpsbt", payload)

    def sendpsbt(self, psbt, reserve=None):
        """
        Finalize extract and broadcast a PSBT
        """
        payload = {
            "psbt": psbt,
            "reserve": reserve,
        }
        return self.call("sendpsbt", payload)

    def signmessage(self, message):
        """
        Sign a message with this node's secret key.
        """
        payload = {
            "message": message
        }
        return self.call("signmessage", payload)

    def checkmessage(self, message, zbase, pubkey=None):
        """
        Check if a message was signed (with a specific key).
        Use returned field ['verified'] to get result.
        """
        payload = {
            "message": message,
            "zbase": zbase,
            "pubkey": pubkey,
        }
        return self.call("checkmessage", payload)

    def getsharedsecret(self, point, **kwargs):
        """
        Compute the hash of the Elliptic Curve Diffie Hellman shared
        secret point from this node private key and an
        input {point}.
        """
        payload = {
            "point": point
        }
        payload.update({k: v for k, v in kwargs.items()})
        return self.call("getsharedsecret", payload)

    def keysend(self, destination, msatoshi, label=None, maxfeepercent=None,
                retry_for=None, maxdelay=None, exemptfee=None,
                extratlvs=None):
        """
        """

        if extratlvs is not None and not isinstance(extratlvs, dict):
            raise ValueError(
                "extratlvs is not a dictionary with integer keys and hexadecimal values"
            )

        payload = {
            "destination": destination,
            "msatoshi": msatoshi,
            "label": label,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "extratlvs": extratlvs,
        }
        return self.call("keysend", payload)
