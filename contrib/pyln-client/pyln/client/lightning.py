import json
import logging
import os
import socket
import sys
from contextlib import contextmanager
from decimal import Decimal
from json import JSONEncoder
from math import floor, log10
from typing import Optional, Union


def to_json_default(self, obj):
    """
    Try to use .to_json() if available, otherwise use the normal JSON default method.
    """
    return getattr(obj.__class__, "to_json", old_json_default)(obj)


old_json_default = JSONEncoder.default
JSONEncoder.default = to_json_default


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

    If you put this in an object, converting to JSON automatically makes it an "...msat" string, so you can safely hand it even to our APIs which treat raw numbers as satoshis.  Converts to and from int.
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
        if isinstance(other, int):
            return self.millisatoshis < other
        return self.millisatoshis < other.millisatoshis

    def __le__(self, other: 'Millisatoshi') -> bool:
        if isinstance(other, int):
            return self.millisatoshis <= other
        return self.millisatoshis <= other.millisatoshis

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Millisatoshi):
            return self.millisatoshis == other.millisatoshis
        elif isinstance(other, int):
            return self.millisatoshis == other
        else:
            return False

    def __gt__(self, other: 'Millisatoshi') -> bool:
        if isinstance(other, int):
            return self.millisatoshis > other
        return self.millisatoshis > other.millisatoshis

    def __ge__(self, other: 'Millisatoshi') -> bool:
        if isinstance(other, int):
            return self.millisatoshis >= other
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
    def __init__(self, socket_path, executor=None, logger=logging, caller_name=None):
        self.socket_path = socket_path
        self.executor = executor
        self.logger = logger
        self._notify = None
        self._filter = None
        if caller_name is None:
            self.caller_name = os.path.splitext(os.path.basename(sys.argv[0]))[0]
        else:
            self.caller_name = caller_name
        self.cmdprefix = None

        self.next_id = 1

    def _writeobj(self, sock, obj):
        s = json.dumps(obj, ensure_ascii=False)
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
                obj, _ = json.JSONDecoder().raw_decode(parts[0].decode("UTF-8"))
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

    def get_json_id(self, method, cmdprefix):
        """Get a nicely formatted, CLN-compliant JSON ID"""
        this_id = "{}:{}#{}".format(self.caller_name, method, str(self.next_id))
        if cmdprefix is None:
            cmdprefix = self.cmdprefix
        if cmdprefix:
            this_id = f'{cmdprefix}/{this_id}'
        return this_id

    def call(self, method, payload=None, cmdprefix=None, filter=None):
        """Generic call API: you can set cmdprefix here, or set self.cmdprefix
        before the call is made.

        """
        self.logger.debug("Calling %s with payload %r", method, payload)

        if payload is None:
            payload = {}
        # Filter out arguments that are None
        if isinstance(payload, dict):
            payload = {k: v for k, v in payload.items() if v is not None}

        this_id = self.get_json_id(method, cmdprefix)
        self.next_id += 1

        # FIXME: we open a new socket for every readobj call...
        sock = UnixSocket(self.socket_path)

        buf = b''

        if self._notify is not None:
            # Opt into the notifications support
            self._writeobj(sock, {
                "jsonrpc": "2.0",
                "method": "notifications",
                "id": this_id + "+notify-enable",
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

        if filter is None:
            filter = self._filter
        if filter is not None:
            request["filter"] = filter

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
            raise TypeError("Malformed response, response is not a dictionary %s." % resp)
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

    @contextmanager
    def reply_filter(self, filter):
        """Filter the fields returned from am RPC call (or more than one)..

        This is a context manager and should be used like this:

        ```python
        with rpc.reply_filter({"transactions": [{"outputs": [{"amount_msat": true, "type": true}]}]}):
            rpc.listtransactions()
        ```
        """
        old = self._filter
        self._filter = filter
        yield
        self._filter = old


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

    def __init__(self, socket_path, executor=None, logger=logging):
        super().__init__(
            socket_path,
            executor,
            logger
        )

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

    def autoclean_status(self, subsystem=None):
        """
        Print status of autocleaning (optionally, just for {subsystem}).
        """
        payload = {
            "subsystem": subsystem,
        }
        return self.call("autoclean-status", payload)

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

    def datastore(self, key, string=None, hex=None, mode=None, generation=None):
        """
        Add/replace an entry in the datastore; either string or hex.
        {key} can be a single string, or a sequence of strings.
        {mode} defaults to 'must-create', but other options are possible:
          - 'must-replace': fail it it doesn't already exist.
          - 'create-or-replace': don't fail.
          - 'must-append': must exist, and append to existing.
          - 'create-or-append': set, or append to existing.
        {generation} only succeeds if the current entry has this generation count (mode must be 'must-replace' or 'must-append').
        """
        payload = {
            "key": key,
            "string": string,
            "hex": hex,
            "mode": mode,
            "generation": generation,
        }
        return self.call("datastore", payload)

    def datastoreusage(self, key=None):
        """
        Returns the total bytes that are stored for under the given key or the
        root of the datastore. All descendants of the given key (or root) are
        taken into account.
        {key} can be a single string or a sequence of strings.
        """
        payload = {
            "key": key,
        }
        return self.call("datastoreusage", payload)

    def decodepay(self, bolt11, description=None):
        """
        Decode {bolt11}, using {description} if necessary.
        """
        payload = {
            "bolt11": bolt11,
            "description": description
        }
        return self.call("decodepay", payload)

    def deldatastore(self, key, generation=None):
        """
        Remove an existing entry from the datastore.
        {key} can be a single string, or a sequence of strings.
        {generation} means delete only succeeds if the current entry has this generation count.
        """
        payload = {
            "key": key,
            "generation": generation,
        }
        return self.call("deldatastore", payload)

    def delexpiredinvoice(self, maxexpirytime=None):
        """
        Delete all invoices that have expired on or before the given {maxexpirytime}.
        """
        payload = {
            "maxexpirytime": maxexpirytime
        }
        return self.call("delexpiredinvoice", payload)

    def delinvoice(self, label, status, desconly=None):
        """
        Delete unpaid invoice {label} with {status} (or, with {desconly} true, remove its description).
        """
        payload = {
            "label": label,
            "status": status,
            "desconly": desconly,
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

    def dev_pay(self, bolt11, amount_msat=None, label=None, riskfactor=None,
                maxfeepercent=None, retry_for=None,
                maxdelay=None, exemptfee=None, dev_use_shadow=True, exclude=None):
        """
        A developer version of `pay`, with the possibility to deactivate
        shadow routing (used for testing).
        """
        payload = {
            "bolt11": bolt11,
            "amount_msat": amount_msat,
            "label": label,
            "riskfactor": riskfactor,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "dev_use_shadow": dev_use_shadow,
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

    def fundchannel(self, node_id, amount, feerate=None, announce=True,
                    minconf=None, utxos=None, push_msat=None, close_to=None,
                    request_amt=None, compact_lease=None,
                    mindepth: Optional[int] = None,
                    reserve: Optional[str] = None,
                    channel_type=None):
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
            "mindepth": mindepth,
            "reserve": reserve,
            "channel_type": channel_type,
        }
        return self.call("fundchannel", payload)

    def fundchannel_start(self, node_id, amount, feerate=None, announce=True,
                          close_to=None, mindepth: Optional[int] = None, channel_type=None):
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
            "mindepth": mindepth,
            "channel_type": channel_type,
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

    def getroute(self, node_id, amount_msat, riskfactor, cltv=9, fromid=None,
                 fuzzpercent=None, exclude=None, maxhops=None):
        """
        Show route to {id} for {amount_msat}, using {riskfactor} and optional
        {cltv} (default 9). If specified search from {fromid} otherwise use
        this node as source. Randomize the route with up to {fuzzpercent}
        (0.0 -> 100.0, default 5.0). {exclude} is an optional array of
        scid/direction or node-id to exclude. Limit the number of hops in the
        route to {maxhops}.
        """
        payload = {
            "id": node_id,
            "amount_msat": amount_msat,
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

    def invoice(self, amount_msat, label, description, expiry=None, fallbacks=None,
                preimage=None, exposeprivatechannels=None, cltv=None, deschashonly=None):
        """
        Create an invoice for {amount_msat} with {label} and {description} with
        optional {expiry} seconds (default 1 week).
        """
        payload = {
            "amount_msat": amount_msat,
            "label": label,
            "description": description,
            "expiry": expiry,
            "fallbacks": fallbacks,
            "preimage": preimage,
            "exposeprivatechannels": exposeprivatechannels,
            "cltv": cltv,
            "deschashonly": deschashonly,
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

    def listdatastore(self, key=None):
        """
        Show entries in the heirarchical datastore, or just one from one {key}root.
        {key} can be a single string, or a sequence of strings.
        """
        payload = {
            "key": key,
        }
        return self.call("listdatastore", payload)

    def listforwards(self, status=None, in_channel=None, out_channel=None, index=None, start=None, limit=None):
        """List all forwarded payments and their information matching
        forward {status}, {in_channel} and {out_channel}.
        """
        payload = {
            "status": status,
            "in_channel": in_channel,
            "out_channel": out_channel,
            "index": index,
            "start": start,
            "limit": limit,
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

    def listinvoices(self, label=None, payment_hash=None, invstring=None, offer_id=None, index=None, start=None, limit=None):
        """Query invoices

        Show invoice matching {label}, {payment_hash}, {invstring} or {offer_id}
        (or all, if no filters are present).

        """
        payload = {
            "label": label,
            "payment_hash": payment_hash,
            "invstring": invstring,
            "offer_id": offer_id,
            "index": index,
            "start": start,
            "limit": limit,
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

    def listpeerchannels(self, peer_id=None):
        """
        Show current peers channels, and if the {peer_id} is specified
        all the channels for the peer are returned.
        """
        payload = {
            "id": peer_id,
        }
        return self.call("listpeerchannels", payload)

    def listsendpays(self, bolt11=None, payment_hash=None, status=None, index=None, start=None, limit=None):
        """Show all sendpays results, or only for `bolt11` or `payment_hash`."""
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash,
            "status": status,
            "index": index,
            "start": start,
            "limit": limit,
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

    def pay(self, bolt11, amount_msat=None, label=None, riskfactor=None,
            maxfeepercent=None, retry_for=None,
            maxdelay=None, exemptfee=None, localinvreqid=None, exclude=None,
            maxfee=None, description=None, partial_msat=None):
        """
        Send payment specified by {bolt11} with {amount_msat}
        (ignored if {bolt11} has an amount), optional {label}
        and {riskfactor} (default 1.0).
        """
        payload = {
            "bolt11": bolt11,
            "amount_msat": amount_msat,
            "label": label,
            "riskfactor": riskfactor,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "localinvreqid": localinvreqid,
            "exclude": exclude,
            "maxfee": maxfee,
            "description": description,
            "partial_msat": partial_msat,
        }
        return self.call("pay", payload)

    def openchannel_init(self, node_id, channel_amount, psbt, feerate=None, funding_feerate=None, announce=True, close_to=None, request_amt=None, channel_type=None):
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
            "channel_type": channel_type,
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

    def splice_init(self, chan_id, amount, initialpsbt=None, feerate_per_kw=None):
        """ Initiate a splice """
        payload = {
            "channel_id": chan_id,
            "relative_amount": amount,
            "initialpsbt": initialpsbt,
            "feerate_per_kw": feerate_per_kw,
        }
        return self.call("splice_init", payload)

    def splice_update(self, chan_id, psbt):
        """ Update a splice """
        payload = {
            "channel_id": chan_id,
            "psbt": psbt
        }
        return self.call("splice_update", payload)

    def splice_signed(self, chan_id, psbt):
        """ Initiate a splice """
        payload = {
            "channel_id": chan_id,
            "psbt": psbt
        }
        return self.call("splice_signed", payload)

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

    def sendcustommsg(self, peer_id, message):
        """
        Sending custom message {message} to {peer_id}.
        """
        payload = {
            "node_id": peer_id,
            "msg": message
        }
        return self.call("sendcustommsg", payload)

    def sendpay(self, route, payment_hash, label=None, amount_msat=None, bolt11=None, payment_secret=None, partid=None, groupid=None, payment_metadata=None):
        """
        Send along {route} in return for preimage of {payment_hash}.
        """
        payload = {
            "route": route,
            "payment_hash": payment_hash,
            "label": label,
            "amount_msat": amount_msat,
            "bolt11": bolt11,
            "payment_secret": payment_secret,
            "partid": partid,
            "groupid": groupid,
            "payment_metadata": payment_metadata,
        }
        return self.call("sendpay", payload)

    def sendonion(
            self, onion, first_hop, payment_hash, label=None,
            shared_secrets=None, partid=None, bolt11=None, amount_msat=None,
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
            "amount_msat": amount_msat,
            "destination": destination,
        }
        return self.call("sendonion", payload)

    def setchannel(self, id, feebase=None, feeppm=None, htlcmin=None, htlcmax=None, enforcedelay=None, ignorefeelimits=None):
        """Set configuration a channel/peer {id} (or 'all').

        {feebase} is a value in millisatoshi that is added as base fee
        to any routed payment.

        {feeppm} is a value added proportionally per-millionths to any
        routed payment volume in satoshi.

        {htlcmin} is the minimum (outgoing) htlc amount to allow and
        advertize.

        {htlcmax} is the maximum (outgoing) htlc amount to allow and
        advertize.

        {enforcedelay} is the number of seconds before enforcing this
        change.

        {ignorefeelimits} is a flag to indicate peer can set any feerate (dangerous!)

        """
        payload = {
            "id": id,
            "feebase": feebase,
            "feeppm": feeppm,
            "htlcmin": htlcmin,
            "htlcmax": htlcmax,
            "enforcedelay": enforcedelay,
            "ignorefeelimits": ignorefeelimits,
        }
        return self.call("setchannel", payload)

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

    def fundpsbt(self, satoshi, feerate, startweight, minconf=None, reserve=None, locktime=None, min_witness_weight=None, excess_as_change=False):
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

    def addpsbtoutput(self, satoshi, initialpsbt=None, locktime=None, destination=None):
        """
        Create a PSBT with an output of amount satoshi leading to the on-chain wallet
        """
        payload = {
            "satoshi": satoshi,
            "initialpsbt": initialpsbt,
            "locktime": locktime,
            "destination": destination,
        }
        return self.call("addpsbtoutput", payload)

    def utxopsbt(self, satoshi, feerate, startweight, utxos, reserve=None, reservedok=False, locktime=None, min_witness_weight=None, excess_as_change=False):
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

    def keysend(self, destination, amount_msat, label=None, maxfeepercent=None,
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
            "amount_msat": amount_msat,
            "label": label,
            "maxfeepercent": maxfeepercent,
            "retry_for": retry_for,
            "maxdelay": maxdelay,
            "exemptfee": exemptfee,
            "extratlvs": extratlvs,
        }
        return self.call("keysend", payload)
