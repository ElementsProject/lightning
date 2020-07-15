from decimal import Decimal
from math import floor, log10
import json
import logging
import os
import socket
import warnings


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
    turned into Millisatoshi types. Converts to and from int.
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
            else:
                raise TypeError("Millisatoshi must be string with msat/sat/btc suffix or int")
            if self.millisatoshis != int(self.millisatoshis):
                raise ValueError("Millisatoshi must be a whole number")
            self.millisatoshis = int(self.millisatoshis)
        elif isinstance(v, Millisatoshi):
            self.millisatoshis = v.millisatoshis
        elif int(v) == v:
            self.millisatoshis = int(v)
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
        Return a Decimal representing the number of satoshis.
        """
        return Decimal(self.millisatoshis) / 1000

    def to_btc(self):
        """
        Return a Decimal representing the number of bitcoin.
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
            return '{:.11f}btc'.format(self.to_btc())
        else:
            return '{:.8f}btc'.format(self.to_btc())

    def to_approx_str(self, digits: int = 3):
        """Returns the shortmost string using common units representation.

        Rounds to significant `digits`. Default: 3
        """
        round_to_n = lambda x, n: round(x, -int(floor(log10(x))) + (n - 1))
        result = None

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
        return Millisatoshi(int(int(self) * other))

    def __truediv__(self, other):
        return Millisatoshi(int(int(self) / other))

    def __floordiv__(self, other):
        return Millisatoshi(int(self) // other)

    def __mod__(self, other):
        return Millisatoshi(int(self) % other)

    def __radd__(self, other):
        return Millisatoshi(int(self) + int(other))


class UnixSocket(object):
    """A wrapper for socket.socket that is specialized to unix sockets.

    Some OS implementations impose restrictions on the Unix sockets.

     - On linux OSs the socket path must be shorter than the in-kernel buffer
       size (somewhere around 100 bytes), thus long paths may end up failing
       the `socket.connect` call.

    This is a small wrapper that tries to work around these limitations.

    """

    def __init__(self, path):
        self.path = path
        self.sock = None
        self.connect()

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            return self.sock.connect(self.path)
        except OSError as e:
            self.sock.close()

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
                return self.sock.connect(short_path)
            else:
                # There is no good way to recover from this.
                raise

    def close(self):
        if self.sock is not None:
            self.sock.close()
        self.sock = None

    def sendall(self, b):
        if self.sock is None:
            raise socket.error("not connected")

        self.sock.sendall(b)

    def recv(self, length):
        if self.sock is None:
            raise socket.error("not connected")

        return self.sock.recv(length)

    def __del__(self):
        self.close()


class UnixDomainSocketRpc(object):
    def __init__(self, socket_path, executor=None, logger=logging, encoder_cls=json.JSONEncoder, decoder=json.JSONDecoder()):
        self.socket_path = socket_path
        self.encoder_cls = encoder_cls
        self.decoder = decoder
        self.executor = executor
        self.logger = logger

        self.next_id = 0

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
        self._writeobj(sock, {
            "jsonrpc": "2.0",
            "method": method,
            "params": payload,
            "id": self.next_id,
        })
        self.next_id += 1
        resp, _ = self._readobj(sock)
        sock.close()

        self.logger.debug("Received response for %s call: %r", method, resp)
        if not isinstance(resp, dict):
            raise ValueError("Malformed response, response is not a dictionary %s." % resp)
        elif "error" in resp:
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
        super().__init__(socket_path, executor, logger, self.LightningJSONEncoder, self.LightningJSONDecoder())

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

    def _deprecated_close(self, peer_id, force=None, timeout=None):
        warnings.warn("close now takes unilateraltimeout arg: expect removal"
                      " in early 2020",
                      DeprecationWarning)
        payload = {
            "id": peer_id,
            "force": force,
            "timeout": timeout
        }
        return self.call("close", payload)

    def close(self, peer_id, *args, **kwargs):
        """
        Close the channel with peer {id}, forcing a unilateral
        close after {unilateraltimeout} seconds if non-zero, and
        the to-local output will be sent to {destination}.

        Deprecated usage has {force} and {timeout} args.
        """

        if 'force' in kwargs or 'timeout' in kwargs:
            return self._deprecated_close(peer_id, *args, **kwargs)

        # Single arg is ambigious.
        if len(args) >= 1:
            if isinstance(args[0], bool):
                return self._deprecated_close(peer_id, *args, **kwargs)
            if len(args) == 2:
                if args[0] is None and isinstance(args[1], int):
                    return self._deprecated_close(peer_id, *args, **kwargs)

        def _close(peer_id, unilateraltimeout=None, destination=None, fee_negotiation_step=None):
            payload = {
                "id": peer_id,
                "unilateraltimeout": unilateraltimeout,
                "destination": destination,
                "fee_negotiation_step": fee_negotiation_step
            }
            return self.call("close", payload)

        return _close(peer_id, *args, **kwargs)

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
                description=None, maxfeepercent=None, retry_for=None,
                maxdelay=None, exemptfee=None, use_shadow=True):
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
            # Deprecated.
            "description": description,
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

    def _deprecated_fundchannel(self, node_id, satoshi, feerate=None, announce=True, minconf=None, utxos=None):
        warnings.warn("fundchannel: the 'satoshi' field is renamed 'amount' : expect removal"
                      " in Mid-2020",
                      DeprecationWarning)

        payload = {
            "id": node_id,
            "satoshi": satoshi,
            "feerate": feerate,
            "announce": announce,
            "minconf": minconf,
            "utxos": utxos
        }
        return self.call("fundchannel", payload)

    def fundchannel(self, node_id, *args, **kwargs):
        """
        Fund channel with {id} using {amount} satoshis with feerate
        of {feerate} (uses default feerate if unset).
        If {announce} is False, don't send channel announcements.
        Only select outputs with {minconf} confirmations.
        If {utxos} is specified (as a list of 'txid:vout' strings),
        fund a channel from these specifics utxos.
        """

        if 'satoshi' in kwargs:
            return self._deprecated_fundchannel(node_id, *args, **kwargs)

        def _fundchannel(node_id, amount, feerate=None, announce=True, minconf=None, utxos=None, push_msat=None):
            payload = {
                "id": node_id,
                "amount": amount,
                "feerate": feerate,
                "announce": announce,
                "minconf": minconf,
                "utxos": utxos,
                "push_msat": push_msat
            }
            return self.call("fundchannel", payload)

        return _fundchannel(node_id, *args, **kwargs)

    def _deprecated_fundchannel_start(self, node_id, satoshi, feerate=None, announce=True):
        warnings.warn("fundchannel_start: the 'satoshi' field is renamed 'amount' : expect removal"
                      " in Mid-2020",
                      DeprecationWarning)

        payload = {
            "id": node_id,
            "satoshi": satoshi,
            "feerate": feerate,
            "announce": announce,
        }
        return self.call("fundchannel_start", payload)

    def fundchannel_start(self, node_id, *args, **kwargs):
        """
        Start channel funding with {id} for {amount} satoshis
        with feerate of {feerate} (uses default feerate if unset).
        If {announce} is False, don't send channel announcements.
        Returns a Bech32 {funding_address} for an external wallet
        to create a funding transaction for. Requires a call to
        'fundchannel_complete' to complete channel establishment
        with peer.
        """

        if 'satoshi' in kwargs:
            return self._deprecated_fundchannel_start(node_id, *args, **kwargs)

        def _fundchannel_start(node_id, amount, feerate=None, announce=True, close_to=None):
            payload = {
                "id": node_id,
                "amount": amount,
                "feerate": feerate,
                "announce": announce,
                "close_to": close_to,
            }
            return self.call("fundchannel_start", payload)

        return _fundchannel_start(node_id, *args, **kwargs)

    def fundchannel_cancel(self, node_id):
        """
        Cancel a 'started' fundchannel with node {id}.
        """
        payload = {
            "id": node_id,
        }
        return self.call("fundchannel_cancel", payload)

    def fundchannel_complete(self, node_id, funding_txid, funding_txout):
        """
        Complete channel establishment with {id}, using {funding_txid} at {funding_txout}.
        """
        payload = {
            "id": node_id,
            "txid": funding_txid,
            "txout": funding_txout,
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

    def invoice(self, msatoshi, label, description, expiry=None, fallbacks=None, preimage=None, exposeprivatechannels=None):
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
            "exposeprivatechannels": exposeprivatechannels
        }
        return self.call("invoice", payload)

    def listchannels(self, short_channel_id=None, source=None):
        """
        Show all known channels, accept optional {short_channel_id} or {source}.
        """
        payload = {
            "short_channel_id": short_channel_id,
            "source": source
        }
        return self.call("listchannels", payload)

    def listconfigs(self, config=None):
        """List this node's config.
        """
        payload = {
            "config": config
        }
        return self.call("listconfigs", payload)

    def listforwards(self):
        """List all forwarded payments and their information.
        """
        return self.call("listforwards")

    def listfunds(self):
        """
        Show funds available for opening channels.
        """
        return self.call("listfunds")

    def listtransactions(self):
        """
        Show wallet history.
        """
        return self.call("listtransactions")

    def listinvoices(self, label=None):
        """
        Show invoice {label} (or all, if no {label)).
        """
        payload = {
            "label": label
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

    def listpayments(self, bolt11=None, payment_hash=None):
        """
        Show outgoing payments, regarding {bolt11} or {payment_hash} if set
        Can only specify one of {bolt11} or {payment_hash}.
        """
        assert not (bolt11 and payment_hash)
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash
        }
        return self.call("listpayments", payload)

    def listpeers(self, peerid=None, level=None):
        """
        Show current peers, if {level} is set, include {log}s".
        """
        payload = {
            "id": peerid,
            "level": level,
        }
        return self.call("listpeers", payload)

    def listsendpays(self, bolt11=None, payment_hash=None):
        """Show all sendpays results, or only for `bolt11` or `payment_hash`."""
        payload = {
            "bolt11": bolt11,
            "payment_hash": payment_hash
        }
        return self.call("listsendpays", payload)

    def newaddr(self, addresstype=None):
        """Get a new address of type {addresstype} of the internal wallet.
        """
        return self.call("newaddr", {"addresstype": addresstype})

    def pay(self, bolt11, msatoshi=None, label=None, riskfactor=None,
            description=None, maxfeepercent=None, retry_for=None,
            maxdelay=None, exemptfee=None):
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
            # Deprecated.
            "description": description,
        }
        return self.call("pay", payload)

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

    def plugin_start(self, plugin):
        """
        Adds a plugin to lightningd.
        """
        payload = {
            "subcommand": "start",
            "plugin": plugin
        }
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

    def _deprecated_sendpay(self, route, payment_hash, description, msatoshi=None):
        warnings.warn("sendpay: the 'description' field is renamed 'label' : expect removal"
                      " in early-2020",
                      DeprecationWarning)
        payload = {
            "route": route,
            "payment_hash": payment_hash,
            "label": description,
            "msatoshi": msatoshi,
        }
        return self.call("sendpay", payload)

    def sendpay(self, route, payment_hash, *args, **kwargs):
        """
        Send along {route} in return for preimage of {payment_hash}.
        """

        if 'description' in kwargs:
            return self._deprecated_sendpay(route, payment_hash, *args, **kwargs)

        def _sendpay(route, payment_hash, label=None, msatoshi=None, bolt11=None, payment_secret=None, partid=None):
            payload = {
                "route": route,
                "payment_hash": payment_hash,
                "label": label,
                "msatoshi": msatoshi,
                "bolt11": bolt11,
                "payment_secret": payment_secret,
                "partid": partid,
            }
            return self.call("sendpay", payload)

        return _sendpay(route, payment_hash, *args, **kwargs)

    def setchannelfee(self, id, base=None, ppm=None):
        """
        Set routing fees for a channel/peer {id} (or 'all'). {base} is a value in millisatoshi
        that is added as base fee to any routed payment. {ppm} is a value added proportionally
        per-millionths to any routed payment volume in satoshi.
        """
        payload = {
            "id": id,
            "base": base,
            "ppm": ppm
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

    def waitsendpay(self, payment_hash, timeout=None, partid=None):
        """
        Wait for payment for preimage of {payment_hash} to complete.
        """
        payload = {
            "payment_hash": payment_hash,
            "timeout": timeout,
            "partid": partid,
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

    def _deprecated_txprepare(self, destination, satoshi, feerate=None, minconf=None):
        warnings.warn("txprepare now takes output arg: expect removal"
                      " in Mid-2020",
                      DeprecationWarning)
        payload = {
            "destination": destination,
            "satoshi": satoshi,
            "feerate": feerate,
            "minconf": minconf,
        }
        return self.call("txprepare", payload)

    def txprepare(self, *args, **kwargs):
        """
        Prepare a Bitcoin transaction which sends to [outputs].
        The format of output is like [{address1: amount1},
        {address2: amount2}], or [{address: "all"}]).
        Only select outputs with {minconf} confirmations.

        Outputs will be reserved until you call txdiscard or txsend, or
        lightningd restarts.
        """
        if 'destination' in kwargs or 'satoshi' in kwargs:
            return self._deprecated_txprepare(*args, **kwargs)

        if len(args) and not isinstance(args[0], list):
            return self._deprecated_txprepare(*args, **kwargs)

        def _txprepare(outputs, feerate=None, minconf=None, utxos=None):
            payload = {
                "outputs": outputs,
                "feerate": feerate,
                "minconf": minconf,
                "utxos": utxos,
            }
            return self.call("txprepare", payload)

        return _txprepare(*args, **kwargs)

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

    def reserveinputs(self, psbt, exclusive=True):
        """
        Reserve any inputs in this psbt.
        """
        payload = {
            "psbt": psbt,
            "exclusive": exclusive,
        }
        return self.call("reserveinputs", payload)

    def unreserveinputs(self, psbt):
        """
        Unreserve (or reduce reservation) on any UTXOs in this psbt were previously reserved.
        """
        payload = {
            "psbt": psbt,
        }
        return self.call("unreserveinputs", payload)

    def signpsbt(self, psbt):
        """
        Add internal wallet's signatures to PSBT
        """
        payload = {
            "psbt": psbt,
        }
        return self.call("signpsbt", payload)

    def sendpsbt(self, psbt):
        """
        Finalize extract and broadcast a PSBT
        """
        payload = {
            "psbt": psbt,
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
