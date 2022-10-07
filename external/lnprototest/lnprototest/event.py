#! /usr/bin/python3
import traceback
from pyln.proto.message import Message
import collections
import os.path
import io
import struct
import time
from .errors import SpecFileError, EventError
from .namespace import namespace
from .utils import check_hex
from .signature import Sig
from .bitfield import has_bit
from bitcoin.core import CTransaction
from typing import Optional, Dict, Union, Callable, Any, List, TYPE_CHECKING, overload

if TYPE_CHECKING:
    # Otherwise a circular dependency
    from .runner import Runner, Conn


# Type for arguments: either strings, or functions to call at runtime
ResolvableStr = Union[str, Callable[["Runner", "Event", str], str]]
ResolvableInt = Union[int, Callable[["Runner", "Event", str], int]]
ResolvableBool = Union[int, Callable[["Runner", "Event", str], bool]]
Resolvable = Union[Any, Callable[["Runner", "Event", str], Any]]


class Event(object):
    """Abstract base class for events."""

    def __init__(self) -> None:
        # From help(traceback.extract_stack):
        #   Each item in the list is a quadruple (filename,
        #   line number, function name, text), and the entries are in order
        #   from oldest to newest stack frame.
        self.name = "unknown"
        for s in reversed(traceback.extract_stack()):
            # Ignore constructor calls, like this one.
            if s[2] != "__init__":
                self.name = "{}:{}:{}".format(
                    type(self).__name__, os.path.basename(s[0]), s[1]
                )
                break

    def enabled(self, runner: "Runner") -> bool:
        """Returns whether it should be enabled for this run.  Usually True"""
        return True

    def action(self, runner: "Runner") -> bool:
        """action() returns the False if it needs to be called again"""
        if runner.config.getoption("verbose"):
            print("# running {}:".format(self))
        return True

    def resolve_arg(self, fieldname: str, runner: "Runner", arg: Resolvable) -> Any:
        """If this is a string, return it, otherwise call it to get result"""
        if callable(arg):
            return arg(runner, self, fieldname)
        else:
            return arg

    def resolve_args(
        self, runner: "Runner", kwargs: Dict[str, Resolvable]
    ) -> Dict[str, Any]:
        """Take a dict of args, replace callables with their return values"""
        ret: Dict[str, str] = {}
        for field, str_or_func in kwargs.items():
            ret[field] = self.resolve_arg(field, runner, str_or_func)
        return ret

    def __repr__(self) -> str:
        return self.name


class PerConnEvent(Event):
    """An event which takes a connprivkey arg"""

    def __init__(self, connprivkey: Optional[str]):
        super().__init__()
        self.connprivkey = connprivkey

    def find_conn(self, runner: "Runner") -> "Conn":
        """Helper for events which have a connection"""
        conn = runner.find_conn(self.connprivkey)
        if conn is None:
            if self.connprivkey is None:
                # None means "same as last used/created"
                raise SpecFileError(self, "No current connection")
            else:
                raise SpecFileError(
                    self, "Unknown connection {}".format(self.connprivkey)
                )
        return conn


class Connect(Event):
    """Connect to the runner, as if a node with private key connprivkey"""

    def __init__(self, connprivkey: str):
        self.connprivkey = connprivkey
        super().__init__()

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        if runner.find_conn(self.connprivkey):
            raise SpecFileError(
                self, "Already have connection to {}".format(self.connprivkey)
            )
        # This is a hack: if we've already got a connection, wait 1 second
        # for gossip to be processed before connecting another one!
        if len(runner.conns) != 0:
            time.sleep(1)
        runner.connect(self, self.connprivkey)
        return True


class MustNotMsg(PerConnEvent):
    """Indicate that this connection must never send any of these message types."""

    def __init__(self, must_not: str, connprivkey: Optional[str] = None):
        super().__init__(connprivkey)
        self.must_not = must_not

    def matches(self, binmsg: bytes) -> bool:
        msgnum = struct.unpack(">H", binmsg[0:2])[0]
        msgtype = namespace().get_msgtype_by_number(msgnum)
        if msgtype:
            name = msgtype.name
        else:
            name = str(msgnum)

        return name == self.must_not

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        self.find_conn(runner).must_not_events.append(self)
        return True


class Disconnect(PerConnEvent):
    """Disconnect the runner from the node whose private key is connprivkey: default is last connection specified"""

    def __init__(self, connprivkey: Optional[str] = None):
        super().__init__(connprivkey)

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.disconnect(self, self.find_conn(runner))
        return True


class Msg(PerConnEvent):
    """Feed a message to the runner (via optional given connection)"""

    def __init__(
        self,
        msgtypename: str,
        connprivkey: Optional[str] = None,
        **kwargs: Union[ResolvableStr, ResolvableInt],
    ):
        super().__init__(connprivkey)
        self.msgtype = namespace().get_msgtype(msgtypename)

        if not self.msgtype:
            raise SpecFileError(self, "Unknown msgtype {}".format(msgtypename))
        self.kwargs = kwargs

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        # Now we have runner, we can fill in all the message fields
        message = Message(self.msgtype, **self.resolve_args(runner, self.kwargs))
        missing = message.missing_fields()
        if missing:
            raise SpecFileError(self, "Missing fields {}".format(missing))
        binmsg = io.BytesIO()
        message.write(binmsg)
        runner.recv(self, self.find_conn(runner), binmsg.getvalue())
        msg_to_stash(runner, self, message)
        return True


class Wait(PerConnEvent):
    """Put a delay in a test, to allow time for things to happen
    on the node's end"""

    def __init__(self, delay_s: int):
        self.delay_s = delay_s

    def action(self, runner: "Runner") -> bool:
        time.sleep(self.delay_s)
        return True


class RawMsg(PerConnEvent):
    """Feed a raw binary, or raw Message to the runner (via optional given connection)"""

    def __init__(
        self,
        message: Union[Resolvable, bytes, Message],
        connprivkey: Optional[str] = None,
    ):
        super().__init__(connprivkey)
        self.message = message

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        msg = self.resolve_arg("binmsg", runner, self.message)
        if isinstance(msg, Message):
            buf = io.BytesIO()
            msg.write(buf)
            binmsg = buf.getvalue()
        else:
            binmsg = msg

        runner.recv(self, self.find_conn(runner), binmsg)
        return True


class ExpectMsg(PerConnEvent):
    """Wait for a message from the runner.

    Args is the (usually incomplete) message which it should match.
    if_match is the function to call if it matches: should raise an
    exception if it's not satisfied.  ignore function to ignore unexpected
    messages: it returns a list of messages to reply with, or None if the
    message should not be ignored: by default, it is ignore_gossip_queries.

    """

    def _default_if_match(self, msg: Message, runner: "Runner") -> None:
        pass

    @staticmethod
    def ignore_pings(msg: Message) -> Optional[List[Message]]:
        """Function to ignore pings (and respond with pongs appropriately)"""
        if msg.messagetype.name != "ping":
            return None

        # BOLT #1:
        # A node receiving a `ping` message:
        # ...
        #  - if `num_pong_bytes` is less than 65532:
        #    - MUST respond by sending a `pong` message, with `byteslen` equal
        #     to `num_pong_bytes`.
        #  - otherwise (`num_pong_bytes` is **not** less than 65532):
        #    - MUST ignore the `ping`.
        if msg.fields["num_pong_bytes"] >= 65532:
            return []

        # A node sending a `pong` message:
        #  - SHOULD set `ignored` to 0s.
        #  - MUST NOT set `ignored` to sensitive data such as secrets or
        #    portions of initialized
        outmsg = Message(
            namespace().get_msgtype("pong"), ignored="00" * msg.fields["num_pong_bytes"]
        )
        return [outmsg]

    @staticmethod
    def ignore_gossip_queries(msg: Message) -> Optional[List[Message]]:
        """Ignore gossip_timestamp_filter, query_channel_range and query_short_channel_ids.  Respond to pings."""
        if msg.messagetype.name in (
            "gossip_timestamp_filter",
            "query_channel_range",
            "query_short_channel_ids",
        ):
            return []
        return ExpectMsg.ignore_pings(msg)

    @staticmethod
    def ignore_all_gossip(msg: Message) -> Optional[List[Message]]:
        """Ignore any gossip messages.  Respond to pings."""
        # BOLT #1: The messages are grouped logically into five
        # groups, ordered by the most significant bit that is set: ...
        #   - Routing (types `256`-`511`): messages containing node and channel
        #     announcements, as well as any active route exploration (described
        #     in [BOLT #7](07-routing-gossip.md))
        if msg.messagetype.number in range(256, 512):
            return []
        return ExpectMsg.ignore_pings(msg)

    def __init__(
        self,
        msgtypename: str,
        if_match: Callable[["ExpectMsg", Message, "Runner"], None] = _default_if_match,
        ignore: Optional[Callable[[Message], Optional[List[Message]]]] = None,
        connprivkey: Optional[str] = None,
        **kwargs: Union[str, Resolvable],
    ):
        super().__init__(connprivkey)
        self.msgtype = namespace().get_msgtype(msgtypename)
        if not self.msgtype:
            raise SpecFileError(self, "Unknown msgtype {}".format(msgtypename))
        self.kwargs = kwargs
        self.if_match = if_match
        # Assigning this in the __init__ line doesn't work!
        if ignore is None:
            ignore = self.ignore_gossip_queries
        self.ignore = ignore

    def message_match(self, runner: "Runner", msg: Message) -> Optional[str]:
        """Does this message match what we expect?"""
        partmessage = Message(self.msgtype, **self.resolve_args(runner, self.kwargs))

        ret = cmp_msg(msg, partmessage)
        if ret is None:
            self.if_match(self, msg, runner)
            msg_to_stash(runner, self, msg)
        return ret

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        conn = self.find_conn(runner)
        while True:
            binmsg = runner.get_output_message(conn, self)
            if binmsg is None:
                raise EventError(
                    self, f"Did not receive a message {self.msgtype} from runner"
                )

            for e in conn.must_not_events:
                if e.matches(binmsg):
                    raise EventError(
                        self, "Got msg banned by {}: {}".format(e, binmsg.hex())
                    )

            # Might be completely unknown to namespace.
            try:
                msg = Message.read(namespace(), io.BytesIO(binmsg))
            except ValueError as ve:
                raise EventError(
                    self, "Runner gave bad msg {}: {}".format(binmsg.hex(), ve)
                )

            # Ignore function may tell us to respond.
            response = self.ignore(msg)
            if response is not None:
                for msg in response:
                    binm = io.BytesIO()
                    msg.write(binm)
                    runner.recv(self, conn, binm.getvalue())
                continue

            err = self.message_match(runner, msg)
            if err:
                raise EventError(self, "{}: message was {}".format(err, msg.to_str()))

            break
        return True


class Block(Event):
    """Generate a block, at blockheight, with optional txs."""

    def __init__(
        self, blockheight: int, number: int = 1, txs: List[ResolvableStr] = []
    ):
        super().__init__()
        self.blockheight = blockheight
        self.number = number
        self.txs = txs

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        # Oops, did they ask us to produce a block with no predecessor?
        if runner.getblockheight() + 1 < self.blockheight:
            raise SpecFileError(
                self,
                "Cannot generate block #{} at height {}".format(
                    self.blockheight, runner.getblockheight()
                ),
            )

        # Throw away blocks we're replacing.
        if runner.getblockheight() >= self.blockheight:
            runner.trim_blocks(self.blockheight - 1)

        # Add new one
        runner.add_blocks(
            self, [self.resolve_arg("tx", runner, tx) for tx in self.txs], self.number
        )
        assert runner.getblockheight() == self.blockheight - 1 + self.number
        return True


class ExpectTx(Event):
    """Expect the runner to broadcast a transaction"""

    def __init__(self, txid: ResolvableStr):
        super().__init__()
        self.txid = txid

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.expect_tx(self, self.resolve_arg("txid", runner, self.txid))
        return True


class FundChannel(PerConnEvent):
    """Tell the runner to fund a channel with this peer."""

    def __init__(
        self,
        amount: ResolvableInt,
        feerate: ResolvableInt = 253,
        expect_fail: ResolvableBool = False,
        connprivkey: Optional[str] = None,
    ):
        super().__init__(connprivkey)
        self.amount = amount
        self.feerate = feerate
        self.expect_fail = expect_fail

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.fundchannel(
            self,
            self.find_conn(runner),
            self.resolve_arg("amount", runner, self.amount),
            self.resolve_arg("feerate", runner, self.feerate),
            self.resolve_arg("expect_fail", runner, self.expect_fail),
        )
        return True


class InitRbf(PerConnEvent):
    def __init__(
        self,
        channel_id: ResolvableStr,
        amount: ResolvableInt,
        utxo_tx: ResolvableStr,
        utxo_outnum: ResolvableInt,
        feerate: int,
        connprivkey: Optional[str] = None,
    ):
        super().__init__(connprivkey)
        self.channel_id = channel_id
        self.amount = amount
        self.feerate = feerate
        self.utxo_tx = utxo_tx
        self.utxo_outnum = utxo_outnum

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        utxo_tx = self.resolve_arg("utxo_tx", runner, self.utxo_tx)
        txid = CTransaction.deserialize(bytes.fromhex(utxo_tx)).GetTxid()[::-1].hex()

        runner.init_rbf(
            self,
            self.find_conn(runner),
            self.resolve_arg("channel_id", runner, self.channel_id),
            self.resolve_arg("amount", runner, self.amount),
            txid,
            self.resolve_arg("utxo_outnum", runner, self.utxo_outnum),
            self.feerate,
        )

        return True


class Invoice(Event):
    def __init__(self, amount: int, preimage: ResolvableStr):
        super().__init__()
        self.preimage = preimage
        self.amount = amount

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.invoice(
            self,
            self.amount,
            check_hex(self.resolve_arg("preimage", runner, self.preimage), 64),
        )
        return True


class AddHtlc(PerConnEvent):
    def __init__(
        self, amount: int, preimage: ResolvableStr, connprivkey: Optional[str] = None
    ):
        super().__init__(connprivkey)
        self.preimage = preimage
        self.amount = amount

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.addhtlc(
            self,
            self.find_conn(runner),
            self.amount,
            check_hex(self.resolve_arg("preimage", runner, self.preimage), 64),
        )
        return True


class DualFundAccept(Event):
    def __init__(self) -> None:
        super().__init__()

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        runner.accept_add_fund(self)
        return True


class ExpectError(PerConnEvent):
    def __init__(self, connprivkey: Optional[str] = None):
        super().__init__(connprivkey)

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        error = runner.check_error(self, self.find_conn(runner))
        if error is None:
            raise EventError(self, "No error found")
        return True


class CheckEq(Event):
    """Event to check a condition is true"""

    def __init__(self, a: Resolvable, b: Resolvable):
        super().__init__()
        self.a = a
        self.b = b

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        a = self.resolve_arg("a", runner, self.a)
        b = self.resolve_arg("b", runner, self.b)
        # dummy runner generates dummy fields.
        if a != b and not runner._is_dummy():
            raise EventError(self, "{} != {}".format(a, b))
        return True


class CloseChannel(Event):
    """Implementing the lnprototest event related to the
    close channel operation.
    BOLT 2"""

    def __init__(self, channel_id: str):
        super(CloseChannel, self).__init__()
        self.channel_id = channel_id

    def action(self, runner: "Runner") -> bool:
        super().action(runner)
        return runner.close_channel(self.channel_id)


def msg_to_stash(runner: "Runner", event: Event, msg: Message) -> None:
    """ExpectMsg and Msg save every field to the stash, in order"""
    fields = msg.to_py()

    stash = runner.get_stash(event, type(event).__name__, [])
    stash.append((msg.messagetype.name, fields))
    runner.add_stash(type(event).__name__, stash)


def cmp_obj(obj: Any, expected: Any, prefix: str) -> Optional[str]:
    """Return None if every field in expected matches a field in obj.  Otherwise return a complaint"""
    if isinstance(expected, collections.abc.Mapping):
        for k, v in expected.items():
            if k not in obj:
                return "Missing field {}".format(prefix + "." + k)
            diff = cmp_obj(obj[k], v, prefix + "." + k)
            if diff:
                return diff
    elif not isinstance(expected, str) and isinstance(
        expected, collections.abc.Sequence
    ):
        # Should we allow expected to be shorter?
        if len(expected) != len(obj):
            return "Expected {} elements, got {} in {}: expected {} not {}".format(
                len(expected), len(obj), prefix, expected, obj
            )
        for i in range(len(expected)):
            diff = cmp_obj(obj[i], expected[i], "{}[{}]".format(prefix, i))
            if diff:
                return diff
    elif isinstance(expected, str) and expected.startswith("Sig("):
        # Special handling for signature comparisons.
        if Sig.from_str(expected) != Sig.from_str(obj):
            return "{}: signature mismatch {} != {}".format(prefix, obj, expected)
    else:
        if obj != expected:
            return "{}: {} != {}".format(prefix, obj, expected)

    return None


def cmp_msg(msg: Message, expected: Message) -> Optional[str]:
    """Return None if every field in expected matches a field in msg.  Otherwise return a complaint"""
    if msg.messagetype != expected.messagetype:
        return "Expected {}, got {}".format(expected.messagetype, msg.messagetype)

    obj = msg.to_py()
    expected_obj = expected.to_py()

    return cmp_obj(obj, expected_obj, expected.messagetype.name)


@overload
def msat(sats: int) -> int:
    ...


@overload
def msat(
    sats: Callable[["Runner", "Event", str], int]
) -> Callable[["Runner", "Event", str], int]:
    ...


def msat(sats: ResolvableInt) -> ResolvableInt:
    """Convert a field from statoshis to millisatoshis"""

    def _msat(runner: "Runner", event: Event, field: str) -> int:
        if callable(sats):
            return 1000 * sats(runner, event, field)
        else:
            return 1000 * sats

    if callable(sats):
        return _msat
    else:
        return 1000 * sats


def negotiated(
    a_features: ResolvableStr,
    b_features: ResolvableStr,
    included: List[int] = [],
    excluded: List[int] = [],
) -> ResolvableBool:
    def has_feature(fbit: int, featurebits: str) -> bool:
        # Feature bits go in optional/compulsory pairs.
        altfbit = fbit ^ 1
        return has_bit(featurebits, fbit) or has_bit(featurebits, altfbit)

    def _negotiated(runner: "Runner", event: Event, field: str) -> bool:
        a = event.resolve_arg("features", runner, a_features)
        b = event.resolve_arg("features", runner, b_features)

        for i in included:
            if not has_feature(i, a) or not has_feature(i, b):
                return False

        for e in excluded:
            if has_feature(e, a) or has_feature(e, b):
                return False

        return True

    return _negotiated
