from lnprototest import Runner, Event, Side, SpecFileError, Funding
from typing import Callable, Optional, Any
from pyln.proto.message import Message
import functools
import time
import coincurve


def commitsig_to_send() -> Callable[[Runner, Event, str], str]:
    """Get the appropriate signature for the local side to send to the remote"""

    def _commitsig_to_send(runner: Runner, event: Event, field: str) -> str:
        tx = runner.get_stash(event, "Commit").remote_unsigned_tx()
        return runner.get_stash(event, "Commit").local_sig(tx)

    return _commitsig_to_send


def commitsig_to_recv() -> Callable[[Runner, Event, str], str]:
    """Get the appropriate signature for the remote side to send to the local"""

    def _commitsig_to_recv(runner: Runner, event: Event, field: str) -> str:
        tx = runner.get_stash(event, "Commit").local_unsigned_tx()
        return runner.get_stash(event, "Commit").remote_sig(tx)

    return _commitsig_to_recv


def _htlc_sigs(signer: Side, runner: Runner, event: Event, field: str) -> str:
    sigs = runner.get_stash(event, "Commit").htlc_sigs(signer, not signer)
    return "[" + ",".join([sig.to_str() for sig in sigs]) + "]"


def htlc_sigs_to_send() -> Callable[[Runner, Event, str], str]:
    """Get the HTLC signatures for local side to send to the remote"""
    return functools.partial(_htlc_sigs, Side.local)


def htlc_sigs_to_recv() -> Callable[[Runner, Event, str], str]:
    """Get the HTLC signatures for remote side to send to the local"""
    return functools.partial(_htlc_sigs, Side.remote)


def channel_id() -> Callable[[Runner, Event, str], str]:
    """Get the channel_id for the current Commit"""

    def _channel_id(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "Commit").funding.channel_id()

    return _channel_id


def channel_id_v2() -> Callable[[Runner, Event, str], str]:
    """Get the channel_id for the current Commit for a v2 channel open"""

    def _channel_id(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "Commit").channel_id_v2()

    return _channel_id


def channel_announcement(
    short_channel_id: str, features: bytes
) -> Callable[[Runner, Event, str], str]:
    """Get the channel_announcement for the current Commit"""

    def _channel_announcement(
        short_channel_id: str, features: bytes, runner: Runner, event: Event, field: str
    ) -> Message:
        return runner.get_stash(event, "Commit").channel_announcement(
            short_channel_id, features
        )

    return functools.partial(_channel_announcement, short_channel_id, features)


def channel_update(
    short_channel_id: str,
    side: Side,
    disable: bool,
    cltv_expiry_delta: int,
    htlc_minimum_msat: int,
    fee_base_msat: int,
    fee_proportional_millionths: int,
    htlc_maximum_msat: Optional[int],
    timestamp: Optional[int] = None,
) -> Callable[[Runner, Event, str], str]:
    """Get a channel_update for the current Commit"""

    def _channel_update(
        short_channel_id: str,
        side: Side,
        disable: bool,
        cltv_expiry_delta: int,
        htlc_minimum_msat: int,
        fee_base_msat: int,
        fee_proportional_millionths: int,
        timestamp: Optional[int],
        htlc_maximum_msat: Optional[int],
        runner: Runner,
        event: Event,
        field: str,
    ) -> Message:
        """Get the channel_update"""
        if timestamp is None:
            timestamp = int(time.time())
            return runner.get_stash(event, "Commit").channel_update(
                short_channel_id,
                side,
                disable,
                cltv_expiry_delta,
                htlc_maximum_msat,
                fee_base_msat,
                fee_proportional_millionths,
                timestamp,
                htlc_maximum_msat,
            )

    return functools.partial(
        _channel_update,
        short_channel_id,
        side,
        disable,
        cltv_expiry_delta,
        htlc_minimum_msat,
        fee_base_msat,
        fee_proportional_millionths,
        htlc_maximum_msat,
        timestamp,
    )


def get_member(
    event: Event, runner: "Runner", stashname: str, var: str, last: bool = True
) -> str:
    """Get member field from stash for ExpectMsg or Msg.

    If var contains a '.' then we look for that message to extract the field.  If last is True, we get the last message, otherwise the first."""
    stash = runner.get_stash(event, stashname)
    if "." in var:
        prevname, _, var = var.partition(".")
    else:
        prevname = ""
    if last:
        seq = reversed(stash)
    else:
        seq = stash

    for name, d in seq:
        if prevname == "" or name == prevname:
            if var not in d:
                raise SpecFileError(
                    event,
                    "{}: {} did not receive a {}".format(stashname, prevname, var),
                )
            return d[var]
    raise SpecFileError(event, "{}: have no prior {}".format(stashname, prevname))


def _get_member(
    stashname: str,
    fieldname: Optional[str],
    casttype: Any,
    # This is the signature which Msg() expects for callable values:
    runner: "Runner",
    event: Event,
    field: str,
) -> Any:
    # If they don't specify fieldname, it's same as this field.
    if fieldname is None:
        fieldname = field
    strval = get_member(event, runner, stashname, fieldname)
    try:
        return casttype(strval)
    except ValueError:
        raise SpecFileError(
            event,
            "{}.{} is {}, not a valid {}".format(
                stashname, fieldname, strval, casttype
            ),
        )


def rcvd(
    fieldname: Optional[str] = None, casttype: Any = str
) -> Callable[[Runner, Event, Any], Any]:
    """Use previous ExpectMsg field (as string)

    fieldname can be [msg].[field] or just [field] for last ExpectMsg

    """
    return functools.partial(_get_member, "ExpectMsg", fieldname, casttype)


def sent(
    fieldname: Optional[str] = None, casttype: Any = str
) -> Callable[[Runner, Event, Any], Any]:
    """Use previous Msg field (as string)

    fieldname can be [msg].[field] or just [field] for last Msg

    """
    return functools.partial(_get_member, "Msg", fieldname, casttype)


def funding_amount() -> Callable[[Runner, Event, str], int]:
    """Get the stashed funding amount"""

    def _funding_amount(runner: Runner, event: Event, field: str) -> int:
        return runner.get_stash(event, "Funding").amount

    return _funding_amount


def funding_pubkey(side: Side) -> Callable[[Runner, Event, str], str]:
    """Get the stashed funding pubkey for side"""

    def _funding_pubkey(side: Side, runner: Runner, event: Event, field: str) -> str:
        return coincurve.PublicKey.from_secret(
            runner.get_stash(event, "Funding").funding_privkeys[side].secret
        )

    return functools.partial(_funding_pubkey, side)


def funding_tx() -> Callable[[Runner, Event, str], str]:
    """Get the funding transaction (as stashed by CreateFunding)"""

    def _funding_tx(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "FundingTx")

    return _funding_tx


def funding_txid() -> Callable[[Runner, Event, str], str]:
    """Get the stashed funding transaction id"""

    def _funding_txid(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "Funding").txid

    return _funding_txid


def funding() -> Callable[[Runner, Event, str], Funding]:
    """Get the stashed Funding (as stashed by CreateFunding or AcceptFunding)"""

    def _funding(runner: Runner, event: Event, field: str) -> Funding:
        return runner.get_stash(event, "Funding")

    return _funding


def witnesses() -> Callable[[Runner, Event, str], str]:
    """Get the witnesses for the stashed funding tx"""

    def _witnesses(runner: Runner, event: Event, field: str) -> str:
        funding = runner.get_stash(event, "Funding")
        return funding.our_witnesses()

    return _witnesses


def locking_script() -> Callable[[Runner, Event, str], str]:
    def _locking_script(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "Funding").locking_script().hex()

    return _locking_script


def funding_close_tx() -> Callable[[Runner, Event, str], str]:
    def _funding_close_tx(runner: Runner, event: Event, field: str) -> str:
        return runner.get_stash(event, "Funding").close_tx()

    return _funding_close_tx
