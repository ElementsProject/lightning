#! /usr/bin/env python3
# Tests for gossip_timestamp_filter
from lnprototest import (
    Connect,
    Block,
    ExpectMsg,
    Msg,
    RawMsg,
    Funding,
    Event,
    Side,
    MustNotMsg,
    OneOf,
    Runner,
    bitfield,
    TryAll,
    Sequence,
    regtest_hash,
    CheckEq,
    EventError,
    namespace,
    Wait,
)
from helpers import tx_spendable, utxo
from typing import Optional
import unittest
import time
import io
import zlib
import crc32c
from pyln.spec.bolt7 import channel_update_timestamps
from pyln.proto.message import Message

# Note for gossip_channel_range: we are *allowed* to return a superset
# of what they ask, so if someone does that this test must be modified
# to accept it (add an option_IMPL_gossip_query_superset?).
#
# Meanwhile, we assume an exact reply.


def encode_timestamps(t1: int = 0, t2: int = 0) -> str:
    # BOLT #7:
    # For a single `channel_update`, timestamps are encoded as:
    #
    # 1. subtype: `channel_update_timestamps`
    # 2. data:
    #     * [`u32`:`timestamp_node_id_1`]
    #     * [`u32`:`timestamp_node_id_2`]
    #
    # Where:
    # * `timestamp_node_id_1` is the timestamp of the `channel_update` for
    #   `node_id_1`, or 0 if there was no `channel_update` from that node.
    # * `timestamp_node_id_2` is the timestamp of the `channel_update` for
    #    `node_id_2`, or 0 if there was no `channel_update` from that node.
    v, _ = channel_update_timestamps.val_from_str(
        "{{timestamp_node_id_1={},timestamp_node_id_2={}}}".format(t1, t2)
    )

    buf = io.BytesIO()
    channel_update_timestamps.write(buf, v, {})
    return buf.getvalue().hex()


def decode_timestamps(runner: "Runner", event: Event, field: str) -> str:
    # Get timestamps from last reply_channel_range msg
    timestamps = runner.get_stash(event, "ExpectMsg")[-1][1]["tlvs"]["timestamps_tlv"]

    # BOLT #7:
    # Encoding types:
    # * `0`: uncompressed array of `short_channel_id` types, in ascending
    #   order.
    # * `1`: array of `short_channel_id` types, in ascending order, compressed
    #   with zlib deflate<sup>[1](#reference-1)</sup>
    if timestamps["encoding_type"] == 0:
        b = bytes.fromhex(timestamps["encoded_timestamps"])
    elif timestamps["encoding_type"] == 1:
        b = zlib.decompress(bytes.fromhex(timestamps["encoded_timestamps"]))
    else:
        raise EventError(event, "Unknown encoding type: {}".format(timestamps))

    return b.hex()


def decode_scids(runner: "Runner", event: Event, field: str) -> str:
    # Nothing to decode if dummy runner.
    if runner._is_dummy():
        return ""

    # Get encoded_short_ids from last msg.
    encoded = bytes.fromhex(
        runner.get_stash(event, "ExpectMsg")[-1][1]["encoded_short_ids"]
    )
    # BOLT #7:
    # Encoding types:
    # * `0`: uncompressed array of `short_channel_id` types, in ascending
    #   order.
    # * `1`: array of `short_channel_id` types, in ascending order, compressed
    #   with zlib deflate<sup>[1](#reference-1)</sup>
    if encoded[0] == 0:
        b = encoded[1:]
    elif encoded[0] == 1:
        b = zlib.decompress(encoded[1:])
    else:
        raise EventError(
            event, "Unknown encoding type {}: {}".format(encoded[0], encoded.hex())
        )

    scidtype = namespace().get_fundamentaltype("short_channel_id")
    arr = []
    buf = io.BytesIO(b)
    while True:
        scid = scidtype.read(buf, {})
        if scid is None:
            break
        arr.append(scid)

    return ",".join([scidtype.val_to_str(a, {}) for a in arr])


def calc_checksum(update: Message) -> int:
    # BOLT #7: The checksum of a `channel_update` is the CRC32C checksum as
    # specified in [RFC3720](https://tools.ietf.org/html/rfc3720#appendix-B.4)
    # of this `channel_update` without its `signature` and `timestamp` fields.
    bufio = io.BytesIO()
    update.write(bufio)
    buf = bufio.getvalue()

    # BOLT #7:
    # 1. type: 258 (`channel_update`)
    # 2. data:
    #     * [`signature`:`signature`]
    #     * [`chain_hash`:`chain_hash`]
    #     * [`short_channel_id`:`short_channel_id`]
    #     * [`u32`:`timestamp`]
    #     * [`byte`:`message_flags`]

    # Note: 2 bytes for `type` field
    return crc32c.crc32c(buf[2 + 64 : 2 + 64 + 32 + 8] + buf[2 + 64 + 32 + 8 + 4 :])


def update_checksums(update1: Optional[Message], update2: Optional[Message]) -> str:
    # BOLT #7:
    # For a single `channel_update`, checksums are encoded as:
    #
    # 1. subtype: `channel_update_checksums`
    # 2. data:
    #     * [`u32`:`checksum_node_id_1`]
    #     * [`u32`:`checksum_node_id_2`]
    #
    # Where:
    # * `checksum_node_id_1` is the checksum of the `channel_update` for
    #   `node_id_1`, or 0 if there was no `channel_update` from that node.
    # * `checksum_node_id_2` is the checksum of the `channel_update` for
    #   `node_id_2`, or 0 if there was no `channel_update` from that node.
    if update1:
        csum1 = calc_checksum(update1)
    else:
        csum1 = 0

    if update2:
        csum2 = calc_checksum(update2)
    else:
        csum2 = 0

    return "{{checksum_node_id_1={},checksum_node_id_2={}}}".format(csum1, csum2)


def test_query_channel_range(runner: Runner) -> None:
    if runner.has_option("option_gossip_queries") is None:
        unittest.SkipTest("Needs option_gossip_queries")

    funding1, funding1_tx = Funding.from_utxo(
        *utxo(0),
        local_node_privkey="02",
        local_funding_privkey="10",
        remote_node_privkey="03",
        remote_funding_privkey="20"
    )

    funding2, funding2_tx = Funding.from_utxo(
        *utxo(1),
        local_node_privkey="04",
        local_funding_privkey="30",
        remote_node_privkey="05",
        remote_funding_privkey="40"
    )

    timestamp_103x1x0_LOCAL = int(time.time())
    timestamp_109x1x0_LOCAL = timestamp_103x1x0_LOCAL - 1
    timestamp_109x1x0_REMOTE = timestamp_109x1x0_LOCAL - 1

    ts_103x1x0 = encode_timestamps(*funding1.node_id_sort(timestamp_103x1x0_LOCAL, 0))
    ts_109x1x0 = encode_timestamps(
        *funding2.node_id_sort(timestamp_109x1x0_LOCAL, timestamp_109x1x0_REMOTE)
    )

    update_103x1x0_LOCAL = funding1.channel_update(
        side=Side.local,
        short_channel_id="103x1x0",
        disable=False,
        cltv_expiry_delta=144,
        htlc_minimum_msat=0,
        fee_base_msat=1000,
        fee_proportional_millionths=10,
        timestamp=timestamp_103x1x0_LOCAL,
        htlc_maximum_msat=None,
    )
    update_109x1x0_LOCAL = funding2.channel_update(
        side=Side.local,
        short_channel_id="109x1x0",
        disable=False,
        cltv_expiry_delta=144,
        htlc_minimum_msat=0,
        fee_base_msat=1000,
        fee_proportional_millionths=10,
        timestamp=timestamp_109x1x0_LOCAL,
        htlc_maximum_msat=None,
    )
    update_109x1x0_REMOTE = funding2.channel_update(
        side=Side.remote,
        short_channel_id="109x1x0",
        disable=False,
        cltv_expiry_delta=144,
        htlc_minimum_msat=0,
        fee_base_msat=1000,
        fee_proportional_millionths=10,
        timestamp=timestamp_109x1x0_REMOTE,
        htlc_maximum_msat=None,
    )

    csums_103x1x0 = update_checksums(*funding1.node_id_sort(update_103x1x0_LOCAL, None))
    csums_109x1x0 = update_checksums(
        *funding2.node_id_sort(update_109x1x0_LOCAL, update_109x1x0_REMOTE)
    )

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        # Channel 103x1x0 (between 002 and 003)
        Block(blockheight=103, number=6, txs=[funding1_tx]),
        # Channel 109x1x0 (between 004 and 005)
        Block(blockheight=109, number=6, txs=[funding2_tx]),
        Connect(connprivkey="03"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=""),
        RawMsg(funding1.channel_announcement("103x1x0", "")),
        RawMsg(update_103x1x0_LOCAL),
        RawMsg(funding2.channel_announcement("109x1x0", "")),
        RawMsg(update_109x1x0_LOCAL),
        RawMsg(update_109x1x0_REMOTE),
        # c-lightning gets a race condition if we dont wait for
        # these updates to be added to the gossip store
        # FIXME: convert to explicit signal
        Wait(1),
        # New peer connects, with gossip_query option.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        # BOLT #9:
        # | 6/7   | `gossip_queries`                 | More sophisticated gossip control
        Msg("init", globalfeatures="", features=bitfield(7)),
        TryAll(
            # No queries?  Must not get anything.
            [
                MustNotMsg("channel_announcement"),
                MustNotMsg("channel_update"),
                MustNotMsg("node_announcement"),
            ],
            # This should elicit an empty response
            [
                Msg(
                    "query_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=0,
                    number_of_blocks=103,
                ),
                ExpectMsg(
                    "reply_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=0,
                    number_of_blocks=103,
                ),
                CheckEq(decode_scids, ""),
            ],
            # This should get the first one, not the second.
            [
                Msg(
                    "query_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=103,
                    number_of_blocks=1,
                ),
                ExpectMsg(
                    "reply_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=103,
                    number_of_blocks=1,
                ),
                CheckEq(decode_scids, "103x1x0"),
            ],
            # This should get the second one, not the first.
            [
                Msg(
                    "query_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=109,
                    number_of_blocks=4294967295,
                ),
                OneOf(
                    ExpectMsg(
                        "reply_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=109,
                        number_of_blocks=4294967186,
                    ),
                    # Could truncate number_of_blocks.
                    ExpectMsg(
                        "reply_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=109,
                        number_of_blocks=1,
                    ),
                ),
                CheckEq(decode_scids, "109x1x0"),
            ],
            # This should get both.
            [
                Msg(
                    "query_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=103,
                    number_of_blocks=7,
                ),
                ExpectMsg(
                    "reply_channel_range",
                    chain_hash=regtest_hash,
                    first_blocknum=103,
                    number_of_blocks=7,
                ),
                CheckEq(decode_scids, "103x1x0,109x1x0"),
            ],
            # This should get appended timestamp fields with option_gossip_queries_ex
            Sequence(
                enable=runner.has_option("option_gossip_queries_ex") is not None,
                events=[
                    Msg(
                        "query_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                        tlvs="{query_option={query_option_flags=1}}",
                    ),
                    ExpectMsg(
                        "reply_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                    ),
                    CheckEq(decode_timestamps, ts_103x1x0 + ts_109x1x0),
                    CheckEq(decode_scids, "103x1x0,109x1x0"),
                ],
            ),
            # This should get appended checksum fields with option_gossip_queries_ex
            Sequence(
                enable=runner.has_option("option_gossip_queries_ex") is not None,
                events=[
                    Msg(
                        "query_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                        tlvs="{query_option={query_option_flags=2}}",
                    ),
                    ExpectMsg(
                        "reply_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                        tlvs="{checksums_tlv={checksums=["
                        + csums_103x1x0
                        + ","
                        + csums_109x1x0
                        + "]}}",
                    ),
                    CheckEq(decode_scids, "103x1x0,109x1x0"),
                ],
            ),
            # This should append timestamps and checksums with option_gossip_queries_ex
            Sequence(
                enable=runner.has_option("option_gossip_queries_ex") is not None,
                events=[
                    Msg(
                        "query_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                        tlvs="{query_option={query_option_flags=3}}",
                    ),
                    ExpectMsg(
                        "reply_channel_range",
                        chain_hash=regtest_hash,
                        first_blocknum=103,
                        number_of_blocks=7,
                        tlvs="{checksums_tlv={checksums=["
                        + csums_103x1x0
                        + ","
                        + csums_109x1x0
                        + "]}}",
                    ),
                    CheckEq(decode_timestamps, ts_103x1x0 + ts_109x1x0),
                    CheckEq(decode_scids, "103x1x0,109x1x0"),
                ],
            ),
        ),
    ]

    runner.run(test)
