#! /usr/bin/env python3
# Tests for gossip_timestamp_filter
from lnprototest import (
    Connect,
    Block,
    ExpectMsg,
    Msg,
    RawMsg,
    Side,
    MustNotMsg,
    Disconnect,
    AnyOrder,
    Runner,
    Funding,
    bitfield,
)
import unittest
import time
from helpers import utxo, tx_spendable


def test_gossip_timestamp_filter(runner: Runner) -> None:
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

    timestamp1 = int(time.time())
    timestamp2 = timestamp1 + 1

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="03"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=""),
        # txid 189c40b0728f382fe91c87270926584e48e0af3a6789f37454afee6c7560311d
        Block(blockheight=103, number=6, txs=[funding1_tx]),
        RawMsg(funding1.channel_announcement("103x1x0", "")),
        RawMsg(
            funding1.node_announcement(
                Side.local, "", (1, 2, 3), "foobar", b"", timestamp1
            )
        ),
        # New peer connects, asks for gossip_timestamp_filter=all. We *won't* relay channel_announcement,
        # as there is no channel_update.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        # BOLT #9:
        # | 6/7   | `gossip_queries`                 | More sophisticated gossip control
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=0,
            timestamp_range=4294967295,
        ),
        MustNotMsg("channel_announcement"),
        MustNotMsg("channel_update"),
        MustNotMsg("node_announcement"),
        Disconnect(),
        # Now, with channel update
        RawMsg(
            funding1.channel_update(
                side=Side.local,
                short_channel_id="103x1x0",
                disable=False,
                cltv_expiry_delta=144,
                htlc_minimum_msat=0,
                fee_base_msat=1000,
                fee_proportional_millionths=10,
                timestamp=timestamp1,
                htlc_maximum_msat=None,
            ),
            connprivkey="03",
        ),
        # New peer connects, asks for gossip_timestamp_filter=all.  update and node announcement will be relayed.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=0,
            timestamp_range=4294967295,
        ),
        ExpectMsg("channel_announcement", short_channel_id="103x1x0"),
        AnyOrder(
            ExpectMsg("channel_update", short_channel_id="103x1x0"),
            ExpectMsg("node_announcement"),
        ),
        Disconnect(),
        # BOLT #7:
        # The receiver:
        #  - SHOULD send all gossip messages whose `timestamp` is greater or
        #    equal to `first_timestamp`, and less than `first_timestamp` plus
        #    `timestamp_range`.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=1000,
            timestamp_range=timestamp1 - 1000,
        ),
        MustNotMsg("channel_announcement"),
        MustNotMsg("channel_update"),
        MustNotMsg("node_announcement"),
        Disconnect(),
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=timestamp1 + 1,
            timestamp_range=4294967295,
        ),
        MustNotMsg("channel_announcement"),
        MustNotMsg("channel_update"),
        MustNotMsg("node_announcement"),
        Disconnect(),
        # These two succeed in getting the gossip, then stay connected for next test.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=timestamp1,
            timestamp_range=4294967295,
        ),
        ExpectMsg("channel_announcement", short_channel_id="103x1x0"),
        AnyOrder(
            ExpectMsg("channel_update", short_channel_id="103x1x0"),
            ExpectMsg("node_announcement"),
        ),
        Connect(connprivkey="06"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(6)),
        Msg(
            "gossip_timestamp_filter",
            chain_hash="06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f",
            first_timestamp=1000,
            timestamp_range=timestamp1 - 1000 + 1,
        ),
        ExpectMsg("channel_announcement", short_channel_id="103x1x0"),
        AnyOrder(
            ExpectMsg("channel_update", short_channel_id="103x1x0"),
            ExpectMsg("node_announcement"),
        ),
        # BOLT #7:
        #  - SHOULD restrict future gossip messages to those whose `timestamp`
        #    is greater or equal to `first_timestamp`, and less than
        #    `first_timestamp` plus `timestamp_range`.
        Block(blockheight=109, number=6, txs=[funding2_tx]),
        RawMsg(funding2.channel_announcement("109x1x0", ""), connprivkey="03"),
        RawMsg(
            funding2.channel_update(
                side=Side.local,
                short_channel_id="109x1x0",
                disable=False,
                cltv_expiry_delta=144,
                htlc_minimum_msat=0,
                fee_base_msat=1000,
                fee_proportional_millionths=10,
                timestamp=timestamp2,
                htlc_maximum_msat=None,
            )
        ),
        RawMsg(
            funding2.channel_update(
                side=Side.remote,
                short_channel_id="109x1x0",
                disable=False,
                cltv_expiry_delta=144,
                htlc_minimum_msat=0,
                fee_base_msat=1000,
                fee_proportional_millionths=10,
                timestamp=timestamp2,
                htlc_maximum_msat=None,
            )
        ),
        RawMsg(
            funding2.node_announcement(
                Side.local, "", (1, 2, 3), "foobar2", b"", timestamp2
            )
        ),
        # 005's filter covers this, 006's doesn't.
        ExpectMsg("channel_announcement", short_channel_id="109x1x0", connprivkey="05"),
        AnyOrder(
            ExpectMsg("channel_update", short_channel_id="109x1x0", channel_flags=0),
            ExpectMsg("channel_update", short_channel_id="109x1x0", channel_flags=1),
            ExpectMsg("node_announcement"),
        ),
        MustNotMsg("channel_announcement", connprivkey="06"),
        MustNotMsg("channel_update"),
        MustNotMsg("node_announcement"),
    ]

    runner.run(test)
