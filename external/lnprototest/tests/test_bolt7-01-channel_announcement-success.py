#! /usr/bin/env python3
# Simple gossip tests.

from lnprototest import (
    Connect,
    Block,
    ExpectMsg,
    Msg,
    RawMsg,
    Funding,
    Side,
    MustNotMsg,
    Disconnect,
    Runner,
)
from helpers import tx_spendable, utxo
import time


def test_gossip(runner: Runner) -> None:
    # Make up a channel between nodes 02 and 03, using bitcoin privkeys 10 and 20
    funding, funding_tx = Funding.from_utxo(
        *utxo(0),
        local_node_privkey="02",
        local_funding_privkey="10",
        remote_node_privkey="03",
        remote_funding_privkey="20"
    )

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="03"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=""),
        Block(blockheight=103, number=6, txs=[funding_tx]),
        RawMsg(funding.channel_announcement("103x1x0", "")),
        # New peer connects, asking for initial_routing_sync.  We *won't* relay channel_announcement, as there is no
        # channel_update.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features="08"),
        MustNotMsg("channel_announcement"),
        Disconnect(),
        RawMsg(
            funding.channel_update(
                "103x1x0",
                Side.local,
                disable=False,
                cltv_expiry_delta=144,
                htlc_minimum_msat=0,
                fee_base_msat=1000,
                fee_proportional_millionths=10,
                timestamp=int(time.time()),
                htlc_maximum_msat=None,
            ),
            connprivkey="03",
        ),
        # Now we'll relay to a new peer.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features="08"),
        ExpectMsg("channel_announcement", short_channel_id="103x1x0"),
        ExpectMsg(
            "channel_update",
            short_channel_id="103x1x0",
            message_flags=0,
            channel_flags=0,
        ),
        Disconnect(),
        # BOLT #7:
        # A node:
        #   - SHOULD monitor the funding transactions in the blockchain, to
        #   identify channels that are being closed.
        #  - if the funding output of a channel is being spent:
        #    - SHOULD be removed from the local network view AND be
        #      considered closed.
        Block(blockheight=109, txs=[funding.close_tx(200, "99")]),
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features="08"),
        MustNotMsg("channel_announcement"),
        MustNotMsg("channel_update"),
    ]

    runner.run(test)
