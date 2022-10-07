#! /usr/bin/env python3
# Tests for malformed/bad channel_announcement

from lnprototest import (
    Connect,
    Block,
    ExpectMsg,
    Msg,
    RawMsg,
    ExpectError,
    Funding,
    Side,
    MustNotMsg,
    Runner,
    TryAll,
    Sig,
)
import time
from typing import cast
from helpers import utxo, tx_spendable


# FIXME: Make this work in-place!
def corrupt_sig(sig: Sig) -> Sig:
    hashval = bytearray(cast(bytes, sig.hashval))
    hashval[-1] ^= 1
    return Sig(sig.privkey.secret.hex(), hashval.hex())


def test_premature_channel_announcement(runner: Runner) -> None:
    # It's allowed (even encouraged!) to cache premature
    # channel_announcements, so we separate this from the other tests.

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
        # txid 189c40b0728f382fe91c87270926584e48e0af3a6789f37454afee6c7560311d
        Block(blockheight=103, txs=[funding_tx]),
        TryAll(
            # Invalid `channel_announcement`: short_channel_id too young.
            [RawMsg(funding.channel_announcement("103x1x0", ""))],
            # Invalid `channel_announcement`: short_channel_id *still* too young.
            [
                Block(blockheight=104, number=4),
                RawMsg(funding.channel_announcement("103x1x0", "")),
            ],
        ),
        # Needs a channel_update if it were to relay.
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
            )
        ),
        # New peer connects, asking for initial_routing_sync.  We *won't* relay channel_announcement.
        Connect(connprivkey="05"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features="08"),
        MustNotMsg("channel_announcement"),
        MustNotMsg("channel_update"),
    ]

    runner.run(test)


def test_bad_announcement(runner: Runner) -> None:
    funding, funding_tx = Funding.from_utxo(
        *utxo(0),
        local_node_privkey="02",
        local_funding_privkey="10",
        remote_node_privkey="03",
        remote_funding_privkey="20"
    )

    # ### Ignored:
    ann_bad_chainhash = funding.channel_announcement("103x1x0", "")
    ann_bad_chainhash.fields["chain_hash"] = bytes.fromhex(
        "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000"
    )

    ann_bad_scid_dne = funding.channel_announcement("103x2x0", "")

    ann_bad_scid_out_dne = funding.channel_announcement("103x1x1", "")

    ann_bad_bitcoin_key1 = Funding(
        funding.txid,
        funding.output_index,
        funding.amount,
        local_node_privkey="02",
        local_funding_privkey="10",
        remote_node_privkey="03",
        remote_funding_privkey="21",
    ).channel_announcement("103x1x0", "")

    ann_bad_bitcoin_key2 = Funding(
        funding.txid,
        funding.output_index,
        funding.amount,
        local_node_privkey="02",
        local_funding_privkey="11",
        remote_node_privkey="03",
        remote_funding_privkey="20",
    ).channel_announcement("103x1x0", "")

    # ### These should cause an error
    ann_bad_nodesig1 = funding.channel_announcement("103x1x0", "")
    ann_bad_nodesig1.fields["node_signature_1"] = corrupt_sig(
        ann_bad_nodesig1.fields["node_signature_1"]
    )

    ann_bad_nodesig2 = funding.channel_announcement("103x1x0", "")
    ann_bad_nodesig2.fields["node_signature_2"] = corrupt_sig(
        ann_bad_nodesig2.fields["node_signature_2"]
    )

    ann_bad_bitcoinsig1 = funding.channel_announcement("103x1x0", "")
    ann_bad_bitcoinsig1.fields["bitcoin_signature_1"] = corrupt_sig(
        ann_bad_bitcoinsig1.fields["bitcoin_signature_1"]
    )

    ann_bad_bitcoinsig2 = funding.channel_announcement("103x1x0", "")
    ann_bad_bitcoinsig2.fields["bitcoin_signature_2"] = corrupt_sig(
        ann_bad_bitcoinsig2.fields["bitcoin_signature_2"]
    )

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="03"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=""),
        # txid 189c40b0728f382fe91c87270926584e48e0af3a6789f37454afee6c7560311d
        Block(blockheight=103, number=6, txs=[funding_tx]),
        TryAll(
            # These are all ignored
            # BOLT #7:
            #   - if the specified `chain_hash` is unknown to the receiver:
            #    - MUST ignore the message.
            [
                TryAll(
                    [RawMsg(ann_bad_chainhash)],
                    # BOLT #7:
                    #   - if the `short_channel_id`'s output does NOT correspond to a P2WSH (using
                    #    `bitcoin_key_1` and `bitcoin_key_2`, as specified in
                    #    [BOLT #3](03-transactions.md#funding-transaction-output)) OR the output is
                    #    spent:
                    #    - MUST ignore the message.
                    [
                        RawMsg(ann_bad_scid_dne),
                        # Needs a channel_update if it were to relay.
                        RawMsg(
                            funding.channel_update(
                                "103x2x0",
                                Side.local,
                                disable=False,
                                cltv_expiry_delta=144,
                                htlc_minimum_msat=0,
                                fee_base_msat=1000,
                                fee_proportional_millionths=10,
                                timestamp=int(time.time()),
                                htlc_maximum_msat=None,
                            )
                        ),
                    ],
                    [
                        RawMsg(ann_bad_scid_out_dne),
                        # Needs a channel_update if it were to relay.
                        RawMsg(
                            funding.channel_update(
                                "103x1x1",
                                Side.local,
                                disable=False,
                                cltv_expiry_delta=144,
                                htlc_minimum_msat=0,
                                fee_base_msat=1000,
                                fee_proportional_millionths=10,
                                timestamp=int(time.time()),
                                htlc_maximum_msat=None,
                            )
                        ),
                    ],
                    [RawMsg(ann_bad_bitcoin_key1)],
                    [RawMsg(ann_bad_bitcoin_key2)],
                ),
                # Needs a channel_update if it were to relay.
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
                    )
                ),
                # New peer connects, asking for initial_routing_sync.  We *won't* relay channel_announcement.
                Connect(connprivkey="05"),
                ExpectMsg("init"),
                Msg("init", globalfeatures="", features="08"),
                MustNotMsg("channel_announcement"),
                MustNotMsg("channel_update"),
            ],
            # BOLT #7:
            #   - otherwise:
            #    - if `bitcoin_signature_1`, `bitcoin_signature_2`, `node_signature_1` OR
            #    `node_signature_2` are invalid OR NOT correct:
            #      - SHOULD fail the connection.
            [
                TryAll(
                    [RawMsg(ann_bad_nodesig1)],
                    [RawMsg(ann_bad_nodesig2)],
                    [RawMsg(ann_bad_bitcoinsig1)],
                    [RawMsg(ann_bad_bitcoinsig2)],
                ),
                ExpectError(),
            ],
        ),
    ]

    runner.run(test)
