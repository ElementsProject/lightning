"""
Spec helper is a collection of functions to help to speed up the
operation of interoperability testing.

It contains a method to generate the correct sequence of channel opening
and, and it feels a dictionary with all the propriety that needs to
be used after this sequence of steps.

author: https://github.com/vincenzopalazzo
"""
from typing import List, Union

from lnprototest import (
    TryAll,
    Connect,
    Block,
    ExpectMsg,
    Msg,
    Runner,
    regtest_hash,
    remote_funding_pubkey,
    remote_revocation_basepoint,
    remote_payment_basepoint,
    remote_delayed_payment_basepoint,
    remote_htlc_basepoint,
    remote_per_commitment_point,
    remote_funding_privkey,
    Commit,
    Side,
    msat,
    CreateFunding,
)
from helpers import (
    utxo,
    pubkey_of,
    gen_random_keyset,
    funding_amount_for_utxo,
)
from lnprototest.stash import (
    rcvd,
    funding,
    sent,
    commitsig_to_recv,
    channel_id,
    commitsig_to_send,
    funding_txid,
    funding_tx,
)


def connect_to_node_helper(
    runner: Runner,
    tx_spendable: str,
    conn_privkey: str = "02",
    global_features="",
    features: str = "",
) -> List[Union[Block, Connect, ExpectMsg, TryAll]]:
    """Helper function to make a connection with the node"""
    return [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey=conn_privkey),
        ExpectMsg("init"),
        Msg("init", globalfeatures=global_features, features=features),
    ]


def open_and_announce_channel_helper(
    runner: Runner, conn_privkey: str = "02", opts: dict = {}
) -> List[Union[Block, Connect, ExpectMsg, TryAll]]:
    # Make up a channel between nodes 02 and 03, using bitcoin privkeys 10 and 20
    local_keyset = gen_random_keyset()
    local_funding_privkey = "20"

    return [
        Msg(
            "open_channel",
            chain_hash=regtest_hash,
            temporary_channel_id="00" * 32,
            funding_satoshis=funding_amount_for_utxo(0),
            push_msat=0,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            channel_reserve_satoshis=9998,
            htlc_minimum_msat=0,
            feerate_per_kw=253,
            # clightning uses to_self_delay=6; we use 5 to test differentiation
            to_self_delay=5,
            max_accepted_htlcs=483,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        ExpectMsg(
            "accept_channel",
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            minimum_depth=3,
            channel_reserve_satoshis=9998,
        ),
        # Create and stash Funding object and FundingTx
        CreateFunding(
            *utxo(0),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey()
        ),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("to_self_delay", int),
            remote_to_self_delay=sent("to_self_delay", int),
            local_amount=msat(sent("funding_satoshis", int)),
            remote_amount=0,
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        Msg(
            "funding_created",
            temporary_channel_id=rcvd(),
            funding_txid=funding_txid(),
            funding_output_index=0,
            signature=commitsig_to_send(),
        ),
        ExpectMsg(
            "funding_signed", channel_id=channel_id(), signature=commitsig_to_recv()
        ),
        # Mine it and get it deep enough to confirm channel.
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id(),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
        Msg(
            "funding_locked",
            channel_id=channel_id(),
            next_per_commitment_point=local_keyset.per_commit_point(1),
        ),
    ]
