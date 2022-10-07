#! /usr/bin/env python3
# Variations on adding an HTLC.

from lnprototest import (
    TryAll,
    Sequence,
    Connect,
    Block,
    ExpectMsg,
    Msg,
    RawMsg,
    KeySet,
    CreateFunding,
    Commit,
    Runner,
    Disconnect,
    remote_funding_pubkey,
    remote_revocation_basepoint,
    remote_payment_basepoint,
    remote_htlc_basepoint,
    remote_per_commitment_point,
    remote_delayed_payment_basepoint,
    Side,
    CheckEq,
    msat,
    remote_funding_privkey,
    regtest_hash,
    bitfield,
    negotiated,
)
from lnprototest.stash import (
    sent,
    rcvd,
    commitsig_to_send,
    commitsig_to_recv,
    channel_id,
    funding_txid,
    funding_tx,
    funding,
)
from helpers import utxo, tx_spendable, funding_amount_for_utxo, pubkey_of

# FIXME: bolt9.featurebits?
# BOLT #9:
# | 12/13 | `option_static_remotekey`        | Static key for remote output
static_remotekey = 13

# BOLT #9:
# | 0/1   | `option_data_loss_protect`       | Requires or supports extra `channel_reestablish` fields
data_loss_protect = 1

# BOLT-a12da24dd0102c170365124782b46d9710950ac1 #9:
# | 20/21 | `option_anchor_outputs`          | Anchor outputs
anchor_outputs = 21


def test_reestablish(runner: Runner) -> None:
    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        TryAll(
            Msg("init", globalfeatures="", features=bitfield(data_loss_protect)),
            Msg("init", globalfeatures="", features=bitfield(static_remotekey)),
            Msg(
                "init",
                globalfeatures="",
                features=bitfield(static_remotekey, anchor_outputs),
            ),
            # And nothing.
            Msg("init", globalfeatures="", features=""),
        ),
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
        Disconnect(),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # Reconnect with same features.
        Msg("init", globalfeatures="", features=sent("init.features")),
        # BOLT #2:
        #  - if `next_revocation_number` equals 0:
        #      - MUST set `your_last_per_commitment_secret` to all zeroes
        #    - otherwise:
        #      - MUST set `your_last_per_commitment_secret` to the last
        #        `per_commitment_secret` it received
        ExpectMsg(
            "channel_reestablish",
            channel_id=channel_id(),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
        ),
        # BOLT #2:
        # The sending node:...
        # - if `option_static_remotekey` applies to the commitment
        #   transaction:
        #     - MUST set `my_current_per_commitment_point` to a valid point.
        # - otherwise:
        #   - MUST set `my_current_per_commitment_point` to its commitment
        #     point for the last signed commitment it received from its
        #     channel peer (i.e. the commitment_point corresponding to the
        #     commitment transaction the sender would use to unilaterally
        #     close).
        Sequence(
            CheckEq(
                rcvd("my_current_per_commitment_point"), remote_per_commitment_point(0)
            ),
            enable=negotiated(
                sent("init.features"),
                rcvd("init.features"),
                excluded=[static_remotekey],
            ),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "channel_reestablish",
            channel_id=channel_id(),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
            my_current_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # FIXME: Check that they error and unilateral close if we give
        # the wrong info!
    ]

    runner.run(test)
