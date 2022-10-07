#!/usr/bin/env python3
# Variations on open_channel

from hashlib import sha256

from pyln.proto.message import Message
from lnprototest import (
    TryAll,
    Connect,
    Block,
    FundChannel,
    InitRbf,
    ExpectMsg,
    Msg,
    RawMsg,
    KeySet,
    CreateFunding,
    Commit,
    Runner,
    remote_funding_pubkey,
    remote_revocation_basepoint,
    remote_payment_basepoint,
    remote_htlc_basepoint,
    remote_per_commitment_point,
    remote_delayed_payment_basepoint,
    Side,
    msat,
    remote_funding_privkey,
    regtest_hash,
    bitfield,
    Event,
    DualFundAccept,
    OneOf,
    CreateDualFunding,
    EventError,
    Funding,
    privkey_expand,
    AddInput,
    AddOutput,
    FinalizeFunding,
    AddWitnesses,
    dual_fund_csv,
    ExpectError,
    Disconnect,
)
from lnprototest.stash import (
    sent,
    rcvd,
    commitsig_to_send,
    commitsig_to_recv,
    funding_txid,
    funding_tx,
    funding,
    locking_script,
    get_member,
    witnesses,
)
from helpers import (
    utxo,
    tx_spendable,
    funding_amount_for_utxo,
    pubkey_of,
    tx_out_for_index,
    privkey_for_index,
    utxo_amount,
    run_runner,
)
from typing import Any, Callable, List


def channel_id_v2(local_keyset: KeySet) -> Callable[[Runner, Event, str], str]:
    def _channel_id_v2(runner: Runner, event: Event, field: str) -> str:

        # BOLT-0eebb43e32a513f3b4dd9ced72ad1e915aefdd25 #2:
        #
        # For channels established using the v2 protocol, the `channel_id` is the
        # SHA256(lesser-revocation-basepoint || greater-revocation-basepoint),
        # where the lesser and greater is based off the order of the
        # basepoint. The basepoints are compact DER-encoded public keys.
        remote_key = runner.get_keyset().raw_revocation_basepoint()
        local_key = local_keyset.raw_revocation_basepoint()
        if remote_key.format() < local_key.format():
            return sha256(remote_key.format() + local_key.format()).digest().hex()
        else:
            return sha256(local_key.format() + remote_key.format()).digest().hex()

    return _channel_id_v2


def channel_id_tmp(
    local_keyset: KeySet, opener: Side
) -> Callable[[Runner, Event, str], str]:
    def _channel_id_tmp(runner: Runner, event: Event, field: str) -> str:
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #2:
        #
        # If the peer's revocation basepoint is unknown (e.g. `open_channel2`),
        # a temporary `channel_id` should be found by using a zeroed out
        # basepoint for the unknown peer.
        if opener == Side.local:
            key = local_keyset.raw_revocation_basepoint()
        else:
            key = runner.get_keyset().raw_revocation_basepoint()

        return sha256(bytes.fromhex("00" * 33) + key.format()).digest().hex()

    return _channel_id_tmp


def odd_serial(event: Event, msg: Message, runner: "Runner") -> None:
    """
    Test that a message's serial_id is odd.
    Note that the dummy runner will fail this test, so we skip for them
    """
    if msg.fields["serial_id"] % 2 == 0:
        if runner._is_dummy():
            return
        raise EventError(
            event,
            "Received **even** serial {}, expected odd".format(msg.fields["serial_id"]),
        )


def even_serial(event: Event, msg: Message, runner: "Runner") -> None:
    if msg.fields["serial_id"] % 2 == 1:
        raise EventError(
            event,
            "Received **odd** serial {}, expected event".format(
                msg.fields["serial_id"]
            ),
        )


def agreed_funding(
    opener: Side, is_rbf: bool = False
) -> Callable[[Runner, Event, str], int]:
    def _agreed_funding(runner: Runner, event: Event, field: str) -> int:
        opener_msg = "init_rbf" if is_rbf else "open_channel2"
        accept_msg = "ack_rbf" if is_rbf else "accept_channel2"

        open_funding = get_member(
            event,
            runner,
            "Msg" if opener == Side.local else "ExpectMsg",
            opener_msg + ".funding_satoshis",
        )
        accept_funding = get_member(
            event,
            runner,
            "ExpectMsg" if opener == Side.local else "Msg",
            accept_msg + ".funding_satoshis",
        )

        return int(open_funding) + int(accept_funding)

    return _agreed_funding


def funding_lockscript(our_privkey: str) -> Callable[[Runner, Event, str], str]:
    def _funding_lockscript(runner: Runner, event: Event, field: str) -> str:
        remote_pubkey = Funding.funding_pubkey_key(
            privkey_expand(runner.get_node_bitcoinkey())
        )
        local_pubkey = Funding.funding_pubkey_key(privkey_expand(our_privkey))
        return Funding.locking_script_keys(remote_pubkey, local_pubkey).hex()

    return _funding_lockscript


def change_amount(
    opener: Side, change_for_opener: bool, script: str, input_amt: int
) -> Callable[[Runner, Event, str], int]:
    # We assume that change is input minus fees
    def _change_amount(runner: Runner, event: Event, field: str) -> int:
        if change_for_opener:
            opening_amt = get_member(
                event,
                runner,
                "Msg" if opener == Side.local else "ExpectMsg",
                "open_channel2.funding_satoshis",
            )
        else:
            opening_amt = get_member(
                event,
                runner,
                "ExpectMsg" if opener == Side.local else "Msg",
                "accept_channel2.funding_satoshis",
            )

        feerate = get_member(
            event,
            runner,
            "Msg" if opener == Side.local else "ExpectMsg",
            "open_channel2.funding_feerate_perkw",
        )

        # assume 1 input, with no redeemscript
        weight = (32 + 4 + 4 + 1 + 0) * 4
        # assume 1 output, with script of varlen of 1
        weight += (8 + max(len(script), 110) // 2 + 1) * 4
        # opener has to pay for 'common' fields plus the funding output
        if change_for_opener:
            weight += 1 + 1 + (4 + 1 + 1 + 4) * 4
            # p2wsh script is 34 bytes, all told
            weight += (8 + 34 + 1) * 4

        fee = (weight * int(feerate)) // 1000
        change = input_amt - int(opening_amt) - fee

        return change

    return _change_amount


def test_open_accepter_no_inputs(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    input_index = 0

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount_for_utxo(input_index),
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=0,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            funding_satoshis=0,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Create and stash Funding object and FundingTx
        CreateFunding(
            *utxo(input_index),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey()
        ),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("accept_channel2.to_self_delay", int),
            remote_to_self_delay=sent("open_channel2.to_self_delay", int),
            local_amount=msat(sent("open_channel2.funding_satoshis", int)),
            remote_amount=0,
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Try removing and re-adding an input
        TryAll(
            [],
            [
                Msg(
                    "tx_remove_input",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg(
                    "tx_add_input",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                    prevtx=tx_spendable,
                    prevtx_vout=tx_out_for_index(input_index),
                    sequence=0xFFFFFFFD,
                    script_sig="",
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            sats=funding_amount_for_utxo(input_index),
            script=locking_script(),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Try removing and re-adding an output
        TryAll(
            [],
            [
                Msg(
                    "tx_remove_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg(
                    "tx_add_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                    sats=funding_amount_for_utxo(input_index),
                    script=locking_script(),
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        FinalizeFunding(funding=funding()),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        ExpectMsg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        # Mine the block!
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        Msg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point="027eed8389cf8eb715d73111b73d94d2c2d04bf96dc43dfd5b0970d80b3617009d",
        ),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point="032405cbd0f41225d5f203fe4adac8401321a9e05767c5f8af97d51d2e81fbb206",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    runner.run(test)


def test_open_accepter_with_inputs(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 5+6 are special, only the test runner can spend them
    input_index = 5

    # Since technically these can be sent in any order,
    # we must specify this as ok!
    expected_add_input = ExpectMsg(
        "tx_add_input",
        channel_id=channel_id_v2(local_keyset),
        sequence=0xFFFFFFFD,
        script_sig="",
        if_match=odd_serial,
    )

    expected_add_output = ExpectMsg(
        "tx_add_output", channel_id=channel_id_v2(local_keyset), if_match=odd_serial
    )

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        DualFundAccept(),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount_for_utxo(input_index),
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=100,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("open_channel2.channel_id"),
            funding_satoshis=funding_amount_for_utxo(input_index),
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Create and stash Funding object and FundingTx
        CreateDualFunding(
            fee=200,
            funding_sats=agreed_funding(Side.local),
            locktime=sent("open_channel2.locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=0,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        OneOf(
            [
                expected_add_input,
                Msg(
                    "tx_add_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=0,
                    sats=agreed_funding(Side.local),
                    script=funding_lockscript(local_funding_privkey),
                ),
                expected_add_output,
            ],
            [
                expected_add_output,
                Msg(
                    "tx_add_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                    sats=agreed_funding(Side.local),
                    script=funding_lockscript(local_funding_privkey),
                ),
                expected_add_input,
            ],
        ),
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            sats=sent("tx_add_output.sats", int),
            script=sent("tx_add_output.script"),
        ),
        FinalizeFunding(funding=funding()),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("accept_channel2.to_self_delay", int),
            remote_to_self_delay=sent("open_channel2.to_self_delay", int),
            local_amount=msat(sent("open_channel2.funding_satoshis", int)),
            remote_amount=msat(rcvd("accept_channel2.funding_satoshis", int)),
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        AddWitnesses(funding=funding(), witness_stack=rcvd("witness_stack")),
        # Mine the block + lock-in
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        Msg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=local_keyset.per_commit_point(1),
        ),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    runner.run(test)


def test_open_opener_no_input(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

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
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=999877),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=999877,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("open_channel2.channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=0,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Create and stash Funding object and FundingTx
        CreateDualFunding(
            fee=200,
            funding_sats=agreed_funding(Side.remote),
            locktime=rcvd("open_channel2.locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            sats=agreed_funding(Side.remote),
            if_match=even_serial,
        ),
        # FIXME: They may send us the funding output second,
        # if there's also a change output
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Their change if they have one!
        OneOf(
            [
                ExpectMsg(
                    "tx_add_output",
                    if_match=even_serial,
                    channel_id=channel_id_v2(local_keyset),
                ),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                AddOutput(
                    funding=funding(),
                    serial_id=rcvd("tx_add_output.serial_id", int),
                    sats=rcvd("tx_add_output.sats", int),
                    script=rcvd("tx_add_output.script"),
                ),
            ],
            [ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset))],
        ),
        FinalizeFunding(funding=funding()),
        Commit(
            funding=funding(),
            opener=Side.remote,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("open_channel2.to_self_delay", int),
            remote_to_self_delay=sent("accept_channel2.to_self_delay", int),
            local_amount=msat(sent("accept_channel2.funding_satoshis", int)),
            remote_amount=msat(rcvd("open_channel2.funding_satoshis", int)),
            local_dust_limit=550,
            remote_dust_limit=546,
            feerate=rcvd("open_channel2.commitment_feerate_perkw", int),
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        AddWitnesses(funding=funding(), witness_stack=rcvd("witness_stack")),
        TryAll(
            [
                Msg(
                    "shutdown",
                    channel_id=channel_id_v2(local_keyset),
                    scriptpubkey="001473daa75958d5b2ddca87a6c279bb7cb307167037",
                ),
                # Ignore unknown odd messages
                TryAll([], RawMsg(bytes.fromhex("270F"))),
                ExpectMsg("shutdown", channel_id=channel_id_v2(local_keyset)),
            ],
            [
                Block(blockheight=103, number=3, txs=[funding_tx()]),
                ExpectMsg(
                    "funding_locked",
                    channel_id=channel_id_v2(local_keyset),
                    next_per_commitment_point=remote_per_commitment_point(1),
                ),
                # Ignore unknown odd messages
                TryAll([], RawMsg(bytes.fromhex("270F"))),
            ],
        ),
    ]

    runner.run(test)


def test_open_opener_with_inputs(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 5 is special, only the test runner can spend it
    ii = 5
    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=999877),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=999877,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("open_channel2.channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=400000,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Create and stash Funding object and FundingTx
        CreateDualFunding(
            fee=200,
            funding_sats=agreed_funding(Side.remote),
            locktime=rcvd("open_channel2.locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=1,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(ii),
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(ii),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            sats=agreed_funding(Side.remote),
            if_match=even_serial,
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=101,
            sats=change_amount(
                Side.remote,
                False,
                "001473daa75958d5b2ddca87a6c279bb7cb307167037",
                funding_amount_for_utxo(ii),
            ),
            script="001473daa75958d5b2ddca87a6c279bb7cb307167037",
        ),
        # FIXME: They may send us the funding output second,
        # if there's also a change output
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Their change if they have one!
        OneOf(
            [
                ExpectMsg(
                    "tx_add_output",
                    if_match=even_serial,
                    channel_id=channel_id_v2(local_keyset),
                ),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                AddOutput(
                    funding=funding(),
                    serial_id=rcvd("tx_add_output.serial_id", int),
                    sats=rcvd("tx_add_output.sats", int),
                    script=rcvd("tx_add_output.script"),
                ),
            ],
            [
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        FinalizeFunding(funding=funding()),
        Commit(
            funding=funding(),
            opener=Side.remote,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("open_channel2.to_self_delay", int),
            remote_to_self_delay=sent("accept_channel2.to_self_delay", int),
            local_amount=msat(sent("accept_channel2.funding_satoshis", int)),
            remote_amount=msat(rcvd("open_channel2.funding_satoshis", int)),
            local_dust_limit=550,
            remote_dust_limit=546,
            feerate=rcvd("open_channel2.commitment_feerate_perkw", int),
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        AddWitnesses(funding=funding(), witness_stack=rcvd("witness_stack")),
        # Mine the block!
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    run_runner(runner, test)


def test_df_accepter_opener_underpays_fees(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 6 is special, it's a 1of5 multisig script that
    # only the test runner can spend
    input_index = 6

    # Since technically these can be sent in any order,
    # we must specify this as ok!
    expected_add_input = ExpectMsg(
        "tx_add_input",
        channel_id=channel_id_v2(local_keyset),
        sequence=0xFFFFFFFD,
        script_sig="",
        if_match=odd_serial,
    )

    funding_amount = 100000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        DualFundAccept(),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            # Leave some room for a change output
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=1000,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=100,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("channel_id"),
            funding_satoshis=funding_amount,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Create and stash Funding object and FundingTx
        CreateDualFunding(
            fee=200,
            funding_sats=agreed_funding(Side.local),
            locktime=sent("open_channel2.locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=0,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        expected_add_input,
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=0,
            sats=agreed_funding(Side.local),
            script=funding_lockscript(local_funding_privkey),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            sats=sent("tx_add_output.sats", int),
            script=sent("tx_add_output.script"),
        ),
        ExpectMsg(
            "tx_add_output", channel_id=channel_id_v2(local_keyset), if_match=odd_serial
        ),
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            # This function is the key to this test.
            # `change_amount` uses a P2WPKH weight to calculate
            # the input's fees; for this test we're using the
            # magic `index_input = 6`, which is a large
            # P2WSH-multisig address.
            sats=change_amount(
                Side.local,
                True,
                "001473daa75958d5b2ddca87a6c279bb7cb307167037",
                utxo_amount(input_index),
            ),
            script="001473daa75958d5b2ddca87a6c279bb7cb307167037",
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        FinalizeFunding(funding=funding()),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("accept_channel2.to_self_delay", int),
            remote_to_self_delay=sent("open_channel2.to_self_delay", int),
            local_amount=msat(sent("open_channel2.funding_satoshis", int)),
            remote_amount=msat(rcvd("accept_channel2.funding_satoshis", int)),
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        ExpectError(),
    ]

    runner.run(test)


def test_df_opener_accepter_underpays_fees(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 6 is special, only the test runner can spend it
    # 6 is a 1 of 5 multisig, meant to test the witness fee calculations
    input_index = 6
    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=900000, feerate=1000, expect_fail=True),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=900000,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_feerate_perkw=1000,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=400000,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Create and stash Funding object and FundingTx
        CreateDualFunding(
            fee=200,
            funding_sats=agreed_funding(Side.remote),
            locktime=rcvd("open_channel2.locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=1,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            sats=agreed_funding(Side.remote),
            if_match=even_serial,
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=101,
            # This function is the key to this test.
            # `change_amount` uses a P2WPKH weight to calculate
            # the input's fees; for this test we're using the
            # magic `index_input = 6`, which is a large
            # P2WSH-multisig address.
            sats=change_amount(
                Side.remote,
                False,
                "001473daa75958d5b2ddca87a6c279bb7cb307167037",
                utxo_amount(input_index),
            ),
            script="001473daa75958d5b2ddca87a6c279bb7cb307167037",
        ),
        # FIXME: They may send us the funding output second,
        # if there's also a change output
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Their change if they have one!
        OneOf(
            [
                ExpectMsg(
                    "tx_add_output",
                    if_match=even_serial,
                    channel_id=channel_id_v2(local_keyset),
                ),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                AddOutput(
                    funding=funding(),
                    serial_id=rcvd("tx_add_output.serial_id", int),
                    sats=rcvd("tx_add_output.sats", int),
                    script=rcvd("tx_add_output.script"),
                ),
            ],
            [
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        FinalizeFunding(funding=funding()),
        Commit(
            funding=funding(),
            opener=Side.remote,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("open_channel2.to_self_delay", int),
            remote_to_self_delay=sent("accept_channel2.to_self_delay", int),
            local_amount=msat(sent("accept_channel2.funding_satoshis", int)),
            remote_amount=msat(rcvd("open_channel2.funding_satoshis", int)),
            local_dust_limit=550,
            remote_dust_limit=546,
            feerate=rcvd("open_channel2.commitment_feerate_perkw", int),
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        ExpectError(),
    ]

    runner.run(test)


def accepter_tx_creation(
    input_index: int,
    is_rbf: bool,
    funding_amt: int,
    local_funding_privkey: str,
    local_keyset: KeySet,
    runner: Runner,
) -> List[Event]:
    """Repeated tx construction protocols, for accepter tests"""
    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(input_index)
    fee = sats_in - funding_amt if is_rbf else fee

    open_msg = "init_rbf" if is_rbf else "open_channel2"
    accept_msg = "ack_rbf" if is_rbf else "accept_channel2"

    return [
        CreateFunding(
            txid_in=txid_in,
            tx_index_in=tx_index_in,
            sats_in=sats_in,
            spending_privkey=spending_privkey,
            fee=fee,
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("accept_channel2.to_self_delay", int),
            remote_to_self_delay=sent("open_channel2.to_self_delay", int),
            local_amount=msat(sent(open_msg + ".funding_satoshis", int)),
            remote_amount=msat(rcvd(accept_msg + ".funding_satoshis", int)),
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Try removing and re-adding an input
        TryAll(
            [],
            [
                Msg(
                    "tx_remove_input",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg(
                    "tx_add_input",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                    prevtx=tx_spendable,
                    prevtx_vout=tx_out_for_index(input_index),
                    sequence=0xFFFFFFFD,
                    script_sig="",
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            sats=funding_amt,
            script=locking_script(),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Try removing and re-adding an output
        TryAll(
            [],
            [
                Msg(
                    "tx_remove_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg(
                    "tx_add_output",
                    channel_id=channel_id_v2(local_keyset),
                    serial_id=2,
                    sats=funding_amt,
                    script=locking_script(),
                ),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        FinalizeFunding(funding=funding()),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        ExpectMsg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
    ]


def opener_tx_creation(
    input_index: int,
    is_rbf: bool,
    funding_amt: int,
    local_funding_privkey: str,
    local_keyset: KeySet,
    runner: Runner,
) -> List[Event]:
    """Repeated tx construction protocols, for opener tests"""
    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(input_index)
    fee = sats_in - funding_amt if is_rbf else fee

    open_msg = "init_rbf" if is_rbf else "open_channel2"
    accept_msg = "ack_rbf" if is_rbf else "accept_channel2"

    return [
        CreateDualFunding(
            fee=fee,
            funding_sats=agreed_funding(Side.remote, is_rbf=is_rbf),
            locktime=rcvd(open_msg + ".locktime", int),
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            serial_id=rcvd("tx_add_input.serial_id", int),
            prevtx=rcvd("tx_add_input.prevtx"),
            prevtx_vout=rcvd("tx_add_input.prevtx_vout", int),
            script_sig=rcvd("tx_add_input.script_sig"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=1,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
        ),
        # FIXME: They may send us the funding output second,
        # if there's also a change output
        AddOutput(
            funding=funding(),
            serial_id=rcvd("tx_add_output.serial_id", int),
            sats=rcvd("tx_add_output.sats", int),
            script=rcvd("tx_add_output.script"),
        ),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=101,
            sats=change_amount(
                Side.remote,
                False,
                "001473daa75958d5b2ddca87a6c279bb7cb307167037",
                funding_amount_for_utxo(input_index),
            ),
            script="001473daa75958d5b2ddca87a6c279bb7cb307167037",
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Their change if they have one!
        OneOf(
            [
                ExpectMsg(
                    "tx_add_output",
                    if_match=even_serial,
                    channel_id=channel_id_v2(local_keyset),
                ),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                AddOutput(
                    funding=funding(),
                    serial_id=rcvd("tx_add_output.serial_id", int),
                    sats=rcvd("tx_add_output.sats", int),
                    script=rcvd("tx_add_output.script"),
                ),
            ],
            [
                ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
                Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
            ],
        ),
        FinalizeFunding(funding=funding()),
        Commit(
            funding=funding(),
            opener=Side.remote,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("open_channel2.to_self_delay", int),
            remote_to_self_delay=sent("accept_channel2.to_self_delay", int),
            local_amount=msat(sent(accept_msg + ".funding_satoshis", int)),
            remote_amount=msat(rcvd(open_msg + ".funding_satoshis", int)),
            local_dust_limit=550,
            remote_dust_limit=546,
            feerate=rcvd("open_channel2.commitment_feerate_perkw", int),
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_recv(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "commitment_signed",
            channel_id=channel_id_v2(local_keyset),
            signature=commitsig_to_send(),
            htlc_signature="[]",
        ),
        Msg(
            "tx_signatures",
            channel_id=channel_id_v2(local_keyset),
            txid=funding_txid(),
            witness_stack=witnesses(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        AddWitnesses(funding=funding(), witness_stack=rcvd("witness_stack")),
    ]


def test_rbf_accepter(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    input_index = 0
    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=0,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("channel_id"),
            funding_satoshis=0,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += accepter_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=0
        ),
    ]

    test += accepter_tx_creation(
        input_index,
        True,
        rbf_funding_amount,
        local_funding_privkey,
        local_keyset,
        runner,
    )

    runner.run(test)


def test_rbf_opener(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 5 is special, only the test runner can spend it
    input_index = 5
    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(input_index)

    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000
    init_feerate = 2000
    rbf_feerate = init_feerate * 65 // 64

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=funding_amount, feerate=init_feerate),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=400000,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += opener_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        InitRbf(
            channel_id=channel_id_v2(local_keyset),
            amount=rbf_funding_amount,
            utxo_tx=rcvd("tx_add_input.prevtx"),
            utxo_outnum=rcvd("tx_add_input.prevtx_vout", int),
            feerate=rbf_feerate * 2,
        ),
        ExpectMsg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=rbf_feerate * 2,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=380000),
    ]

    test += opener_tx_creation(
        input_index,
        True,
        rbf_funding_amount,
        local_funding_privkey,
        local_keyset,
        runner,
    )

    test += [
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    runner.run(test)


def test_rbf_accepter_funding_locked(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    input_index = 0
    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=0,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("channel_id"),
            funding_satoshis=0,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += accepter_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=0
        ),
    ]

    test += [
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # We're in the middle of an RBF, the original funding tx confirms
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=local_keyset.per_commit_point(1),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
    ]

    runner.run(test)


def test_rbf_opener_funding_locked(runner: Runner, with_proposal: Any) -> None:
    """Check that if the funding transaction is published while we're inflight
    everything works as expected"""
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 5 is special, only the test runner can spend it
    input_index = 5
    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(input_index)

    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000
    init_feerate = 2000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=funding_amount, feerate=init_feerate),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("open_channel2.channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=400000,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += opener_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        InitRbf(
            channel_id=channel_id_v2(local_keyset),
            amount=rbf_funding_amount,
            utxo_tx=rcvd("tx_add_input.prevtx"),
            utxo_outnum=rcvd("tx_add_input.prevtx_vout", int),
            feerate=init_feerate * 65 // 64,
        ),
        ExpectMsg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=init_feerate * 65 // 64,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=400000),
    ]

    test += [
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=1,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Block(blockheight=103, number=3, txs=[funding_tx()]),
        Msg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=local_keyset.per_commit_point(1),
        ),
        ExpectMsg(
            "funding_locked",
            channel_id=channel_id_v2(local_keyset),
            next_per_commitment_point=remote_per_commitment_point(1),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    runner.run(test)


def test_rbf_accepter_forgets(runner: Runner, with_proposal: Any) -> None:
    """The runner forgets we're in the middle of an RBF.
    Peer should reconnect and allow another RBF to be initialized.
    """
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    input_index = 0
    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=0,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("open_channel2.channel_id"),
            funding_satoshis=0,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += accepter_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=0
        ),
    ]

    # Now we forget that we're in the middle of an RBF
    test += [
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF, again?
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        ExpectError(),
        # We reconnect!
        Disconnect(),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # We expect them to send channel reestablish
        ExpectMsg(
            "channel_reestablish",
            channel_id=channel_id_v2(local_keyset),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
            ignore=ExpectMsg.ignore_all_gossip,
        ),
        Msg(
            "channel_reestablish",
            channel_id=channel_id_v2(local_keyset),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
            my_current_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        # Let's RBF, again?
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=0
        ),
    ]

    runner.run(test)


def test_rbf_opener_forgets(runner: Runner, with_proposal: Any) -> None:
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # Index 5 is special, only the test runner can spend it
    input_index = 5
    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(input_index)

    funding_amount = funding_amount_for_utxo(input_index)
    rbf_funding_amount = funding_amount - 1000
    initial_feerate = 2000
    rbf_feerate = initial_feerate * 65 // 64

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        FundChannel(amount=funding_amount, feerate=initial_feerate),
        ExpectMsg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.remote),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            htlc_minimum_msat=0,
            to_self_delay=6,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
            channel_flags="01",
        ),
        Msg(
            "accept_channel2",
            channel_id=rcvd("open_channel2.channel_id"),
            dust_limit_satoshis=550,
            funding_satoshis=400000,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            minimum_depth=3,
            max_accepted_htlcs=483,
            # We use 5, to be different from c-lightning runner who uses 6
            to_self_delay=5,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += opener_tx_creation(
        input_index, False, funding_amount, local_funding_privkey, local_keyset, runner
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        InitRbf(
            channel_id=channel_id_v2(local_keyset),
            amount=rbf_funding_amount,
            utxo_tx=rcvd("tx_add_input.prevtx"),
            utxo_outnum=rcvd("tx_add_input.prevtx_vout", int),
            feerate=rbf_feerate,
        ),
        ExpectMsg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=rbf_feerate,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=400000),
    ]

    # Now we forget that we're in the middle of an RBF
    test += [
        ExpectMsg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
            prevtx=tx_spendable,
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=1,
            sequence=0xFFFFFFFD,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(input_index),
            script_sig="",
        ),
        # The funding output
        ExpectMsg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            if_match=even_serial,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF, again?
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=rbf_feerate,
            locktime=100,
        ),
        ExpectError(),
        # We reconnect!
        Disconnect(),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # We expect them to send channel reestablish
        ExpectMsg(
            "channel_reestablish",
            channel_id=channel_id_v2(local_keyset),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
            ignore=ExpectMsg.ignore_all_gossip,
        ),
        Msg(
            "channel_reestablish",
            channel_id=channel_id_v2(local_keyset),
            next_commitment_number=1,
            next_revocation_number=0,
            your_last_per_commitment_secret="00" * 32,
            my_current_per_commitment_point=local_keyset.per_commit_point(0),
        ),
        ExpectMsg(
            "tx_signatures", channel_id=channel_id_v2(local_keyset), txid=funding_txid()
        ),
        # Let's RBF again?
        InitRbf(
            channel_id=channel_id_v2(local_keyset),
            amount=rbf_funding_amount,
            utxo_tx=rcvd("tx_add_input.prevtx"),
            utxo_outnum=rcvd("tx_add_input.prevtx_vout", int),
            feerate=rbf_feerate,
        ),
        ExpectMsg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=rbf_feerate,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        Msg("ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=400000),
    ]

    runner.run(test)


def test_rbf_not_valid_rbf(runner: Runner, with_proposal: Any) -> None:
    """The proposed rbf doesn't have any overlapping inputs"""
    with_proposal(dual_fund_csv)
    runner.add_startup_flag("experimental-dual-fund")

    local_funding_privkey = "20"
    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )
    orig_input_index = 0
    other_input_index = 2

    funding_amount = funding_amount_for_utxo(orig_input_index)
    rbf_funding_amount = funding_amount - 1000

    test = [
        Block(blockheight=102, txs=[tx_spendable]),
        Connect(connprivkey="02"),
        ExpectMsg("init"),
        # BOLT-f53ca2301232db780843e894f55d95d512f297f9 #9:
        # | 28/29 | `option_dual_fund`             | Use v2 of channel open, enables dual funding              | IN9      | `option_anchor_outputs`, `option_static_remotekey`   | [BOLT #2](02-peer-protocol.md)        |
        Msg("init", globalfeatures="", features=bitfield(12, 20, 29)),
        # Accepter side: we initiate a new channel.
        Msg(
            "open_channel2",
            channel_id=channel_id_tmp(local_keyset, Side.local),
            chain_hash=regtest_hash,
            funding_satoshis=funding_amount,
            dust_limit_satoshis=546,
            max_htlc_value_in_flight_msat=4294967295,
            htlc_minimum_msat=0,
            funding_feerate_perkw=253,
            commitment_feerate_perkw=253,
            # We use 5, because c-lightning runner uses 6, so this is different.
            to_self_delay=5,
            max_accepted_htlcs=483,
            locktime=0,
            funding_pubkey=pubkey_of(local_funding_privkey),
            revocation_basepoint=local_keyset.revocation_basepoint(),
            payment_basepoint=local_keyset.payment_basepoint(),
            delayed_payment_basepoint=local_keyset.delayed_payment_basepoint(),
            htlc_basepoint=local_keyset.htlc_basepoint(),
            first_per_commitment_point=local_keyset.per_commit_point(0),
            channel_flags=1,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "accept_channel2",
            channel_id=sent("open_channel2.channel_id"),
            funding_satoshis=0,
            funding_pubkey=remote_funding_pubkey(),
            revocation_basepoint=remote_revocation_basepoint(),
            payment_basepoint=remote_payment_basepoint(),
            delayed_payment_basepoint=remote_delayed_payment_basepoint(),
            htlc_basepoint=remote_htlc_basepoint(),
            first_per_commitment_point=remote_per_commitment_point(0),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
    ]

    test += accepter_tx_creation(
        orig_input_index,
        False,
        funding_amount,
        local_funding_privkey,
        local_keyset,
        runner,
    )

    test += [
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # Let's RBF
        Msg(
            "init_rbf",
            channel_id=channel_id_v2(local_keyset),
            funding_satoshis=rbf_funding_amount,
            funding_feerate_perkw=253 * 65 // 64,
            locktime=0,
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg(
            "ack_rbf", channel_id=channel_id_v2(local_keyset), funding_satoshis=0
        ),
    ]

    txid_in, tx_index_in, sats_in, spending_privkey, fee = utxo(other_input_index)
    fee = sats_in - rbf_funding_amount

    test += [
        CreateFunding(
            txid_in=txid_in,
            tx_index_in=tx_index_in,
            sats_in=sats_in,
            spending_privkey=spending_privkey,
            fee=fee,
            local_node_privkey="02",
            local_funding_privkey=local_funding_privkey,
            remote_node_privkey=runner.get_node_privkey(),
            remote_funding_privkey=remote_funding_privkey(),
        ),
        Commit(
            funding=funding(),
            opener=Side.local,
            local_keyset=local_keyset,
            local_to_self_delay=rcvd("accept_channel2.to_self_delay", int),
            remote_to_self_delay=sent("open_channel2.to_self_delay", int),
            local_amount=msat(sent("init_rbf.funding_satoshis", int)),
            remote_amount=msat(rcvd("ack_rbf.funding_satoshis", int)),
            local_dust_limit=546,
            remote_dust_limit=546,
            feerate=253,
            local_features=sent("init.features"),
            remote_features=rcvd("init.features"),
        ),
        Msg(
            "tx_add_input",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            prevtx=tx_spendable,
            prevtx_vout=tx_out_for_index(other_input_index),
            sequence=0xFFFFFFFD,
            script_sig="",
        ),
        AddInput(
            funding=funding(),
            privkey=privkey_for_index(other_input_index),
            serial_id=sent("tx_add_input.serial_id", int),
            prevtx=sent(),
            prevtx_vout=sent("tx_add_input.prevtx_vout", int),
            script_sig=sent(),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        Msg(
            "tx_add_output",
            channel_id=channel_id_v2(local_keyset),
            serial_id=2,
            sats=rbf_funding_amount,
            script=locking_script(),
        ),
        AddOutput(
            funding=funding(),
            serial_id=sent("tx_add_output.serial_id", int),
            script=sent(),
            sats=sent("tx_add_output.sats", int),
        ),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        ExpectMsg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        Msg("tx_complete", channel_id=channel_id_v2(local_keyset)),
        FinalizeFunding(funding=funding()),
        # Ignore unknown odd messages
        TryAll([], RawMsg(bytes.fromhex("270F"))),
        # We fail, because there's no overlapping input
        ExpectError(),
    ]

    runner.run(test)
