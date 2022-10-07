#! /usr/bin/env python3
# Variations on adding an HTLC.

from lnprototest import (
    TryAll,
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
    msat,
    remote_funding_privkey,
    regtest_hash,
    bitfield,
    HTLC,
    UpdateCommit,
    remote_per_commitment_secret,
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
    htlc_sigs_to_send,
    htlc_sigs_to_recv,
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


def test_htlc_add(runner: Runner) -> None:
    local_funding_privkey = "20"

    local_keyset = KeySet(
        revocation_base_secret="21",
        payment_base_secret="22",
        htlc_base_secret="24",
        delayed_payment_base_secret="23",
        shachain_seed="00" * 32,
    )

    # FIXME: Generate onion routing packet!
    dust_htlc = HTLC(
        owner=Side.local,
        amount_msat=1000,
        payment_secret="00" * 32,
        cltv_expiry=200,
        # hop_data[0] = 00000000000000000000000000000003E8000000C8000000000000000000000000
        onion_routing_packet="0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619b1153ae94698ea83a3298ab3c0ddd9f755853e4e5fbc5d4f3cb457bbb74a9b81d3b5bc9cf42d8617d1fe6966ffb66b8ec0eaa1188865957e26df123d11705395d339472bcc4920e428492f7822424eef8e6d903a768ec01959f3a1f2c1cd8725ba13329df3a932f641dee600dbb1a9f3bbe93a167410961f1777a7b48679d8a3041d57c0b8e795ed4884fbb33a2564d4cdafb528c7b63fc31cd2739e71d1d3b56f35ba7976a373b883eed8f1f263aedd540cce9b548e53e58c32ab604195f6004d8d92fe0a9a454229b9bc0795f3e4ccd54089075483afaa0ef3b32ee12cf321052f7b9e5ac1c28169e57d5628c3aee5c775d5fb33ba835fda195981b1e3a06792bdd0ecf85f8f6107fd830ca932e92c6713ea6d4d5129395f54aeabb54debccca130ad019a1f53a20c0c46dd8625ada068e2a13ea5373b60ecdf412728cc78192ae1a56bae26dfb450d2f6b4905e6bd9843fda7df63eb11fb77ce995b25d3076210eca527bb556b4ddc564fa4c6ccb43f1149163a4959ffe4178d653d35bdc052e4a46dd58b8f95fde83d114c4e35fd02e94a0dd2a9ae21594184808074a57d9de30c5105b53efe03aca192f8c518bc2b9e13211a9761c1948b31aa97f99da449968380005f96ff49a6e5fe833220a82f358eb94197584b2dfa5a1efee8918b5020f028748e5897bb694979f580ff58b8b1d865783340eaff2d1ce738409ec1c62c1bd7f632cf0730a5634a1a2d91244b865302339c1861655e11b264aeaf2feefbf2d1222bb13c6bd6b2d2379d9a548f93de4d2a044928458eafa745021e0a69796bb40f17c1ca53b895c76b53924faa886a4a19f07b50eda5f316e5f3b5422e984c59928144c275d4ae5e78634e16c6dafcfc92bb302c7d5eef1456250b0b8a41f0cabb55dd114d6b0bcaf53ef1ee2185d2383df57a0f1bc21d31f5d3ae395bab6e77370ee83ffe8995e9bfbe2f90b3ff0578720e0584e969479d40327415835579d7b8885037c02a611292c6bbffde25e86c184cc7c7481e8856ce6a3cf7109a6c001e51a2289c5ee3633936578d4dc3de82c18ebb787bf2c475e8fa0393727cbdbcd36849ee0b7411fba6fd5cb8459e63aaf3fba7a4cd4a04b266d8f416f0586e2093ea9c210140a6e6cb72759ae1dee7c24497f68389fb8d154f927cc4ab59b9137652eaf9c7cb56f0cce6c58616646c6fee836b07ce738a965b1ea725d9960c47e61086be053f3e9c48c08ce945404b060d9e699ad962c910208dda42d665f8eacf9865a64d2612ea62e0e2c0a4c731b35ae87b04e45739c34f4c972ce433a2094b10a9601e6711b95a6a226a85f4e4ed0e0417dbc9d737cd7d3513a82943de94ff8e4c9e91838506283f4878e3f41488fec47198b4a262b55d3691d275c6154d2a2ce9ee6ab97087e0f33654b01450869797c993dfca76cd732677bf1856f43d040d68022055987588f64af357bea80491b4bc42341dd6f81631d30fc28e8c5d7e3312655b30d277f10ce76c2525279ad53157b1c2c78b412107fc5f974ac7946bdc33ee54d71f3fc261530d50f20813e4e6aadf39e67573d5dc93a45023edf297b56def6b14ec5e19ca10fbfd1b807f17fa983bec363cf495c708a581db1bba1a23730ce22d0f925d764b04be014d662c3a36ac58b015317c9cf5ca6464f2ecef15e1769f2c91922968532bda66e9aaa2a7f120a9301f563fd33db8e90c940984b0a297e0c595544b7f687476325a07dbaba255c8461e98f069eea2246cfa50f1c2ef8d4c54f5fd509a9cc839548d7c252e60bb9c165d05f30bd525f6b53a4c8afc8fc31026686bcd5a48172593941b3113cbed88e6cfb566f7a693bb63c9a89925c1f5df0a115b4893128866a81c1b",
    )

    non_dust_htlc = HTLC(
        owner=Side.local,
        amount_msat=1000000,
        payment_secret="00" * 32,
        cltv_expiry=200,
        onion_routing_packet="0002eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619b1153ae94698ea83a3298ab3c0ddd9f755853e4e5fbc5d4f3cb457bbb74a9b81d3b5bc9cf42d8617d1fe6966ffb66b8ec0eaa1188865957e26df123d11705395d339472bcc4920e428492f7822424eef8e6d903a768ec01959f3a1f2c1cd8725ba13329df3a932f641dee600dbb1a9f3bbe93a167410961f1777a7b48679d8a3041d57c0b8e795ed4884fbb33a2564d4cdafb528c7b63fc31cd2739e71d1d3b56f35ba7976a373b883eed8f1f263aedd540cce9b548e53e58c32ab604195f6004d8d92fe0a9a454229b9bc0795f3e4ccd54089075483afaa0ef3b32ee12cf321052f7b9e5ac1c28169e57d5628c3aee5c775d5fb33ba835fda195981b1e3a06792bdd0ecf85f8f6107fd830ca932e92c6713ea6d4d5129395f54aeabb54debccca130ad019a1f53a20c0c46dd8625ada068e2a13ea5373b60ecdf412728cc78192ae1a56bae26dfb450d2f6b4905e6bd9843fda7df63eb11fb77ce995b25d3076210eca527bb556b4ddc564fa4c6ccb43f1149163a4959ffe4178d653d35bdc052e4a46dd58b8f95fde83d114c4e35fd02e94a0dd2a9ae21594184808074a57d9de30c5105b53efe03aca192f8c518bc2b9e13211a9761c1948b31aa97f99da449968380005f96ff49a6e5fe833220a82f358eb94197584b2dfa5a1efee8918b5020f028748e5897bb694979f580ff58b8b1d865783340eaff2d1ce738409ec1c62c1bd7f632cf0730a5634a1a2d91244b865302339c1861655e11b264aeaf2feefbf2d1222bb13c6bd6b2d2379d9a548f93de4d2a044928458eafa745021e0a69796bb40f17c1ca53b895c76b53924faa886a4a19f07b50eda5f316e5f3b5422e984c59928144c275d4ae5e78634e16c6dafcfc92bb302c7d5eef1456250b0b8a41f0cabb55dd114d6b0bcaf53ef1ee2185d2383df57a0f1bc21d31f5d3ae395bab6e77370ee83ffe8995e9bfbe2f90b3ff0578720e0584e969479d40327415835579d7b8885037c02a611292c6bbffde25e86c184cc7c7481e8856ce6a3cf7109a6c001e51a2289c5ee3633936578d4dc3de82c18ebb787bf2c475e8fa0393727cbdbcd36849ee0b7411fba6fd5cb8459e63aaf3fba7a4cd4a04b266d8f416f0586e2093ea9c210140a6e6cb72759ae1dee7c24497f68389fb8d154f927cc4ab59b9137652eaf9c7cb56f0cce6c58616646c6fee836b07ce738a965b1ea725d9960c47e61086be053f3e9c48c08ce945404b060d9e699ad962c910208dda42d665f8eacf9865a64d2612ea62e0e2c0a4c731b35ae87b04e45739c34f4c972ce433a2094b10a9601e6711b95a6a226a85f4e4ed0e0417dbc9d737cd7d3513a82943de94ff8e4c9e91838506283f4878e3f41488fec47198b4a262b55d3691d275c6154d2a2ce9ee6ab97087e0f33654b01450869797c993dfca76cd732677bf1856f43d040d68022055987588f64af357bea80491b4bc42341dd6f81631d30fc28e8c5d7e3312655b30d277f10ce76c2525279ad53157b1c2c78b412107fc5f974ac7946bdc33ee54d71f3fc261530d50f20813e4e6aadf39e67573d5dc93a45023edf297b56def6b14ec5e19ca10fbfd1b807f17fa983bec363cf495c708a581db1bba1a23730ce22d0f925d764b04be014d662c3a36ac58b015317c9cf5ca6464f2ecef15e1769f2c91922968532bda66e9aaa2a7f120a9301f563fd33db8e90c940984b0a297e0c595544b7f687476325a07dbaba255c8461e98f069eea2246cfa50f1c2ef8d4c54f5fd509a9cc839548d7c252e60bb9c165d05f30bd525f6b53a4c8afc8fc31026686bcd5a48172593941b3113cbed88e6cfb566f7a693bb63c9a89925c1f5df0a115b4893128866a81c1b",
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
        # We try both a dust and a non-dust htlc.
        TryAll(
            Msg(
                "update_add_htlc",
                channel_id=channel_id(),
                id=0,
                amount_msat=dust_htlc.amount_msat,
                payment_hash=dust_htlc.payment_hash(),
                cltv_expiry=dust_htlc.cltv_expiry,
                onion_routing_packet=dust_htlc.onion_routing_packet,
            ),
            Msg(
                "update_add_htlc",
                channel_id=channel_id(),
                id=0,
                amount_msat=non_dust_htlc.amount_msat,
                payment_hash=non_dust_htlc.payment_hash(),
                cltv_expiry=non_dust_htlc.cltv_expiry,
                onion_routing_packet=non_dust_htlc.onion_routing_packet,
            ),
        ),
        # Optional reconnect:
        TryAll(
            [],
            [
                Disconnect(),
                Connect(connprivkey="02"),
                ExpectMsg("init"),
                # Reconnect with same features.
                Msg("init", globalfeatures="", features=sent("init.features")),
                ExpectMsg(
                    "channel_reestablish",
                    channel_id=channel_id(),
                    next_commitment_number=1,
                    next_revocation_number=0,
                    your_last_per_commitment_secret="00" * 32,
                ),
                Msg(
                    "channel_reestablish",
                    channel_id=channel_id(),
                    next_commitment_number=1,
                    next_revocation_number=0,
                    your_last_per_commitment_secret="00" * 32,
                    my_current_per_commitment_point=local_keyset.per_commit_point(0),
                ),
                # BOLT #2:
                # A node:
                #   - if `next_commitment_number` is 1 in both the
                #     `channel_reestablish` it sent and received:
                #     - MUST retransmit `funding_locked`.
                #   - otherwise:
                #     - MUST NOT retransmit `funding_locked`.
                ExpectMsg(
                    "funding_locked",
                    channel_id=channel_id(),
                    next_per_commitment_point=remote_per_commitment_point(1),
                    ignore=ExpectMsg.ignore_all_gossip,
                ),
                # BOLT #2:
                # A node:
                # ...
                # - upon disconnection:
                #   - MUST reverse any uncommitted updates sent by the
                #   other side (i.e. all messages beginning with `update_`
                #   for which no `commitment_signed` has been received).
                # So this puts us back where we were.
                Msg(
                    "update_add_htlc",
                    channel_id=channel_id(),
                    id=0,
                    amount_msat=dust_htlc.amount_msat,
                    payment_hash=dust_htlc.payment_hash(),
                    cltv_expiry=dust_htlc.cltv_expiry,
                    onion_routing_packet=dust_htlc.onion_routing_packet,
                ),
            ],
        ),
        UpdateCommit(new_htlcs=[(dust_htlc, 0)]),
        Msg(
            "commitment_signed",
            channel_id=channel_id(),
            signature=commitsig_to_send(),
            htlc_signature=htlc_sigs_to_send(),
        ),
        ExpectMsg(
            "revoke_and_ack",
            channel_id=channel_id(),
            per_commitment_secret=remote_per_commitment_secret(0),
            next_per_commitment_point=remote_per_commitment_point(2),
            ignore=ExpectMsg.ignore_all_gossip,
        ),
        ExpectMsg(
            "commitment_signed",
            signature=commitsig_to_recv(),
            htlc_signature=htlc_sigs_to_recv(),
            ignore=ExpectMsg.ignore_all_gossip,
        ),
        # Now try optionally reconnecting.
        TryAll(
            [],
            # Ignore unknown.
            [RawMsg(bytes.fromhex("270F"))],
            [
                Disconnect(),
                Connect(connprivkey="02"),
                ExpectMsg("init"),
                # Reconnect with same features.
                Msg("init", globalfeatures="", features=sent("init.features")),
                ExpectMsg(
                    "channel_reestablish",
                    channel_id=channel_id(),
                    next_commitment_number=2,
                    next_revocation_number=0,
                    your_last_per_commitment_secret="00" * 32,
                    ignore=ExpectMsg.ignore_all_gossip,
                ),
                # Depends on what we tell them we already received:
                TryAll(
                    # We didn't receive revoke_and_ack:
                    [
                        Msg(
                            "channel_reestablish",
                            channel_id=channel_id(),
                            next_commitment_number=1,
                            next_revocation_number=0,
                            your_last_per_commitment_secret="00" * 32,
                            my_current_per_commitment_point=local_keyset.per_commit_point(
                                0
                            ),
                        ),
                        ExpectMsg(
                            "revoke_and_ack",
                            channel_id=channel_id(),
                            per_commitment_secret=remote_per_commitment_secret(0),
                            next_per_commitment_point=remote_per_commitment_point(2),
                            ignore=ExpectMsg.ignore_all_gossip,
                        ),
                        ExpectMsg(
                            "commitment_signed",
                            signature=commitsig_to_recv(),
                            htlc_signature=htlc_sigs_to_recv(),
                            ignore=ExpectMsg.ignore_all_gossip,
                        ),
                    ],
                    # We did receive revoke_and_ack, but not
                    # commitment_signed
                    [
                        Msg(
                            "channel_reestablish",
                            channel_id=channel_id(),
                            next_commitment_number=1,
                            next_revocation_number=1,
                            your_last_per_commitment_secret=remote_per_commitment_secret(
                                0
                            ),
                            my_current_per_commitment_point=local_keyset.per_commit_point(
                                0
                            ),
                        ),
                        ExpectMsg(
                            "commitment_signed",
                            signature=commitsig_to_recv(),
                            htlc_signature=htlc_sigs_to_recv(),
                            ignore=ExpectMsg.ignore_all_gossip,
                        ),
                    ],
                    # We received commitment_signed:
                    [
                        Msg(
                            "channel_reestablish",
                            channel_id=channel_id(),
                            next_commitment_number=2,
                            next_revocation_number=1,
                            your_last_per_commitment_secret=remote_per_commitment_secret(
                                0
                            ),
                            my_current_per_commitment_point=local_keyset.per_commit_point(
                                1
                            ),
                        )
                    ],
                ),
            ],
        ),
    ]

    runner.run(test)
