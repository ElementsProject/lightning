#! /usr/bin/python3
# FIXME: clean this up for use as pyln.proto.tx
from bitcoin.core import (
    COutPoint,
    CTxOut,
    CTxIn,
    Hash160,
    CMutableTransaction,
    CTxWitness,
    CScriptWitness,
)
import bitcoin.core.script as script
from bitcoin.core.script import CScript
import struct
import hashlib
from hashlib import sha256
from .keyset import KeySet
from .errors import SpecFileError, EventError
from .signature import Sig
from typing import List, Tuple, Callable, Union, Optional, Dict
from .event import Event, ResolvableInt, ResolvableStr, negotiated, msat
from .runner import Runner
from .utils import Side, check_hex
from .funding import Funding
import coincurve
import json


class HTLC(object):
    def __init__(
        self,
        owner: Side,
        amount_msat: int,
        payment_secret: str,
        cltv_expiry: int,
        onion_routing_packet: str,
    ):
        """A HTLC offered by @owner"""
        self.owner = owner
        self.amount_msat = amount_msat
        self.payment_secret = check_hex(payment_secret, 64)
        self.cltv_expiry = cltv_expiry
        self.onion_routing_packet = check_hex(onion_routing_packet, 1366 * 2)

    def raw_payment_hash(self) -> bytes:
        return sha256(bytes.fromhex(self.payment_secret)).digest()

    def payment_hash(self) -> str:
        return self.raw_payment_hash().hex()

    def __str__(self) -> str:
        return "htlc({},{},{})".format(
            self.owner, self.amount_msat, self.payment_hash()
        )

    @staticmethod
    def htlc_timeout_fee(feerate_per_kw: int, option_anchor_outputs: bool) -> int:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # The fee for an HTLC-timeout transaction:
        #   - MUST BE calculated to match:
        #     1. Multiply `feerate_per_kw` by 663 (666 if `option_anchor_outputs`) and divide by 1000 (rounding down).
        if option_anchor_outputs:
            base = 666
        else:
            base = 663
        return feerate_per_kw * base // 1000

    @staticmethod
    def htlc_success_fee(feerate_per_kw: int, option_anchor_outputs: bool) -> int:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # The fee for an HTLC-success transaction:
        #   - MUST BE calculated to match:
        #     1. Multiply `feerate_per_kw` by 703 and (706 if `option_anchor_outputs`) divide by 1000 (rounding down).
        if option_anchor_outputs:
            base = 706
        else:
            base = 703
        return feerate_per_kw * base // 1000


class Commitment(object):
    def __init__(
        self,
        funding: Funding,
        opener: Side,
        local_keyset: KeySet,
        remote_keyset: KeySet,
        local_to_self_delay: int,
        remote_to_self_delay: int,
        local_amount: int,
        remote_amount: int,
        local_dust_limit: int,
        remote_dust_limit: int,
        feerate: int,
        option_static_remotekey: bool,
        option_anchor_outputs: bool,
    ):
        self.opener = opener
        self.funding = funding
        self.feerate = feerate
        self.keyset = [local_keyset, remote_keyset]
        self.self_delay = (local_to_self_delay, remote_to_self_delay)
        self.amounts = [local_amount, remote_amount]
        self.dust_limit = (local_dust_limit, remote_dust_limit)
        self.htlcs: Dict[int, HTLC] = {}
        self.commitnum = 0
        self.option_static_remotekey = option_static_remotekey
        self.option_anchor_outputs = option_anchor_outputs
        if self.option_anchor_outputs:
            assert self.option_static_remotekey

    @staticmethod
    def ripemd160(b: bytes) -> bytes:
        hasher = hashlib.new("ripemd160")
        hasher.update(b)
        return hasher.digest()

    def revocation_privkey(self, side: Side) -> coincurve.PrivateKey:
        """Derive the privkey used for the revocation of side's commitment transaction."""
        # BOLT #3:
        # The `revocationpubkey` is a blinded key: when the local node wishes
        # to create a new commitment for the remote node, it uses its own
        # `revocation_basepoint` and the remote node's `per_commitment_point`
        # to derive a new `revocationpubkey` for the commitment.
        revocation_basepoint_secret = self.keyset[not side].revocation_base_secret
        revocation_basepoint = self.keyset[not side].raw_revocation_basepoint()
        per_commitment_secret = self.keyset[side].raw_per_commit_secret(self.commitnum)
        per_commitment_point = self.keyset[side].raw_per_commit_point(self.commitnum)

        # BOLT #3:
        # ...
        #    revocationprivkey = revocation_basepoint_secret * SHA256(revocation_basepoint || per_commitment_point)
        #      + per_commitment_secret * SHA256(per_commitment_point || revocation_basepoint)
        revocation_tweak = sha256(
            revocation_basepoint.format() + per_commitment_point.format()
        ).digest()
        val = revocation_basepoint_secret.multiply(revocation_tweak, update=False)

        per_commit_tweak = sha256(
            per_commitment_point.format() + revocation_basepoint.format()
        ).digest()

        val2 = per_commitment_secret.multiply(per_commit_tweak, update=False)
        return val.add(val2.secret, update=False)

    def revocation_pubkey(self, side: Side) -> coincurve.PublicKey:
        """Derive the pubkey used for side's commitment transaction."""
        return coincurve.PublicKey.from_secret(self.revocation_privkey(side).secret)

    def _basepoint_tweak(
        self, basesecret: coincurve.PrivateKey, side: Side
    ) -> coincurve.PrivateKey:
        # BOLT #3:
        # ### `localpubkey`, `local_htlcpubkey`, `remote_htlcpubkey`,
        #  `local_delayedpubkey`, and `remote_delayedpubkey` Derivation
        # ...
        # The corresponding private keys can be similarly derived, if the
        # basepoint secrets are known (i.e. the private keys corresponding to
        # `localpubkey`, `local_htlcpubkey`, and `local_delayedpubkey` only):
        #
        #    privkey = basepoint_secret + SHA256(per_commitment_point || basepoint)
        per_commit_point = self.keyset[side].raw_per_commit_point(self.commitnum)
        basepoint = coincurve.PublicKey.from_secret(basesecret.secret)

        tweak = sha256(per_commit_point.format() + basepoint.format()).digest()
        return basesecret.add(tweak, update=False)

    def delayed_pubkey(self, side: Side) -> coincurve.PublicKey:
        """Generate local delayed_pubkey for this side"""
        privkey = self._basepoint_tweak(
            self.keyset[side].delayed_payment_base_secret, side
        )
        return coincurve.PublicKey.from_secret(privkey.secret)

    def to_remote_pubkey(self, side: Side) -> coincurve.PublicKey:
        """Generate remote payment key for this side"""
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3: If
        # `option_static_remotekey` or `option_static_remotekey` is negotiated
        # the `remotepubkey` is simply the remote node's `payment_basepoint`,
        # otherwise it is calculated as above using the remote node's
        # `payment_basepoint`.
        if self.option_static_remotekey:
            privkey = self.keyset[not side].payment_base_secret
        else:
            privkey = self._basepoint_tweak(
                self.keyset[not side].payment_base_secret, side
            )
            print(
                "to-remote for side {}: self->payment = {} (local would be {}), per_commit_point = {}, keyset->self_payment_key = {}".format(
                    side,
                    coincurve.PublicKey.from_secret(
                        self.keyset[not side].payment_base_secret.secret
                    )
                    .format()
                    .hex(),
                    coincurve.PublicKey.from_secret(
                        self.keyset[Side.local].payment_base_secret.secret
                    )
                    .format()
                    .hex(),
                    self.keyset[side].per_commit_point(self.commitnum),
                    coincurve.PublicKey.from_secret(privkey.secret).format().hex(),
                )
            )
        return coincurve.PublicKey.from_secret(privkey.secret)

    def local_htlc_pubkey(self, side: Side) -> coincurve.PublicKey:
        privkey = self._basepoint_tweak(self.keyset[side].htlc_base_secret, side)
        return coincurve.PublicKey.from_secret(privkey.secret)

    def remote_htlc_pubkey(self, side: Side) -> coincurve.PublicKey:
        privkey = self._basepoint_tweak(self.keyset[not side].htlc_base_secret, side)
        return coincurve.PublicKey.from_secret(privkey.secret)

    def add_htlc(self, htlc: HTLC, htlc_id: int) -> bool:
        if htlc_id in self.htlcs:
            return False
        self.htlcs[htlc_id] = htlc
        self.amounts[htlc.owner] -= htlc.amount_msat
        return True

    def del_htlc(self, htlc: HTLC, xfer_funds: bool) -> bool:
        for k, v in self.htlcs.items():
            if v == htlc:
                if xfer_funds:
                    gains_to = not htlc.owner
                else:
                    gains_to = htlc.owner  # type: ignore
                self.amounts[gains_to] += htlc.amount_msat
                del self.htlcs[k]
                return True
        return False

    def inc_commitnum(self) -> None:
        self.commitnum += 1

    def channel_id_v2(self) -> str:
        # BOLT-0eebb43e32a513f3b4dd9ced72ad1e915aefdd25 #2:
        #
        # For channels established using the v2 protocol, the `channel_id` is the
        # SHA256(lesser-revocation-basepoint || greater-revocation-basepoint),
        # where the lesser and greater is based off the order of the
        # basepoint. The basepoints are compact DER-encoded public keys.
        remote_key = self.keyset[Side.remote].raw_revocation_basepoint()
        local_key = self.keyset[Side.local].raw_revocation_basepoint()
        if remote_key.format() < local_key.format():
            return sha256(remote_key.format() + local_key.format()).digest().hex()
        else:
            return sha256(local_key.format() + remote_key.format()).digest().hex()

    @staticmethod
    def obscured_commit_num(
        opener_payment_basepoint: coincurve.PublicKey,
        non_opener_payment_basepoint: coincurve.PublicKey,
        commitnum: int,
    ) -> int:
        # BOLT #3:
        # The 48-bit commitment number is obscured by `XOR` with the lower 48 bits of:
        #
        #    SHA256(payment_basepoint from open_channel || payment_basepoint from accept_channel)
        shabytes = sha256(
            opener_payment_basepoint.format() + non_opener_payment_basepoint.format()
        ).digest()[-6:]
        obscurer = struct.unpack(">Q", bytes(2) + shabytes)[0]
        return commitnum ^ obscurer

    def _fee(self, num_untrimmed_htlcs: int) -> int:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # The base fee for a commitment transaction:
        #  - MUST be calculated to match:
        #      1. Start with `weight` = 724 (1124 if `option_anchor_outputs`).
        #      2. For each committed HTLC, if that output is not trimmed as specified in
        #      [Trimmed Outputs](#trimmed-outputs), add 172 to `weight`.
        #      3. Multiply `feerate_per_kw` by `weight`, divide by 1000 (rounding down).

        if self.option_anchor_outputs:
            base = 1124
        else:
            base = 724
        fee = ((base + 172 * num_untrimmed_htlcs) * self.feerate) // 1000
        # FIXME-BOLT_QUOTE:
        #    4. If `option_anchor_outputs` applies to the commitment transaction:
        #      - Add an additional 660 satoshis for the two anchor outputs.
        if self.option_anchor_outputs:
            fee += 660
        return fee

    def _to_local_output(self, fee: int, side: Side) -> Tuple[script.CScript, int]:
        # BOLT #3:
        # #### `to_local` Output
        #
        # This output sends funds back to the owner of this commitment
        # transaction and thus must be timelocked using
        # `OP_CHECKSEQUENCEVERIFY`. It can be claimed, without delay, by the
        # other party if they know the revocation private key. The output is a
        # version-0 P2WSH, with a witness script:
        #
        #     OP_IF
        #         # Penalty transaction
        #         <revocationpubkey>
        #     OP_ELSE
        #         `to_self_delay`
        #         OP_CHECKSEQUENCEVERIFY
        #         OP_DROP
        #         <local_delayedpubkey>
        #     OP_ENDIF
        #     OP_CHECKSIG
        to_self_script = script.CScript(
            [
                script.OP_IF,
                self.revocation_pubkey(side).format(),
                script.OP_ELSE,
                self.self_delay[side],
                script.OP_CHECKSEQUENCEVERIFY,
                script.OP_DROP,
                self.delayed_pubkey(side).format(),
                script.OP_ENDIF,
                script.OP_CHECKSIG,
            ]
        )

        # BOLT #3: The amounts for each output MUST be rounded down to whole
        # satoshis. If this amount, minus the fees for the HTLC transaction,
        # is less than the `dust_limit_satoshis` set by the owner of the
        # commitment transaction, the output MUST NOT be produced (thus the
        # funds add to fees).
        amount_to_self = self.amounts[side] // 1000

        if side == self.opener:
            amount_to_self -= fee

        return to_self_script, amount_to_self

    def _to_remote_output(self, fee: int, side: Side) -> Tuple[script.CScript, int]:
        """Returns the scriptpubkey and amount"""

        amount_to_other = self.amounts[not side] // 1000
        if not side == self.opener:
            amount_to_other -= fee

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # If `option_anchor_outputs` applies to the commitment transaction, the
        # `to_remote` output is encumbered by a one block csv lock.
        #
        #    <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
        #
        # The output is spent by a transaction with `nSequence` field set to
        # `1` and witness:
        #
        #    <remote_sig>
        #
        # Otherwise, this output is a simple P2WPKH to `remotepubkey`.
        if self.option_anchor_outputs:
            redeemscript = script.CScript(
                [
                    self.to_remote_pubkey(side).format(),
                    script.OP_CHECKSIGVERIFY,
                    1,
                    script.OP_CHECKSEQUENCEVERIFY,
                ]
            )
            cscript = script.CScript([script.OP_0, sha256(redeemscript).digest()])
        else:
            cscript = CScript(
                [script.OP_0, Hash160(self.to_remote_pubkey(side).format())]
            )
        return cscript, amount_to_other

    def _offered_htlc_output(
        self, htlc: HTLC, side: Side
    ) -> Tuple[script.CScript, int]:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3: This output sends funds to either an HTLC-timeout
        # transaction after the HTLC-timeout or to the remote node
        # using the payment preimage or the revocation key. The output
        # is a P2WSH, with a witness script (no option_anchor_outputs):
        #
        # # To remote node with revocation key
        # OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
        # OP_IF
        #     OP_CHECKSIG
        # OP_ELSE
        #     <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
        #     OP_NOTIF
        #         # To local node via HTLC-timeout transaction (timelocked).
        #         OP_DROP 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
        #     OP_ELSE
        #         # To remote node with preimage.
        #         OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
        #         OP_CHECKSIG
        #     OP_ENDIF
        # OP_ENDIF

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # Or, with `option_anchor_outputs`:
        #
        #    # To remote node with revocation key
        #    OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
        #    OP_IF
        #        OP_CHECKSIG
        #    OP_ELSE
        #        <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
        #        OP_NOTIF
        #            # To local node via HTLC-timeout transaction (timelocked).
        #            OP_DROP 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
        #        OP_ELSE
        #            # To remote node with preimage.
        #            OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
        #            OP_CHECKSIG
        #        OP_ENDIF
        #        1 OP_CHECKSEQUENCEVERIFY OP_DROP
        #    OP_ENDIF

        if self.option_anchor_outputs:
            csvcheck = [1, script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP]
        else:
            csvcheck = []
        htlc_script = script.CScript(
            [
                script.OP_DUP,
                script.OP_HASH160,
                Hash160(self.revocation_pubkey(side).format()),
                script.OP_EQUAL,
                script.OP_IF,
                script.OP_CHECKSIG,
                script.OP_ELSE,
                self.remote_htlc_pubkey(side).format(),
                script.OP_SWAP,
                script.OP_SIZE,
                32,
                script.OP_EQUAL,
                script.OP_NOTIF,
                script.OP_DROP,
                2,
                script.OP_SWAP,
                self.local_htlc_pubkey(side).format(),
                2,
                script.OP_CHECKMULTISIG,
                script.OP_ELSE,
                script.OP_HASH160,
                self.ripemd160(htlc.raw_payment_hash()),
                script.OP_EQUALVERIFY,
                script.OP_CHECKSIG,
                script.OP_ENDIF,
            ]
            + csvcheck
            + [script.OP_ENDIF]
        )

        # BOLT #3: The amounts for each output MUST be rounded down to whole
        # satoshis.
        return htlc_script, htlc.amount_msat // 1000

    def _received_htlc_output(
        self, htlc: HTLC, side: Side
    ) -> Tuple[script.CScript, int]:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # This output sends funds to either the remote node after the
        # HTLC-timeout or using the revocation key, or to an HTLC-success
        # transaction with a successful payment preimage. The output is a
        # P2WSH, with a witness script (no option_anchor_outputs):
        #
        # # To remote node with revocation key
        # OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
        # OP_IF
        #     OP_CHECKSIG
        # OP_ELSE
        #     <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
        #     OP_IF
        #         # To local node via HTLC-success transaction.
        #         OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
        #         2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
        #     OP_ELSE
        #         # To remote node after timeout.
        #         OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
        #         OP_CHECKSIG
        #     OP_ENDIF
        # OP_ENDIF

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        #  Or, with `option_anchor_outputs`:
        #
        #     # To remote node with revocation key
        #     OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
        #     OP_IF
        #         OP_CHECKSIG
        #     OP_ELSE
        #         <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
        #         OP_IF
        #             # To local node via HTLC-success transaction.
        #             OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
        #             2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
        #         OP_ELSE
        #             # To remote node after timeout.
        #             OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
        #             OP_CHECKSIG
        #         OP_ENDIF
        #         1 OP_CHECKSEQUENCEVERIFY OP_DROP
        #     OP_ENDIF
        if self.option_anchor_outputs:
            csvcheck = [1, script.OP_CHECKSEQUENCEVERIFY, script.OP_DROP]
        else:
            csvcheck = []

        htlc_script = script.CScript(
            [
                script.OP_DUP,
                script.OP_HASH160,
                Hash160(self.revocation_pubkey(side).format()),
                script.OP_EQUAL,
                script.OP_IF,
                script.OP_CHECKSIG,
                script.OP_ELSE,
                self.remote_htlc_pubkey(side).format(),
                script.OP_SWAP,
                script.OP_SIZE,
                32,
                script.OP_EQUAL,
                script.OP_IF,
                script.OP_HASH160,
                self.ripemd160(htlc.raw_payment_hash()),
                script.OP_EQUALVERIFY,
                2,
                script.OP_SWAP,
                self.local_htlc_pubkey(side).format(),
                2,
                script.OP_CHECKMULTISIG,
                script.OP_ELSE,
                script.OP_DROP,
                htlc.cltv_expiry,
                script.OP_CHECKLOCKTIMEVERIFY,
                script.OP_DROP,
                script.OP_CHECKSIG,
                script.OP_ENDIF,
            ]
            + csvcheck
            + [script.OP_ENDIF]
        )

        # BOLT #3: The amounts for each output MUST be rounded down to whole
        # satoshis.
        return htlc_script, htlc.amount_msat // 1000

    def _anchor_out(self, side: Side) -> CTxOut:
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # #### `to_local_anchor` and `to_remote_anchor` Output (option_anchor_outputs)
        # ...
        #    <local_funding_pubkey/remote_funding_pubkey> OP_CHECKSIG OP_IFDUP
        #    OP_NOTIF
        #        OP_16 OP_CHECKSEQUENCEVERIFY
        #    OP_ENDIF
        # ...
        # The amount of the output is fixed at 330 sats
        redeemscript = CScript(
            [
                self.funding.funding_pubkey(side).format(),
                script.OP_CHECKSIG,
                script.OP_IFDUP,
                script.OP_NOTIF,
                16,
                script.OP_CHECKSEQUENCEVERIFY,
                script.OP_ENDIF,
            ]
        )
        return CTxOut(330, CScript([script.OP_0, sha256(redeemscript).digest()]))

    def untrimmed_htlcs(self, side: Side) -> List[HTLC]:
        htlcs = []
        for _, htlc in self.htlcs.items():
            # BOLT #3:
            #   - for every offered HTLC:
            #     - if the HTLC amount minus the HTLC-timeout fee would be less than
            #     `dust_limit_satoshis` set by the transaction owner:
            #       - MUST NOT contain that output.
            #     - otherwise:
            #       - MUST be generated as specified in
            #       [Offered HTLC Outputs](#offered-htlc-outputs).
            if htlc.owner == side:
                # FIXME: Use Millisatoshi type?
                if htlc.amount_msat - msat(
                    htlc.htlc_timeout_fee(self.feerate, self.option_anchor_outputs)
                ) < msat(self.dust_limit[side]):
                    continue
            else:
                # BOLT #3:
                #   - for every received HTLC:
                #     - if the HTLC amount minus the HTLC-success fee would be less
                #      than `dust_limit_satoshis` set by the transaction owner:
                #       - MUST NOT contain that output.
                #     - otherwise:
                #       - MUST be generated as specified in
                #       [Received HTLC Outputs](#received-htlc-outputs).
                if htlc.amount_msat - msat(
                    htlc.htlc_success_fee(self.feerate, self.option_anchor_outputs)
                ) < msat(self.dust_limit[side]):
                    continue
            htlcs.append(htlc)

        return htlcs

    def htlc_outputs(self, side: Side) -> List[Tuple[HTLC, int, bytes]]:
        """Give CTxOut, cltv_expiry, redeemscript for each non-trimmed HTLC"""
        ret: List[Tuple[CTxOut, int, bytes]] = []

        for htlc in self.untrimmed_htlcs(side):
            if htlc.owner == side:
                redeemscript, sats = self._offered_htlc_output(htlc, side)
            else:
                redeemscript, sats = self._received_htlc_output(htlc, side)
            ret.append(
                (
                    CTxOut(sats, CScript([script.OP_0, sha256(redeemscript).digest()])),
                    htlc.cltv_expiry,
                    redeemscript,
                )
            )

        return ret

    def _unsigned_tx(
        self, side: Side
    ) -> Tuple[CMutableTransaction, List[Optional[HTLC]]]:
        """Create the commitment transaction.

        Returns it and a list of matching HTLCs for each output

        """
        ocn = self.obscured_commit_num(
            self.keyset[self.opener].raw_payment_basepoint(),
            self.keyset[not self.opener].raw_payment_basepoint(),
            self.commitnum,
        )

        # BOLT #3:
        # ## Commitment Transaction
        # ...
        # * txin count: 1
        #    * `txin[0]` outpoint: `txid` and `output_index` from `funding_created` message
        #    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
        #    * `txin[0]` script bytes: 0
        #    * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
        txin = CTxIn(
            COutPoint(bytes.fromhex(self.funding.txid), self.funding.output_index),
            nSequence=0x80000000 | (ocn >> 24),
        )

        # txouts, with ctlv_timeouts (for htlc output tiebreak) and htlc
        txouts: List[Tuple[CTxOut, int, Optional[HTLC]]] = []

        have_htlcs = False
        for htlc in self.untrimmed_htlcs(side):
            if htlc.owner == side:
                redeemscript, sats = self._offered_htlc_output(htlc, side)
            else:
                redeemscript, sats = self._received_htlc_output(htlc, side)
            print(
                "*** Got htlc redeemscript {} / {}".format(
                    redeemscript, redeemscript.hex()
                )
            )
            txouts.append(
                (
                    CTxOut(sats, CScript([script.OP_0, sha256(redeemscript).digest()])),
                    htlc.cltv_expiry,
                    htlc,
                )
            )
            have_htlcs = True

        num_untrimmed_htlcs = len(txouts)
        fee = self._fee(num_untrimmed_htlcs)

        have_outputs = [False, False]
        out_redeemscript, sats = self._to_local_output(fee, side)
        if sats >= self.dust_limit[side]:
            txouts.append(
                (
                    CTxOut(
                        sats, CScript([script.OP_0, sha256(out_redeemscript).digest()])
                    ),
                    0,
                    None,
                )
            )
            have_outputs[side] = True

        cscript, sats = self._to_remote_output(fee, side)
        if sats >= self.dust_limit[side]:
            txouts.append((CTxOut(sats, cscript), 0, None))
            have_outputs[not side] = True

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # ## Commitment Transaction Construction
        # ...
        # 8. If `option_anchor_outputs` applies to the commitment transaction:
        #   * if `lo_local` exists and/or there are HTLCs, add a
        #     `to_local_anchor` output
        #   * if `to_remote` exists and/or there are HTLCs, add a
        #     `to_remote_anchor` output
        if self.option_anchor_outputs:
            if have_htlcs or have_outputs[side]:
                txouts.append((self._anchor_out(side), 0, None))
            if have_htlcs or have_outputs[not side]:
                txouts.append((self._anchor_out(not side), 0, None))  # type: ignore

        # BOLT #3:
        # ## Transaction Input and Output Ordering
        #
        # Lexicographic ordering: see
        # [BIP69](https://github.com/bitcoin/bips/blob/master/bip-0069.mediawiki).
        # In the case of identical HTLC outputs, the outputs are ordered in
        # increasing `cltv_expiry` order.

        # First sort by cltv_expiry
        txouts.sort(key=lambda txout: txout[1])
        # Now sort by BIP69: lexical key, then amount
        txouts.sort(key=lambda txout: txout[0].scriptPubKey)
        txouts.sort(key=lambda txout: txout[0].nValue)

        # BOLT #3:
        # ## Commitment Transaction
        #
        # * version: 2
        # * locktime: upper 8 bits are 0x20, lower 24 bits are the
        #   lower 24 bits of the obscured commitment number
        return (
            CMutableTransaction(
                vin=[txin],
                vout=[txout[0] for txout in txouts],
                nVersion=2,
                nLockTime=0x20000000 | (ocn & 0x00FFFFFF),
            ),
            [txout[2] for txout in txouts],
        )

    def htlc_tx(
        self,
        commit_tx: CMutableTransaction,
        outnum: int,
        side: Side,
        amount_sat: int,
        locktime: int,
        option_anchor_outputs: bool,
    ) -> CMutableTransaction:
        # BOLT #3:
        # ## HTLC-Timeout and HTLC-Success Transactions
        #
        # These HTLC transactions are almost identical, except the
        # HTLC-timeout transaction is timelocked. Both
        # HTLC-timeout/HTLC-success transactions can be spent by a valid
        # penalty transaction.

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
        # ## HTLC-Timeout and HTLC-Success Transactions
        # ...
        # * txin count: 1
        # * `txin[0]` outpoint: `txid` of the commitment transaction and
        #    `output_index` of the matching HTLC output for the HTLC transaction
        # * `txin[0]` sequence: `0` (set to `1` for `option_anchor_outputs`)
        # * `txin[0]` script bytes: `0`
        if option_anchor_outputs:
            sequence = 1
        else:
            sequence = 0

        txin = CTxIn(COutPoint(commit_tx.GetTxid(), outnum), nSequence=sequence)

        # BOLT #3:
        # ## HTLC-Timeout and HTLC-Success Transactions
        # ...
        # * txout count: 1
        # * `txout[0]` amount: the HTLC amount minus fees (see [Fee
        #    Calculation](#fee-calculation))
        # * `txout[0]` script: version-0 P2WSH with witness script as shown below
        # ...
        # The witness script for the output is:
        # OP_IF
        #     # Penalty transaction
        #     <revocationpubkey>
        # OP_ELSE
        #     `to_self_delay`
        #     OP_CHECKSEQUENCEVERIFY
        #     OP_DROP
        #     <local_delayedpubkey>
        # OP_ENDIF
        # OP_CHECKSIG
        redeemscript = script.CScript(
            [
                script.OP_IF,
                self.revocation_pubkey(side).format(),
                script.OP_ELSE,
                self.self_delay[side],
                script.OP_CHECKSEQUENCEVERIFY,
                script.OP_DROP,
                self.delayed_pubkey(side).format(),
                script.OP_ENDIF,
                script.OP_CHECKSIG,
            ]
        )
        print("htlc redeemscript = {}".format(redeemscript.hex()))
        txout = CTxOut(
            amount_sat, CScript([script.OP_0, sha256(redeemscript).digest()])
        )

        # BOLT #3:
        # ## HTLC-Timeout and HTLC-Success Transactions
        # ...
        # * version: 2
        # * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
        return CMutableTransaction(
            vin=[txin], vout=[txout], nVersion=2, nLockTime=locktime
        )

    def local_unsigned_tx(self) -> CMutableTransaction:
        return self._unsigned_tx(Side.local)[0]

    def remote_unsigned_tx(self) -> CMutableTransaction:
        return self._unsigned_tx(Side.remote)[0]

    def _sig(self, privkey: coincurve.PrivateKey, tx: CMutableTransaction) -> Sig:
        sighash = script.SignatureHash(
            self.funding.redeemscript(),
            tx,
            inIdx=0,
            hashtype=script.SIGHASH_ALL,
            amount=self.funding.amount,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
        return Sig(privkey.secret.hex(), sighash.hex())

    def local_sig(self, tx: CMutableTransaction) -> Sig:
        return self._sig(self.funding.bitcoin_privkeys[Side.local], tx)

    def remote_sig(self, tx: CMutableTransaction) -> Sig:
        print(
            "Signing {} redeemscript keys {} and {}: {} amount = {}\ntx: {}".format(
                Side.remote,
                self.funding.funding_pubkey(Side.local).format().hex(),
                self.funding.funding_pubkey(Side.remote).format().hex(),
                self.funding.redeemscript().hex(),
                self.funding.amount,
                tx.serialize().hex(),
            )
        )
        return self._sig(self.funding.bitcoin_privkeys[Side.remote], tx)

    def htlc_txs(
        self, side: Side
    ) -> List[Tuple[CMutableTransaction, script.CScript, int]]:
        """Return unsigned HTLC txs (+ redeemscript, input sats) in output order"""
        # So we need the HTLCs in output order, which is why we had _unsigned_tx
        # return them.
        commit_tx, htlcs = self._unsigned_tx(side)

        ret: List[Tuple[CMutableTransaction, script.CScript, int]] = []
        for outnum, htlc in enumerate(htlcs):
            # to_local or to_remote output?
            if htlc is None:
                continue
            if htlc.owner == side:
                redeemscript, sats = self._offered_htlc_output(htlc, side)
                fee = htlc.htlc_timeout_fee(self.feerate, self.option_anchor_outputs)
                # BOLT #3:
                # * locktime: `0` for HTLC-success, `cltv_expiry` for HTLC-timeout
                locktime = htlc.cltv_expiry
            else:
                redeemscript, sats = self._received_htlc_output(htlc, side)
                fee = htlc.htlc_success_fee(self.feerate, self.option_anchor_outputs)
                locktime = 0

            ret.append(
                (
                    self.htlc_tx(
                        commit_tx,
                        outnum,
                        side,
                        (htlc.amount_msat - msat(fee)) // 1000,
                        locktime,
                        self.option_anchor_outputs,
                    ),
                    redeemscript,
                    sats,
                )
            )

        return ret

    def htlc_sigs(self, signer: Side, side: Side) -> List[Sig]:
        """Produce the signer's signatures for the dest's HTLC transactions"""
        # BOLT #2:
        # - MUST include one `htlc_signature` for every HTLC transaction
        #   corresponding to the ordering of the commitment transaction (see
        #   [BOLT
        #   #3](03-transactions.md#transaction-input-and-output-ordering)).
        sigs: List[Sig] = []
        for htlc_tx, redeemscript, sats in self.htlc_txs(side):
            # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
            # ## HTLC-Timeout and HTLC-Success Transactions
            #
            # if `option_anchor_outputs` applies to this commitment transaction,
            # `SIGHASH_SINGLE|SIGHASH_ANYONECANPAY` is used.
            if self.option_anchor_outputs:
                hashtype = script.SIGHASH_SINGLE | script.SIGHASH_ANYONECANPAY
            else:
                hashtype = script.SIGHASH_ALL

            sighash = script.SignatureHash(
                redeemscript,
                htlc_tx,
                inIdx=0,
                hashtype=hashtype,
                amount=sats,
                sigversion=script.SIGVERSION_WITNESS_V0,
            )
            privkey = self._basepoint_tweak(self.keyset[signer].htlc_base_secret, side)
            sigs.append(Sig(privkey.secret.hex(), sighash.hex()))

        return sigs

    def signed_tx(self, unsigned_tx: CMutableTransaction) -> CMutableTransaction:
        # BOLT #3:
        # * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
        tx = unsigned_tx.copy()
        sighash = script.SignatureHash(
            self.funding.redeemscript(),
            tx,
            inIdx=0,
            hashtype=script.SIGHASH_ALL,
            amount=self.funding.amount,
            sigversion=script.SIGVERSION_WITNESS_V0,
        )
        sigs = [
            key.sign(sighash, hasher=None)
            for key in self.funding.funding_privkeys_for_tx()
        ]
        tx.wit = CTxWitness(
            [
                CScriptWitness(
                    [
                        bytes(),
                        sigs[0] + bytes([script.SIGHASH_ALL]),
                        sigs[1] + bytes([script.SIGHASH_ALL]),
                        self.funding.redeemscript(),
                    ]
                )
            ]
        )
        return tx


ResolvableFunding = Union[Funding, Callable[["Runner", "Event", str], Funding]]


class Commit(Event):
    def __init__(
        self,
        opener: Side,
        local_keyset: KeySet,
        funding: ResolvableFunding,
        local_to_self_delay: ResolvableInt,
        remote_to_self_delay: ResolvableInt,
        local_amount: ResolvableInt,
        remote_amount: ResolvableInt,
        local_dust_limit: ResolvableInt,
        remote_dust_limit: ResolvableInt,
        feerate: ResolvableInt,
        local_features: ResolvableStr,
        remote_features: ResolvableStr,
    ):
        """Stashes a commitment transaction as 'Commit'.

        Note that local_to_self_delay is dictated by the remote side, and
        remote_to_self_delay is dicated by the local side!

        """
        super().__init__()
        self.funding = funding
        self.opener = opener
        self.local_keyset = local_keyset
        self.local_to_self_delay = local_to_self_delay
        self.remote_to_self_delay = remote_to_self_delay
        self.local_amount = local_amount
        self.remote_amount = remote_amount
        self.local_dust_limit = local_dust_limit
        self.remote_dust_limit = remote_dust_limit
        self.feerate = feerate
        # BOLT #9:
        # | 12/13 | `option_static_remotekey`        | Static key for remote output
        self.static_remotekey = negotiated(local_features, remote_features, [12])
        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #9:
        # | 20/21 | `option_anchor_outputs`          | Anchor outputs
        self.anchor_outputs = negotiated(local_features, remote_features, [20])

    def action(self, runner: Runner) -> bool:
        super().action(runner)

        static_remotekey = self.resolve_arg(
            "option_static_remotekey", runner, self.static_remotekey
        )
        anchor_outputs = self.resolve_arg(
            "option_anchor_outputs", runner, self.anchor_outputs
        )

        # BOLT-a12da24dd0102c170365124782b46d9710950ac1 #9:
        # | Bits  | Name                     | Description    | Context  | Dependencies
        # ...
        # | 20/21 | `option_anchor_outputs`  | Anchor outputs | IN       | `option_static_remotekey` |
        if anchor_outputs and not static_remotekey:
            raise EventError(
                self,
                "Cannot have option_anchor_outputs without option_static_remotekey",
            )

        commit = Commitment(
            local_keyset=self.local_keyset,
            remote_keyset=runner.get_keyset(),
            opener=self.opener,
            option_static_remotekey=static_remotekey,
            option_anchor_outputs=anchor_outputs,
            **self.resolve_args(
                runner,
                {
                    "funding": self.funding,
                    "local_to_self_delay": self.local_to_self_delay,
                    "remote_to_self_delay": self.remote_to_self_delay,
                    "local_amount": self.local_amount,
                    "remote_amount": self.remote_amount,
                    "local_dust_limit": self.local_dust_limit,
                    "remote_dust_limit": self.remote_dust_limit,
                    "feerate": self.feerate,
                },
            )
        )
        runner.add_stash("Commit", commit)
        return True


class UpdateCommit(Event):
    def __init__(
        self,
        new_htlcs: List[Tuple[HTLC, int]] = [],
        resolved_htlcs: List[HTLC] = [],
        failed_htlcs: List[HTLC] = [],
        new_feerate: Optional[ResolvableInt] = None,
    ):
        super().__init__()
        self.new_htlcs = new_htlcs
        self.resolved_htlcs = resolved_htlcs
        self.failed_htlcs = failed_htlcs
        self.new_feerate = new_feerate

    def action(self, runner: Runner) -> bool:
        super().action(runner)

        commit: Commitment = runner.get_stash(self, "Commit")
        for htlc, htlc_id in self.new_htlcs:
            if not commit.add_htlc(htlc, htlc_id):
                raise SpecFileError(self, "Already have htlc id {}".format(htlc_id))
        for htlc in self.resolved_htlcs:
            if not commit.del_htlc(htlc, xfer_funds=True):
                raise SpecFileError(self, "Cannot resolve missing htlc {}".format(htlc))
        for htlc in self.failed_htlcs:
            if not commit.del_htlc(htlc, xfer_funds=False):
                raise SpecFileError(self, "Cannot resolve missing htlc {}".format(htlc))

        if self.new_feerate is not None:
            commit.feerate = self.resolve_arg("feerate", runner, self.new_feerate)

        commit.inc_commitnum()
        return True


def test_commitment_number() -> None:
    # BOLT #3:
    # In the following:
    #  - *local* transactions are considered, which implies that all payments to *local* are delayed.
    #  - It's assumed that *local* is the funder.
    ...
    #     commitment_number: 42

    # BOLT #3:
    # INTERNAL: local_payment_basepoint_secret: 111111111111111111111111111111111111111111111111111111111111111101
    # ...
    # INTERNAL: remote_payment_basepoint_secret: 444444444444444444444444444444444444444444444444444444444444444401
    opener_pubkey = coincurve.PublicKey.from_secret(
        bytes.fromhex(
            "1111111111111111111111111111111111111111111111111111111111111111"
        )
    )
    non_opener_pubkey = coincurve.PublicKey.from_secret(
        bytes.fromhex(
            "4444444444444444444444444444444444444444444444444444444444444444"
        )
    )

    # BOLT #3: Here are the points used to derive the obscuring factor
    # for the commitment number:
    # local_payment_basepoint: 034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa
    # remote_payment_basepoint: 032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991
    # # obscured commitment number = 0x2bb038521914 ^ 42
    assert (
        opener_pubkey.format().hex()
        == "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa"
    )
    assert (
        non_opener_pubkey.format().hex()
        == "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991"
    )

    assert (
        Commitment.obscured_commit_num(opener_pubkey, non_opener_pubkey, 42)
        == 0x2BB038521914 ^ 42
    )


def revhex(h: str) -> str:
    return bytes(reversed(bytes.fromhex(h))).hex()


def test_simple_commitment() -> None:
    # We use '99' where the results shouldn't matter.
    c = Commitment(
        funding=Funding(
            funding_txid=revhex(
                "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
            ),
            funding_output_index=0,
            funding_amount=10000000,
            local_node_privkey="99",
            # BOLT #3:
            #     local_funding_privkey: 30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901
            local_funding_privkey="30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749",
            remote_node_privkey="99",
            # BOLT #3:
            # INTERNAL: remote_funding_privkey: 1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301
            remote_funding_privkey="1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13",
        ),
        opener=Side.local,
        # BOLT #3:
        # INTERNAL: local_payment_basepoint_secret: 111111111111111111111111111111111111111111111111111111111111111101
        local_keyset=KeySet(
            revocation_base_secret="99",
            payment_base_secret="1111111111111111111111111111111111111111111111111111111111111111",
            htlc_base_secret="1111111111111111111111111111111111111111111111111111111111111111",
            # BOLT #3:
            # INTERNAL: local_delayed_payment_basepoint_secret: 333333333333333333333333333333333333333333333333333333333333333301
            delayed_payment_base_secret="3333333333333333333333333333333333333333333333333333333333333333",
            shachain_seed="99" * 32,
        ),
        # BOLT #3:
        # INTERNAL: remote_revocation_basepoint_secret: 222222222222222222222222222222222222222222222222222222222222222201
        remote_keyset=KeySet(
            revocation_base_secret="2222222222222222222222222222222222222222222222222222222222222222",
            # BOLT #3:
            # INTERNAL: remote_payment_basepoint_secret: 444444444444444444444444444444444444444444444444444444444444444401
            payment_base_secret="4444444444444444444444444444444444444444444444444444444444444444",
            htlc_base_secret="4444444444444444444444444444444444444444444444444444444444444444",
            delayed_payment_base_secret="99",
            shachain_seed="99" * 32,
        ),
        local_to_self_delay=144,
        remote_to_self_delay=145,
        local_amount=7000000000,
        remote_amount=3000000000,
        local_dust_limit=546,
        remote_dust_limit=546,
        feerate=15000,
        option_static_remotekey=False,
        option_anchor_outputs=False,
    )

    # Make sure undefined field are not used.
    c.keyset[Side.local].revocation_base_secret = None
    c.keyset[Side.local].shachain_seed = None  # type: ignore
    c.keyset[Side.remote].delayed_payment_base_secret = None
    c.keyset[Side.remote].shachain_seed = None  # type: ignore

    # BOLT #3:
    # x_local_per_commitment_secret: 1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010001

    # This is not derived as expected, but defined :(
    c.keyset[Side.local].raw_per_commit_secret = lambda _: coincurve.PrivateKey(bytes.fromhex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"))  # type: ignore

    # BOLT #3:
    # commitment_number: 42
    c.commitnum = 42

    # BOLT #3:
    # name: simple commitment tx with no HTLCs
    # to_local_msat: 7000000000
    # to_remote_msat: 3000000000
    # local_feerate_per_kw: 15000
    # # base commitment transaction fee = 10860
    # # actual commitment transaction fee = 10860
    # # to_local amount 6989140 wscript 63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac
    # # to_remote amount 3000000 P2WPKH(0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b)
    # remote_signature = 3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0
    # # local_signature = 3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939
    # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
    # num_htlcs: 0

    fee = c._fee(0)
    assert fee == 10860

    out_redeemscript, sats = c._to_local_output(fee, Side.local)
    assert sats == 6989140
    assert out_redeemscript == bytes.fromhex(
        "63210212a140cd0c6539d07cd08dfe09984dec3251ea808b892efeac3ede9402bf2b1967029000b2752103fd5960528dc152014952efdb702a88f71e3c1653b2314431701ec77e57fde83c68ac"
    )

    out_redeemscript, sats = c._to_remote_output(fee, Side.local)
    assert sats == 3000000
    assert out_redeemscript == CScript(
        [
            script.OP_0,
            Hash160(
                bytes.fromhex(
                    "0394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b"
                )
            ),
        ]
    )

    # FIXME: We don't yet have a routine to fill the witness, so we cmp txid.
    tx, _ = c._unsigned_tx(Side.local)
    assert (
        tx.GetTxid()
        == CMutableTransaction.deserialize(
            bytes.fromhex(
                "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311054a56a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c383693901483045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220"
            )
        ).GetTxid()
    )

    assert c.remote_sig(tx) == Sig(
        "3045022100f51d2e566a70ba740fc5d8c0f07b9b93d2ed741c3c0860c613173de7d39e7968022041376d520e9c0e1ad52248ddf4b22e12be8763007df977253ef45a4ca3bdb7c0"
    )
    assert c.local_sig(tx) == Sig(
        "3044022051b75c73198c6deee1a875871c3961832909acd297c6b908d59e3319e5185a46022055c419379c5051a78d00dbbce11b5b664a0c22815fbcc6fcef6b1937c3836939"
    )

    htlcs = []
    # BOLT #3:
    #     htlc 0 direction: remote->local
    #     htlc 0 amount_msat: 1000000
    #     htlc 0 expiry: 500
    #     htlc 0 payment_preimage: 0000000000000000000000000000000000000000000000000000000000000000
    htlcs.append(HTLC(Side.remote, 1000000, "00" * 32, 500, "00" * 1366))
    # BOLT #3:
    #     htlc 1 direction: remote->local
    #     htlc 1 amount_msat: 2000000
    #     htlc 1 expiry: 501
    #     htlc 1 payment_preimage: 0101010101010101010101010101010101010101010101010101010101010101
    htlcs.append(HTLC(Side.remote, 2000000, "01" * 32, 501, "00" * 1366))
    # BOLT #3:
    #     htlc 2 direction: local->remote
    #     htlc 2 amount_msat: 2000000
    #     htlc 2 expiry: 502
    #     htlc 2 payment_preimage: 0202020202020202020202020202020202020202020202020202020202020202
    htlcs.append(HTLC(Side.local, 2000000, "02" * 32, 502, "00" * 1366))
    # BOLT #3:
    #     htlc 3 direction: local->remote
    #     htlc 3 amount_msat: 3000000
    #     htlc 3 expiry: 503
    #     htlc 3 payment_preimage: 0303030303030303030303030303030303030303030303030303030303030303
    htlcs.append(HTLC(Side.local, 3000000, "03" * 32, 503, "00" * 1366))
    # BOLT #3:
    #     htlc 4 direction: remote->local
    #     htlc 4 amount_msat: 4000000
    #     htlc 4 expiry: 504
    #     htlc 4 payment_preimage: 0404040404040404040404040404040404040404040404040404040404040404
    htlcs.append(HTLC(Side.remote, 4000000, "04" * 32, 504, "00" * 1366))

    # BOLT #3:
    #     name: commitment tx with all five HTLCs untrimmed (minimum feerate)
    #     to_local_msat: 6988000000
    #     to_remote_msat: 3000000000
    for i, h in enumerate(htlcs):
        c.add_htlc(h, i)

    c.amounts[Side.local] = 6988000000
    c.amounts[Side.remote] = 3000000000

    # feerate, localsig, remotesig, committx, [htlc sigs]
    table = [
        # BOLT #3:
        # local_feerate_per_kw: 0
        # ...
        # remote_signature = 304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b70606
        # # local_signature = 30440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f06
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 5
        # # signature for output 0 (HTLC 0)
        # remote_htlc_signature = 304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6
        # # signature for output 1 (HTLC 2)
        # remote_htlc_signature = 3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b
        # # signature for output 2 (HTLC 1)
        # remote_htlc_signature = 304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202
        # # signature for output 3 (HTLC 3)
        # remote_htlc_signature = 3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554
        # # signature for output 4 (HTLC 4)
        # remote_htlc_signature = 304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d
        (
            0,
            Sig(
                "30440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f06"
            ),
            Sig(
                "304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b70606"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e0a06a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220275b0c325a5e9355650dc30c0eccfbc7efb23987c24b556b9dfdd40effca18d202206caceb2c067836c51f296740c7ae807ffcbfbf1dd3a0d56b6de9a5b247985f060147304402204fd4928835db1ccdfc40f5c78ce9bd65249b16348df81f0c44328dcdefc97d630220194d3869c38bc732dd87d13d2958015e2fc16829e74cd4377f84d215c0b7060601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "304402206a6e59f18764a5bf8d4fa45eebc591566689441229c918b480fb2af8cc6a4aeb02205248f273be447684b33e3c8d1d85a8e0ca9fa0bae9ae33f0527ada9c162919a6"
                ),
                Sig(
                    "3045022100d5275b3619953cb0c3b5aa577f04bc512380e60fa551762ce3d7a1bb7401cff9022037237ab0dac3fe100cde094e82e2bed9ba0ed1bb40154b48e56aa70f259e608b"
                ),
                Sig(
                    "304402201b63ec807771baf4fdff523c644080de17f1da478989308ad13a58b51db91d360220568939d38c9ce295adba15665fa68f51d967e8ed14a007b751540a80b325f202"
                ),
                Sig(
                    "3045022100daee1808f9861b6c3ecd14f7b707eca02dd6bdfc714ba2f33bc8cdba507bb182022026654bf8863af77d74f51f4e0b62d461a019561bb12acb120d3f7195d148a554"
                ),
                Sig(
                    "304402207e0410e45454b0978a623f36a10626ef17b27d9ad44e2760f98cfa3efb37924f0220220bd8acd43ecaa916a80bd4f919c495a2c58982ce7c8625153f8596692a801d"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 647
        # ...
        # remote_signature = 3045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b
        # # local_signature = 304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d1163
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e09c6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040048304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d116301483045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 5
        # # signature for output 0 (HTLC 0)
        # remote_htlc_signature = 30440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab343740
        # # signature for output 1 (HTLC 2)
        # remote_htlc_signature = 304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b0
        # # signature for output 2 (HTLC 1)
        # remote_htlc_signature = 304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d833
        # # signature for output 3 (HTLC 3)
        # remote_htlc_signature = 30450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d
        # # signature for output 4 (HTLC 4)
        # remote_htlc_signature = 3045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f0
        (
            647,
            Sig(
                "304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d1163"
            ),
            Sig(
                "3045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8007e80300000000000022002052bfef0479d7b293c27e0f1eb294bea154c63a3294ef092c19af51409bce0e2ad007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110e09c6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040048304502210094bfd8f5572ac0157ec76a9551b6c5216a4538c07cd13a51af4a54cb26fa14320220768efce8ce6f4a5efac875142ff19237c011343670adf9c7ac69704a120d116301483045022100a5c01383d3ec646d97e40f44318d49def817fcd61a0ef18008a665b3e151785502203e648efddd5838981ef55ec954be69c4a652d021e6081a100d034de366815e9b01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "30440220385a5afe75632f50128cbb029ee95c80156b5b4744beddc729ad339c9ca432c802202ba5f48550cad3379ac75b9b4fedb86a35baa6947f16ba5037fb8b11ab343740"
                ),
                Sig(
                    "304402207ceb6678d4db33d2401fdc409959e57c16a6cb97a30261d9c61f29b8c58d34b90220084b4a17b4ca0e86f2d798b3698ca52de5621f2ce86f80bed79afa66874511b0"
                ),
                Sig(
                    "304402206a401b29a0dff0d18ec903502c13d83e7ec019450113f4a7655a4ce40d1f65ba0220217723a084e727b6ca0cc8b6c69c014a7e4a01fcdcba3e3993f462a3c574d833"
                ),
                Sig(
                    "30450221009b1c987ba599ee3bde1dbca776b85481d70a78b681a8d84206723e2795c7cac002207aac84ad910f8598c4d1c0ea2e3399cf6627a4e3e90131315bc9f038451ce39d"
                ),
                Sig(
                    "3045022100cc28030b59f0914f45b84caa983b6f8effa900c952310708c2b5b00781117022022027ba2ccdf94d03c6d48b327f183f6e28c8a214d089b9227f94ac4f85315274f0"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 648
        # ...
        # remote_signature = 3044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b057
        # # local_signature = 3045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431104e9d6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de01473044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b05701475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 4
        # # signature for output 0 (HTLC 2)
        # remote_htlc_signature = 3044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada8
        # # signature for output 1 (HTLC 1)
        # remote_htlc_signature = 3045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d4
        # # signature for output 2 (HTLC 3)
        # remote_htlc_signature = 3045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c2
        # # signature for output 3 (HTLC 4)
        # remote_htlc_signature = 3044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f
        (
            648,
            Sig(
                "3045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de"
            ),
            Sig(
                "3044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b057"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431104e9d6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a2270d5950c89ae0841233f6efea9c951898b301b2e89e0adbd2c687b9f32efa02207943d90f95b9610458e7c65a576e149750ff3accaacad004cd85e70b235e27de01473044022072714e2fbb93cdd1c42eb0828b4f2eff143f717d8f26e79d6ada4f0dcb681bbe02200911be4e5161dd6ebe59ff1c58e1997c4aea804f81db6b698821db6093d7b05701475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3044022062ef2e77591409d60d7817d9bb1e71d3c4a2931d1a6c7c8307422c84f001a251022022dad9726b0ae3fe92bda745a06f2c00f92342a186d84518588cf65f4dfaada8"
                ),
                Sig(
                    "3045022100e968cbbb5f402ed389fdc7f6cd2a80ed650bb42c79aeb2a5678444af94f6c78502204b47a1cb24ab5b0b6fe69fe9cfc7dba07b9dd0d8b95f372c1d9435146a88f8d4"
                ),
                Sig(
                    "3045022100aa91932e305292cf9969cc23502bbf6cef83a5df39c95ad04a707c4f4fed5c7702207099fc0f3a9bfe1e7683c0e9aa5e76c5432eb20693bf4cb182f04d383dc9c8c2"
                ),
                Sig(
                    "3044022035cac88040a5bba420b1c4257235d5015309113460bc33f2853cd81ca36e632402202fc94fd3e81e9d34a9d01782a0284f3044370d03d60f3fc041e2da088d2de58f"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 2069
        # ...
        # remote_signature = 3044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb4
        # # local_signature = 304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311077956a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea01473044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb401475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 4
        # # signature for output 0 (HTLC 2)
        # remote_htlc_signature = 3045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f992
        # # signature for output 1 (HTLC 1)
        # remote_htlc_signature = 3045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f4
        # # signature for output 2 (HTLC 3)
        # remote_htlc_signature = 3045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef18
        # # signature for output 3 (HTLC 4)
        # remote_htlc_signature = 30450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c
        (
            2069,
            Sig(
                "304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea"
            ),
            Sig(
                "3044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb4"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8006d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5d007000000000000220020748eba944fedc8827f6b06bc44678f93c0f9e6078b35c6331ed31e75f8ce0c2db80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311077956a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203ca8f31c6a47519f83255dc69f1894d9a6d7476a19f498d31eaf0cd3a85eeb63022026fd92dc752b33905c4c838c528b692a8ad4ced959990b5d5ee2ff940fa90eea01473044022001d55e488b8b035b2dd29d50b65b530923a416d47f377284145bc8767b1b6a75022019bb53ddfe1cefaf156f924777eaaf8fdca1810695a7d0a247ad2afba8232eb401475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3045022100d1cf354de41c1369336cf85b225ed033f1f8982a01be503668df756a7e668b66022001254144fb4d0eecc61908fccc3388891ba17c5d7a1a8c62bdd307e5a513f992"
                ),
                Sig(
                    "3045022100d065569dcb94f090345402736385efeb8ea265131804beac06dd84d15dd2d6880220664feb0b4b2eb985fadb6ec7dc58c9334ea88ce599a9be760554a2d4b3b5d9f4"
                ),
                Sig(
                    "3045022100d4e69d363de993684eae7b37853c40722a4c1b4a7b588ad7b5d8a9b5006137a102207a069c628170ee34be5612747051bdcc087466dbaa68d5756ea81c10155aef18"
                ),
                Sig(
                    "30450221008ec888e36e4a4b3dc2ed6b823319855b2ae03006ca6ae0d9aa7e24bfc1d6f07102203b0f78885472a67ff4fe5916c0bb669487d659527509516fc3a08e87a2cc0a7c"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 2070
        # ...
        # remote_signature = 3045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f37526
        # # local_signature = 30440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd0
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110da966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd001483045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f3752601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 3
        # # signature for output 0 (HTLC 2)
        # remote_htlc_signature = 3045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f891
        # # signature for output 1 (HTLC 3)
        # remote_htlc_signature = 3044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf6
        # # signature for output 2 (HTLC 4)
        # remote_htlc_signature = 3045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a4
        (
            2070,
            Sig(
                "30440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd0"
            ),
            Sig(
                "3045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f37526"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110da966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220443cb07f650aebbba14b8bc8d81e096712590f524c5991ac0ed3bbc8fd3bd0c7022028a635f548e3ca64b19b69b1ea00f05b22752f91daf0b6dab78e62ba52eb7fd001483045022100f2377f7a67b7fc7f4e2c0c9e3a7de935c32417f5668eda31ea1db401b7dc53030220415fdbc8e91d0f735e70c21952342742e25249b0d062d43efbfc564499f3752601475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3045022100eed143b1ee4bed5dc3cde40afa5db3e7354cbf9c44054b5f713f729356f08cf7022077161d171c2bbd9badf3c9934de65a4918de03bbac1450f715275f75b103f891"
                ),
                Sig(
                    "3044022071e9357619fd8d29a411dc053b326a5224c5d11268070e88ecb981b174747c7a02202b763ae29a9d0732fa8836dd8597439460b50472183f420021b768981b4f7cf6"
                ),
                Sig(
                    "3045022100c9458a4d2cbb741705577deb0a890e5cb90ee141be0400d3162e533727c9cb2102206edcf765c5dc5e5f9b976ea8149bf8607b5a0efb30691138e1231302b640d2a4"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 2194
        # ...
        # remote_signature = 3045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec86203953348
        # # local_signature = 304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f7061
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311040966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f706101483045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec8620395334801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 3
        # # signature for output 0 (HTLC 2)
        # remote_htlc_signature = 30450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf44
        # # signature for output 1 (HTLC 3)
        # remote_htlc_signature = 30440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d
        # # signature for output 2 (HTLC 4)
        # remote_htlc_signature = 3045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a
        (
            2194,
            Sig(
                "304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f7061"
            ),
            Sig(
                "3045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec86203953348"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8005d007000000000000220020403d394747cae42e98ff01734ad5c08f82ba123d3d9a620abda88989651e2ab5b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311040966a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b1b010c109c2ecbe7feb2d259b9c4126bd5dc99ee693c422ec0a5781fe161ba0220571fe4e2c649dea9c7aaf7e49b382962f6a3494963c97d80fef9a430ca3f706101483045022100d33c4e541aa1d255d41ea9a3b443b3b822ad8f7f86862638aac1f69f8f760577022007e2a18e6931ce3d3a804b1c78eda1de17dbe1fb7a95488c9a4ec8620395334801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "30450221009ed2f0a67f99e29c3c8cf45c08207b765980697781bb727fe0b1416de0e7622902206052684229bc171419ed290f4b615c943f819c0262414e43c5b91dcf72ddcf44"
                ),
                Sig(
                    "30440220155d3b90c67c33a8321996a9be5b82431b0c126613be751d400669da9d5c696702204318448bcd48824439d2c6a70be6e5747446be47ff45977cf41672bdc9b6b12d"
                ),
                Sig(
                    "3045022100a12a9a473ece548584aabdd051779025a5ed4077c4b7aa376ec7a0b1645e5a48022039490b333f53b5b3e2ddde1d809e492cba2b3e5fc3a436cd3ffb4cd3d500fa5a"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 2195
        # ...
        # remote_signature = 304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb7924298
        # # local_signature = 304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a5429
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110b8976a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a54290147304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb792429801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 2
        # # signature for output 0 (HTLC 3)
        # remote_htlc_signature = 3045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc
        # # signature for output 1 (HTLC 4)
        # remote_htlc_signature = 3045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92
        (
            2195,
            Sig(
                "304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a5429"
            ),
            Sig(
                "304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb7924298"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110b8976a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402203b12d44254244b8ff3bb4129b0920fd45120ab42f553d9976394b099d500c99e02205e95bb7a3164852ef0c48f9e0eaf145218f8e2c41251b231f03cbdc4f29a54290147304402205e2f76d4657fb732c0dfc820a18a7301e368f5799e06b7828007633741bda6df0220458009ae59d0c6246065c419359e05eb2a4b4ef4a1b310cc912db44eb792429801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3045022100a8a78fa1016a5c5c3704f2e8908715a3cef66723fb95f3132ec4d2d05cd84fb4022025ac49287b0861ec21932405f5600cbce94313dbde0e6c5d5af1b3366d8afbfc"
                ),
                Sig(
                    "3045022100e769cb156aa2f7515d126cef7a69968629620ce82afcaa9e210969de6850df4602200b16b3f3486a229a48aadde520dbee31ae340dbadaffae74fbb56681fef27b92"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 3702
        # ...
        # remote_signature = 3045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c1
        # # local_signature = 304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b0
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431106f916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b001483045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 2
        # # signature for output 0 (HTLC 3)
        # remote_htlc_signature = 3045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb
        # # signature for output 1 (HTLC 4)
        # remote_htlc_signature = 3045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9
        (
            3702,
            Sig(
                "304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b0"
            ),
            Sig(
                "3045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c1"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8004b80b000000000000220020c20b5d1f8584fd90443e7b7b720136174fa4b9333c261d04dbbd012635c0f419a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431106f916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402200e930a43c7951162dc15a2b7344f48091c74c70f7024e7116e900d8bcfba861c022066fa6cbda3929e21daa2e7e16a4b948db7e8919ef978402360d1095ffdaff7b001483045022100c1a3b0b60ca092ed5080121f26a74a20cec6bdee3f8e47bae973fcdceb3eda5502207d467a9873c939bf3aa758014ae67295fedbca52412633f7e5b2670fc7c381c101475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3045022100dfb73b4fe961b31a859b2bb1f4f15cabab9265016dd0272323dc6a9e85885c54022059a7b87c02861ee70662907f25ce11597d7b68d3399443a831ae40e777b76bdb"
                ),
                Sig(
                    "3045022100ea9dc2a7c3c3640334dab733bb4e036e32a3106dc707b24227874fa4f7da746802204d672f7ac0fe765931a8df10b81e53a3242dd32bd9dc9331eb4a596da87954e9"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 3703
        # ...
        # remote_signature = 30450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb0
        # # local_signature = 3044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110eb936a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506014830450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 1
        # # signature for output 0 (HTLC 4)
        # remote_htlc_signature = 3044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd
        (
            3703,
            Sig(
                "3044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506"
            ),
            Sig(
                "30450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb0"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110eb936a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400473044022047305531dd44391dce03ae20f8735005c615eb077a974edb0059ea1a311857d602202e0ed6972fbdd1e8cb542b06e0929bc41b2ddf236e04cb75edd56151f4197506014830450221008b7c191dd46893b67b628e618d2dc8e81169d38bade310181ab77d7c94c6675e02203b4dd131fd7c9deb299560983dcdc485545c98f989f7ae8180c28289f9e6bdb001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3044022044f65cf833afdcb9d18795ca93f7230005777662539815b8a601eeb3e57129a902206a4bf3e53392affbba52640627defa8dc8af61c958c9e827b2798ab45828abdd"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 4914
        # ...
        # remote_signature = 304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e
        # # local_signature = 304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe26
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110ae8f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe260147304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 1
        # # signature for output 0 (HTLC 4)
        # remote_htlc_signature = 3045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf
        (
            4914,
            Sig(
                "304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe26"
            ),
            Sig(
                "304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8003a00f0000000000002200208c48d15160397c9731df9bc3b236656efb6665fbfe92b4a6878e88a499f741c4c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110ae8f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402206a2679efa3c7aaffd2a447fd0df7aba8792858b589750f6a1203f9259173198a022008d52a0e77a99ab533c36206cb15ad7aeb2aa72b93d4b571e728cb5ec2f6fe260147304402206d6cb93969d39177a09d5d45b583f34966195b77c7e585cf47ac5cce0c90cefb022031d71ae4e33a4e80df7f981d696fbdee517337806a3c7138b7491e2cbb077a0e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (
                Sig(
                    "3045022100fcb38506bfa11c02874092a843d0cc0a8613c23b639832564a5f69020cb0f6ba02206508b9e91eaa001425c190c68ee5f887e1ad5b1b314002e74db9dbd9e42dbecf"
                ),
            ),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 4915
        # ...
        # remote_signature = 304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f8765552
        # # local_signature = 3045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b9
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110fa926a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b90147304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f876555201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 0
        (
            4915,
            Sig(
                "3045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b9"
            ),
            Sig(
                "304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f8765552"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8002c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de843110fa926a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100a012691ba6cea2f73fa8bac37750477e66363c6d28813b0bb6da77c8eb3fb0270220365e99c51304b0b1a6ab9ea1c8500db186693e39ec1ad5743ee231b0138384b90147304402200769ba89c7330dfa4feba447b6e322305f12ac7dac70ec6ba997ed7c1b598d0802204fe8d337e7fee781f9b7b1a06e580b22f4f79d740059560191d7db53f876555201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 9651180
        # ...
        # remote_signature = 3044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd
        # # local_signature = 30440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b9
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b800222020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ec0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311004004730440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b901473044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 0
        (
            9651180,
            Sig(
                "30440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b9"
            ),
            Sig(
                "3044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b800222020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80ec0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de84311004004730440220514f977bf7edc442de8ce43ace9686e5ebdc0f893033f13e40fb46c8b8c6e1f90220188006227d175f5c35da0b092c57bea82537aed89f7778204dc5bacf4f29f2b901473044022037f83ff00c8e5fb18ae1f918ffc24e54581775a20ff1ae719297ef066c71caa9022039c529cccd89ff6c5ed1db799614533844bd6d101da503761c45c713996e3bbd01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (),
        ),
        # BOLT #3:
        # local_feerate_per_kw: 9651181
        # ...
        # remote_signature = 3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e
        # # local_signature = 3044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b1
        # output commit_tx: 02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220
        # num_htlcs: 0
        (
            9651181,
            Sig(
                "3044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b1"
            ),
            Sig(
                "3044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e"
            ),
            "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b8001c0c62d0000000000160014ccf1af2f2aabee14bb40fa3851ab2301de8431100400473044022031a82b51bd014915fe68928d1abf4b9885353fb896cac10c3fdd88d7f9c7f2e00220716bda819641d2c63e65d3549b6120112e1aeaf1742eed94a471488e79e206b101473044022064901950be922e62cbe3f2ab93de2b99f37cff9fc473e73e394b27f88ef0731d02206d1dfa227527b4df44a07599289e207d6fd9cca60c0365682dcd3deaf739567e01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
            (),
        ),
    ]

    for feerate, localsig, remotesig, committx, htlc_sigs in table:
        c.feerate = feerate
        tx, _ = c._unsigned_tx(Side.local)
        assert c.local_sig(tx) == localsig
        assert c.remote_sig(tx) == remotesig
        # We don't (yet) generate witnesses, so compare txids.
        assert (
            tx.GetTxid()
            == CMutableTransaction.deserialize(bytes.fromhex(committx)).GetTxid()
        )

        sigs = c.htlc_sigs(Side.remote, Side.local)
        assert tuple(sigs) == htlc_sigs


def test_anchor_commitment() -> None:
    # This magically-formatted quote means that tools/check_quotes.py will validated it.
    boltquote = """
# BOLT-a12da24dd0102c170365124782b46d9710950ac1 #3:
# ```yaml
# [
#     {
#         "Name": "simple commitment tx with no HTLCs",
#         "LocalBalance": 7000000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 15000,
#         "HtlcDescs": [],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80044a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a508b6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221008266ac6db5ea71aac3c95d97b0e172ff596844851a3216eb88382a8dddfd33d2022050e240974cfd5d708708b4365574517c18e7ae535ef732a3484d43d0d82be9f701483045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100f89034eba16b2be0e5581f750a0a6309192b75cce0f202f0ee2b4ec0cc394850022076c65dc507fe42276152b7a3d90e961e678adbe966e916ecfe85e64d430e75f3"
#     },
#     {
#         "Name": "commitment tx with seven outputs untrimmed (maximum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 644,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "304402205912d91c58016f593d9e46fefcdb6f4125055c41a17b03101eaaa034b9028ab60220520d4d239c85c66e4c75c5b413620b62736e227659d7821b308e2b8ced3e728e",
#                 "ResolutionTxHex": "02000000000101b8cefef62ea66f5178b9361b2371be0759cbc8c689bcfa7a8e6746d497ec221a0200000000010000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402205912d91c58016f593d9e46fefcdb6f4125055c41a17b03101eaaa034b9028ab60220520d4d239c85c66e4c75c5b413620b62736e227659d7821b308e2b8ced3e728e834730440220473166a5adcca68550bab80403f410a726b5bd855030527e3fefa8c1e4b4fd7b02203b1dc91d8d69039473036cb5c34398b99e8eb90ae500c22130a557b62294b188012000000000000000000000000000000000000000000000000000000000000000008d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a914b8bcb07f6344b42ab04250c86a6e8b75d3fdbbc688527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f401b175ac6851b2756800000000"
#             },
#             {
#                 "RemoteSigHex": "3045022100c6b4113678039ee1e43a6cba5e3224ed2355ffc05e365a393afe8843dc9a76860220566d01fd52d65a89ba8595023884f9e8f2e9a310a6b9b85281c0bce06863430c",
#                 "ResolutionTxHex": "02000000000101b8cefef62ea66f5178b9361b2371be0759cbc8c689bcfa7a8e6746d497ec221a0300000000010000000124060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100c6b4113678039ee1e43a6cba5e3224ed2355ffc05e365a393afe8843dc9a76860220566d01fd52d65a89ba8595023884f9e8f2e9a310a6b9b85281c0bce06863430c83483045022100d0d86307ea55d5daa80f453ad6d64b78fe8a6504aac25407c73e8502c0702c1602206a0809a02aa00c8dc4a53d976bb05d4605d8bb0b7b26b973a5c4e2734d8afbb401008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000"
#             },
#             {
#                 "RemoteSigHex": "304402203c3a699fb80a38112aafd73d6e3a9b7d40bc2c3ed8b7fbc182a20f43b215172202204e71821b984d1af52c4b8e2cd4c572578c12a965866130c2345f61e4c2d3fef4",
#                 "ResolutionTxHex": "02000000000101b8cefef62ea66f5178b9361b2371be0759cbc8c689bcfa7a8e6746d497ec221a040000000001000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402203c3a699fb80a38112aafd73d6e3a9b7d40bc2c3ed8b7fbc182a20f43b215172202204e71821b984d1af52c4b8e2cd4c572578c12a965866130c2345f61e4c2d3fef48347304402205bcfa92f83c69289a412b0b6dd4f2a0fe0b0fc2d45bd74706e963257a09ea24902203783e47883e60b86240e877fcbf33d50b1742f65bc93b3162d1be26583b367ee012001010101010101010101010101010101010101010101010101010101010101018d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6851b2756800000000"
#             },
#             {
#                 "RemoteSigHex": "304402200f089bcd20f25475216307d32aa5b6c857419624bfba1da07335f51f6ba4645b02206ce0f7153edfba23b0d4b2afc26bb3157d404368cb8ea0ca7cf78590dcdd28cf",
#                 "ResolutionTxHex": "02000000000101b8cefef62ea66f5178b9361b2371be0759cbc8c689bcfa7a8e6746d497ec221a050000000001000000010c0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402200f089bcd20f25475216307d32aa5b6c857419624bfba1da07335f51f6ba4645b02206ce0f7153edfba23b0d4b2afc26bb3157d404368cb8ea0ca7cf78590dcdd28cf83483045022100e4516da08f72c7a4f7b2f37aa84a0feb54ae2cc5b73f0da378e81ae0ca8119bf02207751b2628d8e2f62b4b9abccda4866246c1bfcc82e3d416ad562fd212102c28f01008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "3045022100aa72cfaf0965020c73a12c77276c6411ca68c4de36ac1998adf86c917a899a43022060da0a159fecfe0bed37c3962d767f12f90e30fed8a8f34b1301775c21a2bd3a",
#                 "ResolutionTxHex": "02000000000101b8cefef62ea66f5178b9361b2371be0759cbc8c689bcfa7a8e6746d497ec221a06000000000100000001da0d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100aa72cfaf0965020c73a12c77276c6411ca68c4de36ac1998adf86c917a899a43022060da0a159fecfe0bed37c3962d767f12f90e30fed8a8f34b1301775c21a2bd3a8347304402203cd12065c2a42963c762e6b1a981e17695616ecb6f9fb33d8b0717cdd7ca0ee4022065500005c491c1dcf2fe9c4024f74b1c90785d572527055a491278f901143904012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80094a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994e80300000000000022002010f88bf09e56f14fb4543fd26e47b0db50ea5de9cf3fc46434792471082621aed0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837ead007000000000000220020fe0598d74fee2205cc3672e6e6647706b4f3099713b4661b62482c3addd04a5eb80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a4f996a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100ef82a405364bfc4007e63a7cc82925a513d79065bdbc216d60b6a4223a323f8a02200716730b8561f3c6d362eaf47f202e99fb30d0557b61b92b5f9134f8e2de368101483045022100e0106830467a558c07544a3de7715610c1147062e7d091deeebe8b5c661cda9402202ad049c1a6d04834317a78483f723c205c9f638d17222aafc620800cc1b6ae3501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100e0106830467a558c07544a3de7715610c1147062e7d091deeebe8b5c661cda9402202ad049c1a6d04834317a78483f723c205c9f638d17222aafc620800cc1b6ae35"
#     },
#     {
#         "Name": "commitment tx with six outputs untrimmed (minimum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 645,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "30440220446f9e5c375db6a61d6eeee8b59219a30a4a37372afc2670a1a2889c78e9b943022061895f6088fb48b490ab2140a4842c277b64bf25ff591625dd0356e0c96ab7a8",
#                 "ResolutionTxHex": "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b28534856132000200000000010000000123060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220446f9e5c375db6a61d6eeee8b59219a30a4a37372afc2670a1a2889c78e9b943022061895f6088fb48b490ab2140a4842c277b64bf25ff591625dd0356e0c96ab7a883483045022100c1621ba26a99c263fd885feff5fda5ca2cc73df080b3a49ecf15164ee244d2a5022037f4cc7fd4441af39a83a0e44c3b1db7d64a4c8080e8697f9e952f85421a34d801008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000"
#             },
#             {
#                 "RemoteSigHex": "3044022027a3ffcb8a007e3349d75382efbd4b3fb99fcbd479a18555e58697bd1278d5c402205c8303d46211c3ae8975fe84a0df08b4623119fecd03bc93b49d7f7a0c64c710",
#                 "ResolutionTxHex": "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b28534856132000300000000010000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500473044022027a3ffcb8a007e3349d75382efbd4b3fb99fcbd479a18555e58697bd1278d5c402205c8303d46211c3ae8975fe84a0df08b4623119fecd03bc93b49d7f7a0c64c71083483045022100b697aca55c6fb15e5348bb7387b584815fd15e8dd306afe0c477cb550d0c2d40022050b0f7e370f7604d2fec781fefe86715dbe95dff4dab88d628f509d62f854de1012001010101010101010101010101010101010101010101010101010101010101018d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6851b2756800000000"
#             },
#             {
#                 "RemoteSigHex": "30440220013975ae356e6daf22a86a29f21c4f35aca82ed8f731a1103c60c74f5ed1c5aa02200350d4e5455cdbcacb7ccf174db5bed8286019e509a113f6b4c5e606ee12c9d7",
#                 "ResolutionTxHex": "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b2853485613200040000000001000000010b0a0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220013975ae356e6daf22a86a29f21c4f35aca82ed8f731a1103c60c74f5ed1c5aa02200350d4e5455cdbcacb7ccf174db5bed8286019e509a113f6b4c5e606ee12c9d783483045022100e69a29f78779577830e73f327073c93168896f1b89432124b7846f5def9cd9cb02204433db3697e6ed7ac89574ca066a749640e0c9e114ac2e0ee4545741fcf7b7e901008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "304402205257017423644c7e831f30bc0c334eecfe66e9a6d2e92d157c5bece576b2be4f022047b21cf8e955e22b7471940563922d1a5852fb95459ca32905c7d46a19141664",
#                 "ResolutionTxHex": "02000000000101104f394af4c4fad78337f95e3e9f802f4c0d86ab231853af09b285348561320005000000000100000001d90d0000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402205257017423644c7e831f30bc0c334eecfe66e9a6d2e92d157c5bece576b2be4f022047b21cf8e955e22b7471940563922d1a5852fb95459ca32905c7d46a191416648347304402204f5de65a624e3f757adffb678bd887eb4e656538c5ea7044922f6ee3eed8a06202206ff6f7bfe73b565343cae76131ac658f1a9c60d3ca2343358cda60b9e35f94c8012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80084a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837ead007000000000000220020fe0598d74fee2205cc3672e6e6647706b4f3099713b4661b62482c3addd04a5eb80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994abc996a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100d57697c707b6f6d053febf24b98e8989f186eea42e37e9e91663ec2c70bb8f70022079b0715a472118f262f43016a674f59c015d9cafccec885968e76d9d9c5d005101473044022025d97466c8049e955a5afce28e322f4b34d2561118e52332fb400f9b908cc0a402205dc6fba3a0d67ee142c428c535580cd1f2ff42e2f89b47e0c8a01847caffc31201475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3044022025d97466c8049e955a5afce28e322f4b34d2561118e52332fb400f9b908cc0a402205dc6fba3a0d67ee142c428c535580cd1f2ff42e2f89b47e0c8a01847caffc312"
#     },
#     {
#         "Name": "commitment tx with six outputs untrimmed (maximum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 2060,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "30440220011f999016570bbab9f3125377d0f35096b4dbe155f97c20f71829ead2817d1602201f23f7e17f6928734601c5d8613431eed5c90aa41c3106e8c1cb02ce32aacb5d",
#                 "ResolutionTxHex": "02000000000101e7f364cf3a554b670767e723ef14b2af7a3eac70bd79dbde9256f384369c062d0200000000010000000175020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220011f999016570bbab9f3125377d0f35096b4dbe155f97c20f71829ead2817d1602201f23f7e17f6928734601c5d8613431eed5c90aa41c3106e8c1cb02ce32aacb5d83473044022017da96dfb0eb4061fa0162dc6fa6b2e07ecc5040ab5e6cb07be59838460b3e58022079371ffc95002cc1dc2891ec38198c9c25aca8164304fe114f1b55e2ffd1ddd501008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000"
#             },
#             {
#                 "RemoteSigHex": "304402202d2d9681409b0a0987bd4a268ffeb112df85c4c988ac2a3a2475cb00a61912c302206aa4f4d1388b7d3282bc847871af3cca30766cc8f1064e3a41ec7e82221e10f7",
#                 "ResolutionTxHex": "02000000000101e7f364cf3a554b670767e723ef14b2af7a3eac70bd79dbde9256f384369c062d0300000000010000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402202d2d9681409b0a0987bd4a268ffeb112df85c4c988ac2a3a2475cb00a61912c302206aa4f4d1388b7d3282bc847871af3cca30766cc8f1064e3a41ec7e82221e10f78347304402206426d67911aa6ff9b1cb147b093f3f65a37831a86d7c741d999afc0666e1773d022000bb71821650c70ea58d9bcdd03af736c41a5a8159d436c3ee0408a07394dcce012001010101010101010101010101010101010101010101010101010101010101018d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a9144b6b2e5444c2639cc0fb7bcea5afba3f3cdce23988527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f501b175ac6851b2756800000000"
#             },
#             {
#                 "RemoteSigHex": "3045022100f51cdaa525b7d4304548c642bb7945215eb5ae7d32874517cde67ca23ab0a12202206286d59e4b19926c6ac844be6f3ab8149a1ddb9c70f5026b7e83e40a6c08e6e1",
#                 "ResolutionTxHex": "02000000000101e7f364cf3a554b670767e723ef14b2af7a3eac70bd79dbde9256f384369c062d040000000001000000015d060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100f51cdaa525b7d4304548c642bb7945215eb5ae7d32874517cde67ca23ab0a12202206286d59e4b19926c6ac844be6f3ab8149a1ddb9c70f5026b7e83e40a6c08e6e18348304502210091b16b1ac63b867e7a5ca0344f7b2aa1cdd49d4b72eac86a31e7ec6f069e20640220402bfb571ba3a9c49e3b0061c89303453803d0241059d899222aaac4799b507601008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "304402202f058d99cb5a54f90773d43ba4e7a0089efd9f8269ef2da1b85d48a3e230555402205acc4bd6561830867d45cd7b84bba9fa35ad2b345016471c1737142bc99782c4",
#                 "ResolutionTxHex": "02000000000101e7f364cf3a554b670767e723ef14b2af7a3eac70bd79dbde9256f384369c062d05000000000100000001f2090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402202f058d99cb5a54f90773d43ba4e7a0089efd9f8269ef2da1b85d48a3e230555402205acc4bd6561830867d45cd7b84bba9fa35ad2b345016471c1737142bc99782c48347304402202913f9cacea54efd2316cffa91219def9e0e111977216c1e76e9da80befab14f022000a9a69e8f37ebe4a39107ab50fab0dde537334588f8f412bbaca57b179b87a6012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80084a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837ead007000000000000220020fe0598d74fee2205cc3672e6e6647706b4f3099713b4661b62482c3addd04a5eb80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994ab88f6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402201ce37a44b95213358c20f44404d6db7a6083bea6f58de6c46547ae41a47c9f8202206db1d45be41373e92f90d346381febbea8c78671b28c153e30ad1db3441a94970147304402206208aeb34e404bd052ce3f298dfa832891c9d42caec99fe2a0d2832e9690b94302201b034bfcc6fa9faec667a9b7cbfe0b8d85e954aa239b66277887b5088aff08c301475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "304402206208aeb34e404bd052ce3f298dfa832891c9d42caec99fe2a0d2832e9690b94302201b034bfcc6fa9faec667a9b7cbfe0b8d85e954aa239b66277887b5088aff08c3"
#     },
#     {
#         "Name": "commitment tx with five outputs untrimmed (minimum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 2061,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "3045022100e10744f572a2cd1d787c969e894b792afaed21217ee0480df0112d2fa3ef96ea02202af4f66eb6beebc36d8e98719ed6b4be1b181659fcb561fc491d8cfebff3aa85",
#                 "ResolutionTxHex": "02000000000101cf32732fe2d1387ed4e2335f69ddd3c0f337dabc03269e742531f89d35e161d10200000000010000000174020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e10744f572a2cd1d787c969e894b792afaed21217ee0480df0112d2fa3ef96ea02202af4f66eb6beebc36d8e98719ed6b4be1b181659fcb561fc491d8cfebff3aa8583483045022100c3dc3ea50a0ca20e350f97b50c52c5514717cfa36cb9600918caac5cb556842b022049af018d676dde0c8e28ecf325f3ff5c1594261c4f7511d501f9d62d0594d2a201008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000"
#             },
#             {
#                 "RemoteSigHex": "3045022100e1f51fb72fec604b029b348a3bb6363454e1869f5b1e24fd736f860c8039f8070220030a2c90186437d8c9b47d4897798c024521b1274991c4cdc125970b346094b1",
#                 "ResolutionTxHex": "02000000000101cf32732fe2d1387ed4e2335f69ddd3c0f337dabc03269e742531f89d35e161d1030000000001000000015c060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100e1f51fb72fec604b029b348a3bb6363454e1869f5b1e24fd736f860c8039f8070220030a2c90186437d8c9b47d4897798c024521b1274991c4cdc125970b346094b183483045022100ec7ade6037e531629f24390ca9713782a04d648065d17fbe6b015981cdb296c202202d61049a6ecba2fb5314f3edcda2361cad187a89bea6e5d15185354d80c0c08501008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "304402203479f81a1d83c516957679dc98bf91d35deada967739a8e3869e3e8db08246130220053c8e154b97e3019048dcec3d51bfaf396f36861fbda6d33f0e2a57155c8b9f",
#                 "ResolutionTxHex": "02000000000101cf32732fe2d1387ed4e2335f69ddd3c0f337dabc03269e742531f89d35e161d104000000000100000001f1090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402203479f81a1d83c516957679dc98bf91d35deada967739a8e3869e3e8db08246130220053c8e154b97e3019048dcec3d51bfaf396f36861fbda6d33f0e2a57155c8b9f83483045022100a558eb5caa04e35a4417c1f0123ac12eec5f6badee28f5764dc6b69486e594f802201589b12784e242f205832d2d032149bd4e79433ec304c05394241fc7dcba5a71012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80074a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837eab80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a18916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e040047304402204ab07c659412dd2cd6043b1ad811ab215e901b6b5653e08cb3d2fe63d3e3dc57022031c7b3d130f9380ef09581f4f5a15cb6f359a2e0a597146b96c3533a26d6f4cd01483045022100a2faf2ad7e323b2a82e07dc40b6847207ca6ad7b089f2c21dea9a4d37e52d59d02204c9480ce0358eb51d92a4342355a97e272e3cc45f86c612a76a3fe32fc3c4cb401475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100a2faf2ad7e323b2a82e07dc40b6847207ca6ad7b089f2c21dea9a4d37e52d59d02204c9480ce0358eb51d92a4342355a97e272e3cc45f86c612a76a3fe32fc3c4cb4"
#     },
#     {
#         "Name": "commitment tx with five outputs untrimmed (maximum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 2184,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "304402202e03ba1390998b3487e9a7fefcb66814c09abea0ef1bcc915dbaefbcf310569a02206bd10493a105ac69048e9bcedcb8e3301ef81b55018d911a4afd297297f98d30",
#                 "ResolutionTxHex": "020000000001015b03043e20eb467029305a22af4c3b915e793743f192c5d225cf1d3c6e8c03010200000000010000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402202e03ba1390998b3487e9a7fefcb66814c09abea0ef1bcc915dbaefbcf310569a02206bd10493a105ac69048e9bcedcb8e3301ef81b55018d911a4afd297297f98d308347304402200c3952ca04be0c60dcc0b7873a0829f560607524943554ae4a27d8d967166199022021a68657b88e22f9bf9ac6065be412685aff643d17049f04f2e99e86197dabb101008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a914b43e1b38138a41b37f7cd9a1d274bc63e3a9b5d188ac6851b27568f6010000"
#             },
#             {
#                 "RemoteSigHex": "304402201f8a6adda2403bc400c919ea69d72d315337291e00d02cde085ea32953dbc50002202d65230da98df7af8ebefd2b60b457d0945232988ee2d7460a94a77d414a9acc",
#                 "ResolutionTxHex": "020000000001015b03043e20eb467029305a22af4c3b915e793743f192c5d225cf1d3c6e8c0301030000000001000000010a060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402201f8a6adda2403bc400c919ea69d72d315337291e00d02cde085ea32953dbc50002202d65230da98df7af8ebefd2b60b457d0945232988ee2d7460a94a77d414a9acc83483045022100ea69c9273b8914ac62b5b7082d6ac1da2b7b065ebf2ef3cd6403f5305ce3f26802203d98736ea97638895a898dfcc5ee0d0c55eb496b3964df0bb25d223688ea8b8701008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "3045022100ea6e4c9b8f56dd9cf5799492a201cdd65b8bc9bc089c3cff34107896ae313f90022034760f7760975cc68e8917a7f62894e25583da7be11af557c4fc402661d0cbf8",
#                 "ResolutionTxHex": "020000000001015b03043e20eb467029305a22af4c3b915e793743f192c5d225cf1d3c6e8c0301040000000001000000019b090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100ea6e4c9b8f56dd9cf5799492a201cdd65b8bc9bc089c3cff34107896ae313f90022034760f7760975cc68e8917a7f62894e25583da7be11af557c4fc402661d0cbf8834730440220717012f2f7ef6cac590aaf66c2109132c93ffba245959ac62d82e394ba80191302203f00fd9cb37c92c6b0ad4b33e62c3e55b04e5c2cfa0adcca5a9bc49774eeca8a012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80074a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994d0070000000000002200203e68115ae0b15b8de75b6c6bc9af5ac9f01391544e0870dae443a1e8fe7837eab80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a4f906a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220555c05261f72c5b4702d5c83a608630822b473048724b08640d6e75e345094250220448950b74a96a56963928ba5db8b457661a742c855e69d239b3b6ab73de307a301473044022013d326f80ff7607cf366c823fcbbcb7a2b10322484825f151e6c4c756af24b8f02201ba05b9d8beb7cea2947f9f4d9e03f90435e93db2dd48b32eb9ca3f3dd042c7901475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3044022013d326f80ff7607cf366c823fcbbcb7a2b10322484825f151e6c4c756af24b8f02201ba05b9d8beb7cea2947f9f4d9e03f90435e93db2dd48b32eb9ca3f3dd042c79"
#     },
#     {
#         "Name": "commitment tx with four outputs untrimmed (minimum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 2185,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "304502210094480e38afb41d10fae299224872f19c53abe23c7033a1c0642c48713e7863a10220726dd9456407682667dc4bd9c66975acb3744961770b5002f7eb9c0df9ef2f3e",
#                 "ResolutionTxHex": "02000000000101ac13a7715f80b8e52dda43c6929cade5521bdced3a405da02b443f1ffb1e33cc0200000000010000000109060000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050048304502210094480e38afb41d10fae299224872f19c53abe23c7033a1c0642c48713e7863a10220726dd9456407682667dc4bd9c66975acb3744961770b5002f7eb9c0df9ef2f3e8347304402203148dac61513dc0361738cba30cb341a1e580f8acd5ab0149bf65bd670688cf002207e5d9a0fcbbea2c263bc714fa9e9c44d7f582ea447f366119fc614a23de32f1f01008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "304402200dbde868dbc20c6a2433fe8979ba5e3f966b1c2d1aeb615f1c42e9c938b3495402202eec5f663c8b601c2061c1453d35de22597c137d1907a2feaf714d551035cb6e",
#                 "ResolutionTxHex": "02000000000101ac13a7715f80b8e52dda43c6929cade5521bdced3a405da02b443f1ffb1e33cc030000000001000000019a090000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402200dbde868dbc20c6a2433fe8979ba5e3f966b1c2d1aeb615f1c42e9c938b3495402202eec5f663c8b601c2061c1453d35de22597c137d1907a2feaf714d551035cb6e83483045022100b896bded41d7feac7af25c19e35c53037c53b50e73cfd01eb4ba139c7fdf231602203a3be049d3d89396c4dc766d82ce31e237da8bc3a93e2c7d35992d1932d9cfeb012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80064a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994b80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994ac5916a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100cd8479cfe1edb1e5a1d487391e0451a469c7171e51e680183f19eb4321f20e9b02204eab7d5a6384b1b08e03baa6e4d9748dfd2b5ab2bae7e39604a0d0055bbffdd501473044022040f63a16148cf35c8d3d41827f5ae7f7c3746885bb64d4d1b895892a83812b3e02202fcf95c2bf02c466163b3fa3ced6a24926fbb4035095a96842ef516e86ba54c001475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3044022040f63a16148cf35c8d3d41827f5ae7f7c3746885bb64d4d1b895892a83812b3e02202fcf95c2bf02c466163b3fa3ced6a24926fbb4035095a96842ef516e86ba54c0"
#     },
#     {
#         "Name": "commitment tx with four outputs untrimmed (maximum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 3686,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "304402202cfe6618926ca9f1574f8c4659b425e9790b4677ba2248d77901290806130ffe02204ab37bb0287abcdb8b750b018d41a09effe37cb65ff801fa70d3f1a416599841",
#                 "ResolutionTxHex": "020000000001012c32e55722e4b96324d8e5b398d583a20780b25202816adc32dc3157dee731c90200000000010000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e050047304402202cfe6618926ca9f1574f8c4659b425e9790b4677ba2248d77901290806130ffe02204ab37bb0287abcdb8b750b018d41a09effe37cb65ff801fa70d3f1a41659984183473044022030b318139715e3b34f19be852cc01c1c0e1599e8b926a73df2bfb70dd186ddee022062a2b7398aed9f563b4014da04a1a99debd0ff663ceece68a547df5982dc2d7201008876a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c820120876475527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae67a9148a486ff2e31d6158bf39e2608864d63fefd09d5b88ac6851b27568f7010000"
#             },
#             {
#                 "RemoteSigHex": "30440220687af8544d335376620a6f4b5412bfd0da48de047c1785674f26e669d4a3ff82022058591c1e3a6c50017427d38a8f756eb685bdab88ec73838eed3530048861f9d5",
#                 "ResolutionTxHex": "020000000001012c32e55722e4b96324d8e5b398d583a20780b25202816adc32dc3157dee731c90300000000010000000176050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004730440220687af8544d335376620a6f4b5412bfd0da48de047c1785674f26e669d4a3ff82022058591c1e3a6c50017427d38a8f756eb685bdab88ec73838eed3530048861f9d5834730440220109f1a62b5a13d28d5b7634dd7693b1d5994eb404c4bb4a9a80aa540d3984d170220307251107ff8499a23e99abce7dda4f1c707c98abddb9405a83de0081cde8ace012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80064a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994b80b000000000000220020f96d0334feb64a4f40eb272031d07afcb038db56aa57446d60308c9f8ccadef9a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a29896a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100c268496aad5c3f97f25cf41c1ba5483a12982de29b222051b6de3daa2229413b02207f3c82d77a2c14f0096ed9bb4c34649483bb20fa71f819f71af44de6593e8bb2014730440220784485cf7a0ad7979daf2c858ffdaf5298d0020cea7aea466843e7948223bd9902206031b81d25e02a178c64e62f843577fdcdfc7a1decbbfb54cd895de692df85ca01475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "30440220784485cf7a0ad7979daf2c858ffdaf5298d0020cea7aea466843e7948223bd9902206031b81d25e02a178c64e62f843577fdcdfc7a1decbbfb54cd895de692df85ca"
#     },
#     {
#         "Name": "commitment tx with three outputs untrimmed (minimum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 3687,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "3045022100b287bb8e079a62dcb3aaa8b6c67c0f434a87ebf64ab0bcfb2fc14b55576b859f02206d37c2eb5fd04cfc9eb0534c76a28a98da251b84a931377cce307af39dfaed74",
#                 "ResolutionTxHex": "02000000000101542562b326c08e3a076d9cfca2be175041366591da334d8d513ff1686fd95a600200000000010000000175050000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0500483045022100b287bb8e079a62dcb3aaa8b6c67c0f434a87ebf64ab0bcfb2fc14b55576b859f02206d37c2eb5fd04cfc9eb0534c76a28a98da251b84a931377cce307af39dfaed7483483045022100a497c64faea286ec4221f48628086dc6403fd7b60a23c4176e8ebbca15ae70dc0220754e20e968e96cf6421fd2a672c8c26d3bc6e19218cfc8fc2aa51fce026c14b1012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80054a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994aa28b6a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e0400483045022100c970799bcb33f43179eb43b3378a0a61991cf2923f69b36ef12548c3df0e6d500220413dc27d2e39ee583093adfcb7799be680141738babb31cc7b0669a777a31f5d01483045022100ad6c71569856b2d7ff42e838b4abe74a713426b37f22fa667a195a4c88908c6902202b37272b02a42dc6d9f4f82cab3eaf84ac882d9ed762859e1e75455c2c22837701475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100ad6c71569856b2d7ff42e838b4abe74a713426b37f22fa667a195a4c88908c6902202b37272b02a42dc6d9f4f82cab3eaf84ac882d9ed762859e1e75455c2c228377"
#     },
#     {
#         "Name": "commitment tx with three outputs untrimmed (maximum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 4893,
#         "HtlcDescs": [
#             {
#                 "RemoteSigHex": "30450221008db80f8531104820b3e894492b4463f074f965b542e1b5c153ddfb108a5ea642022030b203d857a2b3581c2087a7bf17c95d04fadc1c6cdae88c620477f2dccb1ee4",
#                 "ResolutionTxHex": "02000000000101d515a15e9175fd315bb8d4e768f28684801a9e5a9acdfeba34f7b3b3b3a9ba1d0200000000010000000122020000000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e05004830450221008db80f8531104820b3e894492b4463f074f965b542e1b5c153ddfb108a5ea642022030b203d857a2b3581c2087a7bf17c95d04fadc1c6cdae88c620477f2dccb1ee483483045022100e5fbae857c47dbfc050a05924bd449fc9804798bd6442002c578437dc34450810220296589bc387645512345299e307116aaac4ce9fc752abcd1936b802d03526312012004040404040404040404040404040404040404040404040404040404040404048d76a91414011f7254d96b819c76986c277d115efce6f7b58763ac67210394854aa6eab5b2a8122cc726e9dded053a2184d88256816826d6231c068d4a5b7c8201208763a91418bc1a114ccf9c052d3d23e28d3b0a9d1227434288527c21030d417a46946384f88d5f3337267c5e579765875dc4daca813e21734b140639e752ae677502f801b175ac6851b2756800000000"
#             }
#         ],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80054a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994a00f000000000000220020ce6e751274836ff59622a0d1e07f8831d80bd6730bd48581398bfadd2bb8da9ac0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994a87856a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004730440220086288faceab47461eb2d808e9e9b0cb3ffc24a03c2f18db7198247d38f10e58022031d1c2782a58c8c6ce187d0019eb47a83babdf3040e2caff299ab48f7e12b1fa01483045022100a8771147109e4d3f44a5976c3c3de98732bbb77308d21444dbe0d76faf06480e02200b4e916e850c3d1f918de87bbbbb07843ffea1d4658dfe060b6f9ccd96d34be801475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100a8771147109e4d3f44a5976c3c3de98732bbb77308d21444dbe0d76faf06480e02200b4e916e850c3d1f918de87bbbbb07843ffea1d4658dfe060b6f9ccd96d34be8"
#     },
#     {
#         "Name": "commitment tx with two outputs untrimmed (minimum feerate)",
#         "LocalBalance": 6988000000,
#         "RemoteBalance": 3000000000,
#         "FeePerKw": 4894,
#         "HtlcDescs": [],
#         "ExpectedCommitmentTxHex": "02000000000101bef67e4e2fb9ddeeb3461973cd4c62abb35050b1add772995b820b584a488489000000000038b02b80044a010000000000002200202b1b5854183c12d3316565972c4668929d314d81c5dcdbb21cb45fe8a9a8114f4a01000000000000220020e9e86e4823faa62e222ebc858a226636856158f07e69898da3b0d1af0ddb3994c0c62d0000000000220020f3394e1e619b0eca1f91be2fb5ab4dfc59ba5b84ebe014ad1d43a564d012994ad0886a00000000002200204adb4e2f00643db396dd120d4e7dc17625f5f2c11a40d857accc862d6b7dd80e04004830450221009f16ac85d232e4eddb3fcd750a68ebf0b58e3356eaada45d3513ede7e817bf4c02207c2b043b4e5f971261975406cb955219fa56bffe5d834a833694b5abc1ce4cfd01483045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b9501475221023da092f6980e58d2c037173180e9a465476026ee50f96695963e8efe436f54eb21030e9f7b623d2ccc7c9bd44d66d5ce21ce504c0acf6385a132cec6d3c39fa711c152ae3e195220",
#         "RemoteSigHex": "3045022100e784a66b1588575801e237d35e510fd92a81ae3a4a2a1b90c031ad803d07b3f3022021bc5f16501f167607d63b681442da193eb0a76b4b7fd25c2ed4f8b28fd35b95"
#     }
# ]
#```
"""
    # Skip over yaml start and end marker, remove '#'
    yamlstr = "\n".join([line[1:] for line in boltquote.splitlines()[3:-1]])
    tests = json.loads(yamlstr)

    # We use '99' where the results shouldn't matter.
    c = Commitment(
        funding=Funding(
            funding_txid=revhex(
                "8984484a580b825b9972d7adb15050b3ab624ccd731946b3eeddb92f4e7ef6be"
            ),
            funding_output_index=0,
            funding_amount=10000000,
            local_node_privkey="99",
            # BOLT #3:
            #     local_funding_privkey: 30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f374901
            local_funding_privkey="30ff4956bbdd3222d44cc5e8a1261dab1e07957bdac5ae88fe3261ef321f3749",
            remote_node_privkey="99",
            # BOLT #3:
            # INTERNAL: remote_funding_privkey: 1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e1301
            remote_funding_privkey="1552dfba4f6cf29a62a0af13c8d6981d36d0ef8d61ba10fb0fe90da7634d7e13",
        ),
        opener=Side.local,
        # BOLT #3:
        # INTERNAL: local_payment_basepoint_secret: 111111111111111111111111111111111111111111111111111111111111111101
        local_keyset=KeySet(
            revocation_base_secret="99",
            payment_base_secret="1111111111111111111111111111111111111111111111111111111111111111",
            htlc_base_secret="1111111111111111111111111111111111111111111111111111111111111111",
            # BOLT #3:
            # INTERNAL: local_delayed_payment_basepoint_secret: 333333333333333333333333333333333333333333333333333333333333333301
            delayed_payment_base_secret="3333333333333333333333333333333333333333333333333333333333333333",
            shachain_seed="99" * 32,
        ),
        # BOLT #3:
        # INTERNAL: remote_revocation_basepoint_secret: 222222222222222222222222222222222222222222222222222222222222222201
        remote_keyset=KeySet(
            revocation_base_secret="2222222222222222222222222222222222222222222222222222222222222222",
            # BOLT #3:
            # INTERNAL: remote_payment_basepoint_secret: 444444444444444444444444444444444444444444444444444444444444444401
            payment_base_secret="4444444444444444444444444444444444444444444444444444444444444444",
            htlc_base_secret="4444444444444444444444444444444444444444444444444444444444444444",
            delayed_payment_base_secret="99",
            shachain_seed="99" * 32,
        ),
        local_to_self_delay=144,
        remote_to_self_delay=145,
        local_amount=7000000000,
        remote_amount=3000000000,
        local_dust_limit=546,
        remote_dust_limit=546,
        feerate=15000,
        option_static_remotekey=True,
        option_anchor_outputs=True,
    )

    # Make sure undefined field are not used.
    c.keyset[Side.local].revocation_base_secret = None
    c.keyset[Side.local].shachain_seed = None  # type: ignore
    c.keyset[Side.remote].delayed_payment_base_secret = None
    c.keyset[Side.remote].shachain_seed = None  # type: ignore

    # BOLT #3:
    # x_local_per_commitment_secret: 1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908070605040302010001

    # This is not derived as expected, but defined :(
    c.keyset[Side.local].raw_per_commit_secret = lambda _: coincurve.PrivateKey(bytes.fromhex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100"))  # type: ignore

    # BOLT #3:
    # commitment_number: 42
    c.commitnum = 42

    # First test is different: it has no HTLCs.
    c.feerate = tests[0]["FeePerKw"]
    tx, _ = c._unsigned_tx(Side.local)
    # We don't (yet) generate witnesses, so compare txids.
    assert (
        tx.GetTxid()
        == CMutableTransaction.deserialize(
            bytes.fromhex(tests[0]["ExpectedCommitmentTxHex"])
        ).GetTxid()
    )
    assert c.remote_sig(tx) == Sig(tests[0]["RemoteSigHex"])

    # Add HTLCs for remaining tests.
    htlcs = []
    # BOLT #3:
    #     htlc 0 direction: remote->local
    #     htlc 0 amount_msat: 1000000
    #     htlc 0 expiry: 500
    #     htlc 0 payment_preimage: 0000000000000000000000000000000000000000000000000000000000000000
    htlcs.append(HTLC(Side.remote, 1000000, "00" * 32, 500, "00" * 1366))
    # BOLT #3:
    #     htlc 1 direction: remote->local
    #     htlc 1 amount_msat: 2000000
    #     htlc 1 expiry: 501
    #     htlc 1 payment_preimage: 0101010101010101010101010101010101010101010101010101010101010101
    htlcs.append(HTLC(Side.remote, 2000000, "01" * 32, 501, "00" * 1366))
    # BOLT #3:
    #     htlc 2 direction: local->remote
    #     htlc 2 amount_msat: 2000000
    #     htlc 2 expiry: 502
    #     htlc 2 payment_preimage: 0202020202020202020202020202020202020202020202020202020202020202
    htlcs.append(HTLC(Side.local, 2000000, "02" * 32, 502, "00" * 1366))
    # BOLT #3:
    #     htlc 3 direction: local->remote
    #     htlc 3 amount_msat: 3000000
    #     htlc 3 expiry: 503
    #     htlc 3 payment_preimage: 0303030303030303030303030303030303030303030303030303030303030303
    htlcs.append(HTLC(Side.local, 3000000, "03" * 32, 503, "00" * 1366))
    # BOLT #3:
    #     htlc 4 direction: remote->local
    #     htlc 4 amount_msat: 4000000
    #     htlc 4 expiry: 504
    #     htlc 4 payment_preimage: 0404040404040404040404040404040404040404040404040404040404040404
    htlcs.append(HTLC(Side.remote, 4000000, "04" * 32, 504, "00" * 1366))

    for i, h in enumerate(htlcs):
        c.add_htlc(h, i)

    for test in tests[1:]:
        c.amounts[Side.local] = test["LocalBalance"]
        c.amounts[Side.remote] = test["RemoteBalance"]
        c.feerate = test["FeePerKw"]
        tx, _ = c._unsigned_tx(Side.local)
        # We don't (yet) generate witnesses, so compare txids.
        assert (
            tx.GetTxid()
            == CMutableTransaction.deserialize(
                bytes.fromhex(test["ExpectedCommitmentTxHex"])
            ).GetTxid()
        )
        assert c.remote_sig(tx) == Sig(test["RemoteSigHex"])

        # This is tx, redeemscript, sats for each HTLC.
        htlc_info = c.htlc_txs(Side.local)
        sigs = c.htlc_sigs(Side.remote, Side.local)
        assert len(htlc_info) == len(sigs)
        assert len(sigs) == len(test["HtlcDescs"])

        for sig, htlc, desc in zip(sigs, htlc_info, test["HtlcDescs"]):
            assert (
                htlc[0].GetTxid()
                == CMutableTransaction.deserialize(
                    bytes.fromhex(desc["ResolutionTxHex"])
                ).GetTxid()
            )
            assert sig == Sig(desc["RemoteSigHex"])
