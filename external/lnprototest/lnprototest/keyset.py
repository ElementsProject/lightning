#! /usr/bin/python3
# FIXME: clean this up for use as pyln.proto.tx
import coincurve
import hashlib
from .utils import privkey_expand, check_hex


class KeySet(object):
    def __init__(
        self,
        revocation_base_secret: str,
        payment_base_secret: str,
        htlc_base_secret: str,
        delayed_payment_base_secret: str,
        shachain_seed: str,
    ):
        self.revocation_base_secret = privkey_expand(revocation_base_secret)
        self.payment_base_secret = privkey_expand(payment_base_secret)
        self.htlc_base_secret = privkey_expand(htlc_base_secret)
        self.delayed_payment_base_secret = privkey_expand(delayed_payment_base_secret)
        self.shachain_seed = bytes.fromhex(check_hex(shachain_seed, 64))

    def raw_payment_basepoint(self) -> coincurve.PublicKey:
        return coincurve.PublicKey.from_secret(self.payment_base_secret.secret)

    def payment_basepoint(self) -> str:
        return self.raw_payment_basepoint().format().hex()

    def raw_revocation_basepoint(self) -> coincurve.PublicKey:
        return coincurve.PublicKey.from_secret(self.revocation_base_secret.secret)

    def revocation_basepoint(self) -> str:
        return self.raw_revocation_basepoint().format().hex()

    def raw_delayed_payment_basepoint(self) -> coincurve.PublicKey:
        return coincurve.PublicKey.from_secret(self.delayed_payment_base_secret.secret)

    def delayed_payment_basepoint(self) -> str:
        return self.raw_delayed_payment_basepoint().format().hex()

    def raw_htlc_basepoint(self) -> coincurve.PublicKey:
        return coincurve.PublicKey.from_secret(self.htlc_base_secret.secret)

    def htlc_basepoint(self) -> str:
        return self.raw_htlc_basepoint().format().hex()

    def raw_per_commit_secret(self, n: int) -> coincurve.PrivateKey:
        # BOLT #3:
        # The first secret used:
        #  - MUST be index 281474976710655,
        #    - and from there, the index is decremented.
        if n > 281474976710655:
            raise ValueError("48 bits is all you get!")
        index = 281474976710655 - n

        # BOLT #3:
        # generate_from_seed(seed, I):
        #     P = seed
        #     for B in 47 down to 0:
        #         if B set in I:
        #             flip(B) in P
        #             P = SHA256(P)
        #     return P
        # ```

        # FIXME: This is the updated wording from PR #779
        # Where "flip(B)" alternates the (B mod 8)'th bit of the (B div 8)'th
        # byte of the value.  So, "flip(0) in e3b0..." is "e2b0...", and
        # "flip(10) in "e3b0..." is "e3b4".
        P = bytearray(self.shachain_seed)
        for B in range(47, -1, -1):
            if ((1 << B) & index) != 0:
                P[B // 8] ^= 1 << (B % 8)
                P = bytearray(hashlib.sha256(P).digest())

        return coincurve.PrivateKey(P)

    def per_commit_secret(self, n: int) -> str:
        return self.raw_per_commit_secret(n).secret.hex()

    def raw_per_commit_point(self, n: int) -> coincurve.PublicKey:

        return coincurve.PublicKey.from_secret(self.raw_per_commit_secret(n).secret)

    def per_commit_point(self, n: int) -> str:
        return self.raw_per_commit_point(n).format().hex()


def test_shachain() -> None:
    # BOLT #3:
    # ## Generation Tests
    # name: generate_from_seed 0 final node
    # seed: 0x0000000000000000000000000000000000000000000000000000000000000000
    # I: 281474976710655
    # output: 0x02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148
    keyset = KeySet(
        "01",
        "01",
        "01",
        "01",
        "0000000000000000000000000000000000000000000000000000000000000000",
    )
    assert (
        keyset.per_commit_secret(0xFFFFFFFFFFFF - 281474976710655)
        == "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"
    )

    # BOLT #3:
    # name: generate_from_seed FF final node
    # seed: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # I: 281474976710655
    # output: 0x7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc
    keyset = KeySet(
        "01",
        "01",
        "01",
        "01",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    )
    assert (
        keyset.per_commit_secret(0xFFFFFFFFFFFF - 281474976710655)
        == "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"
    )

    # BOLT #3:
    # name: generate_from_seed FF alternate bits 1
    # seed: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # I: 0xaaaaaaaaaaa
    # output: 0x56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528
    keyset = KeySet(
        "01",
        "01",
        "01",
        "01",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    )
    assert (
        keyset.per_commit_secret(0xFFFFFFFFFFFF - 0xAAAAAAAAAAA)
        == "56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"
    )

    # BOLT #3:
    # name: generate_from_seed FF alternate bits 2
    # seed: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # I: 0x555555555555
    # output: 0x9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31
    keyset = KeySet(
        "01",
        "01",
        "01",
        "01",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
    )
    assert (
        keyset.per_commit_secret(0xFFFFFFFFFFFF - 0x555555555555)
        == "9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"
    )

    # BOLT #3:
    # name: generate_from_seed 01 last nontrivial node
    # seed: 0x0101010101010101010101010101010101010101010101010101010101010101
    # I: 1
    # output: 0x915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c
    keyset = KeySet(
        "01",
        "01",
        "01",
        "01",
        "0101010101010101010101010101010101010101010101010101010101010101",
    )
    assert (
        keyset.per_commit_secret(0xFFFFFFFFFFFF - 1)
        == "915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"
    )
