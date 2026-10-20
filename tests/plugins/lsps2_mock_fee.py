"""The LSPS2 opening fee, written from the bLIP-52 text.

Used by the mock LSPS2 service (lsps2_mock.py) and by the tests to compute
expected values. It is deliberately not derived from any other
implementation in this repository: if the client and the mock shared the
fee code, a bug in it would go unnoticed.

bLIP-52, "Computing The `opening_fee`":

    opening_fee = ((payment_size_msat * proportional) + 999999) / 10000000
    if opening_fee < min_fee_msat:
        opening_fee = min_fee_msat

    * All numbers MUST be computed in unsigned 64-bit integers.
      * Clients and LSPs MAY use arbitrary-precision integers [...] IF AND
        ONLY IF they check for overflow of unsigned 64-bit at each basic
        arithmetic operation.
    * Integer division MUST round down; the `+ 9999999` causes this to
      round up.
    * Arithmetic overflow MUST cause the computation to fail and abort
      this flow [...]
      * The check MUST be done on EACH addition and multiplication
        operation, including those with constants.

Two constants above are typos: `proportional` is defined in parts per
million, and the spec's own C and Rust versions add 999999 and divide by
1000000, which is what this module does.
"""

U64_MAX = 2**64 - 1


class FeeOverflow(ArithmeticError):
    """The computation left the unsigned 64-bit range."""


def _checked(n):
    if n > U64_MAX:
        raise FeeOverflow(n)
    return n


def opening_fee(payment_size_msat, min_fee_msat, proportional):
    """Return the opening fee in msat; raise FeeOverflow on overflow."""
    for n in (payment_size_msat, min_fee_msat, proportional):
        if not 0 <= n <= U64_MAX:
            raise ValueError(f"{n} is not an unsigned 64-bit integer")
    product = _checked(payment_size_msat * proportional)
    fee = _checked(product + 999_999) // 1_000_000
    return max(fee, min_fee_msat)
