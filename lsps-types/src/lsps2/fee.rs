/// Computes the LSPS2 opening fee in millisatoshis. Returns `None` if an
/// arithmetic operation overflows.
///
/// This is the one opening fee computation shared by LSPS2 clients and
/// LSPs. bLIP-52, "Computing The `opening_fee`":
///
/// > For a given `payment_size_msat` (in millisatoshis) and a selected
/// > `opening_fee_params` object, both client and LSP MUST compute the
/// > `opening_fee` (in millisatoshis) as follows:
/// >
/// > ```text
/// > opening_fee = ((payment_size_msat * proportional) + 999999) / 10000000
/// > if opening_fee < min_fee_msat:
/// >     opening_fee = min_fee_msat
/// > ```
/// >
/// > * All numbers MUST be computed in unsigned 64-bit integers.
/// > * Integer division MUST round down; the `+ 9999999` causes this to
/// >   round up.
/// > * Arithmetic overflow MUST cause the computation to fail and abort
/// >   this flow [...]
///
/// The divisor `10000000` and the `+ 9999999` in the quote are typos: the
/// spec's own C and Rust reference implementations divide by `1000000` and
/// add `999999`, and `proportional` is defined in parts per million ("how
/// many millisatoshis to charge for every 1 million millisatoshis of
/// payment size"). This follows the reference implementations, so the
/// proportional part is `payment_size_msat * proportional / 1_000_000`
/// rounded up.
///
/// # Arguments
/// * `payment_size_msat` - The size of the payment for which the channel is
///   being opened.
/// * `opening_fee_min_fee_msat` - `opening_fee_params.min_fee_msat`.
/// * `opening_fee_proportional` - `opening_fee_params.proportional`, in
///   parts per million.
pub fn compute_opening_fee(
    payment_size_msat: u64,
    opening_fee_min_fee_msat: u64,
    opening_fee_proportional: u64,
) -> Option<u64> {
    let fee = payment_size_msat
        .checked_mul(opening_fee_proportional)?
        .checked_add(999_999)?
        / 1_000_000;
    Some(fee.max(opening_fee_min_fee_msat))
}
