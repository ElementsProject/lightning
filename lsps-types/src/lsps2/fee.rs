/// Computes the opening fee in millisatoshis as described in LSPS2.
/// Returns None if an arithmetic overflow occurs during calculation.
///
/// # Arguments
/// * `payment_size_msat` - The size of the payment for which the channel is
///   being opened.
/// * `opening_fee_min_fee_msat` - The minimum fee to be paid by the client to
///   the LSP
/// * `opening_fee_proportional` - The proportional fee charged by the LSP
pub fn compute_opening_fee(
    payment_size_msat: u64,
    opening_fee_min_fee_msat: u64,
    opening_fee_proportional: u64,
) -> Option<u64> {
    payment_size_msat
        .checked_mul(opening_fee_proportional)
        .and_then(|f| f.checked_add(999999))
        .and_then(|f| f.checked_div(1000000))
        .map(|f| std::cmp::max(f, opening_fee_min_fee_msat))
}
