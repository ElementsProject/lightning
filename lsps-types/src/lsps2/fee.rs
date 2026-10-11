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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn rounds_up_to_the_next_msat() {
        // The proportional part is above min_fee_msat (0) in all cases.
        // product = payment_size * proportional
        for (payment_size, proportional, fee) in [
            (0, 1_000, 0),                   // product 0
            (1, 1, 1),                       // product 1
            (999_999, 1, 1),                 // product 10^6 - 1
            (1_000_000, 1, 1),               // product 10^6
            (1_000_001, 1, 2),               // product 10^6 + 1
            (1_999_999, 1, 2),               // product 2*10^6 - 1
            (2_000_000, 1, 2),               // product 2*10^6
            (2_000_001, 1, 3),               // product 2*10^6 + 1
            (1_000, 1_000_000, 1_000),       // product 10^9
            (1_001, 999_999, 1_001),         // product 10^9 - 1 + 1001 - 1000
            (500_000_000, 2_000, 1_000_000), // product 10^12
            (500_000_001, 2_000, 1_000_001), // product 10^12 + 2000
        ] {
            assert_eq!(
                compute_opening_fee(payment_size, 0, proportional),
                Some(fee),
                "payment_size={payment_size} proportional={proportional}"
            );
        }
    }

    #[test]
    fn min_fee_is_a_floor() {
        // Proportional part: ceil(10_000_000 * 1_000 / 10^6) = 10_000.
        assert_eq!(compute_opening_fee(10_000_000, 9_999, 1_000), Some(10_000));
        assert_eq!(compute_opening_fee(10_000_000, 10_000, 1_000), Some(10_000));
        assert_eq!(compute_opening_fee(10_000_000, 10_001, 1_000), Some(10_001));
        // Rounding happens before the floor is applied.
        assert_eq!(compute_opening_fee(10_000_001, 10_000, 1_000), Some(10_001));
        assert_eq!(compute_opening_fee(0, 546_000, 1_200), Some(546_000));
        assert_eq!(compute_opening_fee(0, u64::MAX, 0), Some(u64::MAX));
    }

    #[test]
    fn multiplication_overflow_fails() {
        assert_eq!(compute_opening_fee(u64::MAX, 0, 2), None);
        assert_eq!(compute_opening_fee(2, 0, u64::MAX), None);
        assert_eq!(compute_opening_fee(u64::MAX / 2 + 1, 0, 2), None);
        assert_eq!(compute_opening_fee(u64::MAX, 0, u64::from(u32::MAX)), None);
        // The product u64::MAX - 1 fits, but adding 999_999 does not.
        assert_eq!(compute_opening_fee(u64::MAX / 2, 0, 2), None);
        // Product u64::MAX - 10^6: multiplication and addition both fit.
        assert_eq!(
            compute_opening_fee((u64::MAX - 999_999) / 5, 0, 5),
            Some(u64::MAX / 1_000_000)
        );
    }

    #[test]
    fn addition_overflow_fails() {
        // The product fits, adding 999_999 does not.
        assert_eq!(compute_opening_fee(u64::MAX - 999_998, 0, 1), None);
        assert_eq!(compute_opening_fee(u64::MAX, 0, 1), None);
        // u64::MAX / 10^6 * 10^6 fits, + 999_999 is above u64::MAX.
        assert_eq!(
            compute_opening_fee(u64::MAX / 1_000_000, 0, 1_000_000),
            None
        );
        // The largest product that does not overflow.
        assert_eq!(
            compute_opening_fee(u64::MAX - 999_999, 0, 1),
            Some(u64::MAX / 1_000_000)
        );
        // An overflow fails even if min_fee_msat would dominate.
        assert_eq!(compute_opening_fee(u64::MAX, u64::MAX, 1), None);
    }

    #[test]
    fn zero_proportional_is_min_fee() {
        assert_eq!(compute_opening_fee(u64::MAX, 1_000, 0), Some(1_000));
    }

    /// Independent reference: exact arithmetic in u128, then the u64
    /// overflow rule from the spec.
    fn reference(payment_size: u64, min_fee: u64, proportional: u64) -> Option<u64> {
        let sum = u128::from(payment_size) * u128::from(proportional) + 999_999;
        if sum > u128::from(u64::MAX) {
            return None;
        }
        let fee = u64::try_from(sum / 1_000_000).unwrap();
        Some(fee.max(min_fee))
    }

    proptest! {
        #[test]
        fn matches_u128_reference(
            payment_size in any::<u64>(),
            min_fee in any::<u64>(),
            proportional in any::<u64>(),
        ) {
            prop_assert_eq!(
                compute_opening_fee(payment_size, min_fee, proportional),
                reference(payment_size, min_fee, proportional)
            );
        }

        #[test]
        fn matches_u128_reference_realistic(
            payment_size in 0u64..=21_000_000 * 100_000_000_000,
            min_fee in 0u64..=100_000_000,
            proportional in 0u64..=u64::from(u32::MAX),
        ) {
            prop_assert_eq!(
                compute_opening_fee(payment_size, min_fee, proportional),
                reference(payment_size, min_fee, proportional)
            );
        }

        #[test]
        fn is_ceiling_of_proportional_part(
            // Small enough that payment_size * 10^6 + 999_999 fits in u64.
            payment_size in 0u64..u64::MAX / 1_000_000,
            proportional in 0u64..=1_000_000,
        ) {
            let fee = compute_opening_fee(payment_size, 0, proportional).unwrap();
            let product = u128::from(payment_size) * u128::from(proportional);
            // fee is the smallest integer with fee * 10^6 >= product.
            prop_assert!(u128::from(fee) * 1_000_000 >= product);
            prop_assert!(fee == 0 || (u128::from(fee) - 1) * 1_000_000 < product);
        }
    }
}
