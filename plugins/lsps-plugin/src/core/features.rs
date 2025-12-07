use core::fmt;

/// Checks whether a feature bit is set in a bitmap interpreted as
/// **big-endian across bytes**, while keeping **LSB-first within each byte**.
///
/// This function creates a reversed copy of `bitmap` (so the least-significant
/// byte becomes last), then calls the simple LSB-first `is_feature_bit_set` on it.
/// No mutation of the caller’s slice occurs.
///
/// In other words:
/// - byte order: **reversed** (big-endian across the slice)
/// - bit order within a byte: **LSB-first** (unchanged)
///
/// If you need *full* MSB-first (also within a byte), don’t use this helper—
/// rewrite the mask as `1u8 << (7 - bit_index)` instead.
///
/// # Arguments
/// * `bitmap` – byte slice containing the bitfield (original order, not modified)
/// * `feature_bit` – zero-based bit index across the entire bitmap
///
/// # Returns
/// `true` if the bit is set; `false` if the bit is unset or out of bounds
pub fn is_feature_bit_set_reversed(bitmap: &[u8], feature_bit: usize) -> bool {
    let mut reversed = bitmap.to_vec();
    reversed.reverse();
    is_feature_bit_set(&reversed, feature_bit)
}

/// Checks if the feature bit is set in the provided bitmap.
/// Returns true if the `feature_bit` is set in the `bitmap`. Returns false if
/// the `feature_bit` is unset or our ouf bounds.
///
/// # Arguments
///
/// * `bitmap`: A slice of bytes representing the feature bitmap.
/// * `feature_bit`: The 0-based index of the bit to check across the bitmap.
///
pub fn is_feature_bit_set(bitmap: &[u8], feature_bit: usize) -> bool {
    let byte_index = feature_bit >> 3; // Equivalent to feature_bit / 8
    let bit_index = feature_bit & 7; // Equivalent to feature_bit % 8

    if let Some(&target_byte) = bitmap.get(byte_index) {
        let mask = 1 << bit_index;
        (target_byte & mask) != 0
    } else {
        false
    }
}

/// Returns a single feature_bit in hex representation, least-significant bit
/// first.
///
/// # Arguments
///
/// * `feature_bit`: The 0-based index of the bit to check across the bitmap.
///
pub fn feature_bit_to_hex(feature_bit: usize) -> String {
    let byte_index = feature_bit >> 3; // Equivalent to feature_bit / 8
    let mask = 1 << (feature_bit & 7); // Equivalent to feature_bit % 8
    let mut map = vec![0u8; byte_index + 1];
    map[0] |= mask; // least-significant bit first ordering.
    hex::encode(&map)
}

/// Errors that can occur when unwrapping payload data
#[derive(Debug, Clone, PartialEq)]
pub enum UnwrapError {
    /// The public key bytes are invalid
    InvalidPublicKey(String),
    /// Failed to deserialize json value,
    SerdeFailure(String),
}

impl fmt::Display for UnwrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UnwrapError::InvalidPublicKey(e) => {
                write!(f, "Invalid public key: {}", e)
            }
            UnwrapError::SerdeFailure(e) => {
                write!(f, "Failed to serialize or deserialize json value: {}", e)
            }
        }
    }
}

impl std::error::Error for UnwrapError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_bit_checks() {
        // Example bitmap:
        // Byte 0: 0b10100101 (165) -> Bits 0, 2, 5, 7 set
        // Byte 1: 0b01101010 (106) -> Bits 1, 3, 5, 6 set (indices 9, 11, 13, 14)
        let bitmap: &[u8] = &[0b10100101, 0b01101010];

        // Check bits in byte 0 (indices 0-7)
        assert_eq!(is_feature_bit_set(bitmap, 0), true); // Bit 0
        assert_eq!(is_feature_bit_set(bitmap, 1), false); // Bit 1
        assert_eq!(is_feature_bit_set(bitmap, 2), true); // Bit 2
        assert_eq!(is_feature_bit_set(bitmap, 3), false); // Bit 3
        assert_eq!(is_feature_bit_set(bitmap, 4), false); // Bit 4
        assert_eq!(is_feature_bit_set(bitmap, 5), true); // Bit 5
        assert_eq!(is_feature_bit_set(bitmap, 6), false); // Bit 6
        assert_eq!(is_feature_bit_set(bitmap, 7), true); // Bit 7

        // Check bits in byte 1 (indices 8-15)
        assert_eq!(is_feature_bit_set(bitmap, 8), false); // Bit 8 (Byte 1, bit 0)
        assert_eq!(is_feature_bit_set(bitmap, 9), true); // Bit 9 (Byte 1, bit 1)
        assert_eq!(is_feature_bit_set(bitmap, 10), false); // Bit 10 (Byte 1, bit 2)
        assert_eq!(is_feature_bit_set(bitmap, 11), true); // Bit 11 (Byte 1, bit 3)
        assert_eq!(is_feature_bit_set(bitmap, 12), false); // Bit 12 (Byte 1, bit 4)
        assert_eq!(is_feature_bit_set(bitmap, 13), true); // Bit 13 (Byte 1, bit 5)
        assert_eq!(is_feature_bit_set(bitmap, 14), true); // Bit 14 (Byte 1, bit 6)
        assert_eq!(is_feature_bit_set(bitmap, 15), false); // Bit 15 (Byte 1, bit 7)
    }

    #[test]
    fn test_out_of_bounds() {
        let bitmap: &[u8] = &[0b11111111, 0b00000000]; // 16 bits total

        assert_eq!(is_feature_bit_set(bitmap, 15), false); // Last valid bit (is 0)
        assert_eq!(is_feature_bit_set(bitmap, 16), false); // Out of bounds
        assert_eq!(is_feature_bit_set(bitmap, 100), false); // Way out of bounds
    }

    #[test]
    fn test_empty_bitmap() {
        let bitmap: &[u8] = &[];
        assert_eq!(is_feature_bit_set(bitmap, 0), false);
        assert_eq!(is_feature_bit_set(bitmap, 8), false);
    }

    #[test]
    fn test_feature_to_hex_bit_0_be() {
        // Bit 0 is in Byte 0 (LE index). num_bytes=1. BE index = 1-1-0=0.
        // Expected map: [0x01]
        let feature_hex = feature_bit_to_hex(0);
        assert_eq!(feature_hex, "01");
        assert!(is_feature_bit_set(&hex::decode(feature_hex).unwrap(), 0));
    }

    #[test]
    fn test_feature_to_hex_bit_8_be() {
        // Bit 8 is in Byte 1 (LE index). num_bytes=2. BE index = 2-1-1=0.
        // Mask is 0x01 for bit 0 within its byte.
        // Expected map: [0x01, 0x00] (Byte for 8-15 first, then 0-7)
        let feature_hex = feature_bit_to_hex(8);
        let mut decoded = hex::decode(&feature_hex).unwrap();
        decoded.reverse();
        assert_eq!(feature_hex, "0100");
        assert!(is_feature_bit_set(&decoded, 8));
    }

    #[test]
    fn test_feature_to_hex_bit_27_be() {
        // Bit 27 is in Byte 3 (LE index). num_bytes=4. BE index = 4-1-3=0.
        // Mask is 0x08 for bit 3 within its byte.
        // Expected map: [0x08, 0x00, 0x00, 0x00] (Byte for 24-31 first)
        let feature_hex = feature_bit_to_hex(27);
        let mut decoded = hex::decode(&feature_hex).unwrap();
        decoded.reverse();
        assert_eq!(feature_hex, "08000000");
        assert!(is_feature_bit_set(&decoded, 27));
    }
}
