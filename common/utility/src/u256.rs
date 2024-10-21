// Copyright (c) zkMove Authors

pub use move_core_types::u256;
pub use move_core_types::u256::U256;
use move_vm_runtime::witnessing::traced_value::Integer;

pub fn pair_u128_to_u256(lo: u128, hi: u128) -> U256 {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&lo.to_le_bytes());
    bytes[16..].copy_from_slice(&hi.to_le_bytes());
    U256::from_le_bytes(&bytes)
}
pub fn split_u256_to_u128(input: U256) -> (u128, u128) {
    let bytes = input.to_le_bytes();
    let lo = u128::from_le_bytes(bytes[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(bytes[16..].try_into().unwrap());
    (lo, hi)
}

/// Returns tuple consists of low and high part of U256
pub fn split_u256(value: &U256) -> (U256, U256) {
    let mask = U256::from(u128::MAX);
    let lo = *value & mask;
    let hi = (*value >> 128) & mask;
    (hi, lo)
}

/// Split a U256 value into 4 64-bit limbs stored in U256 values.
pub fn split_u256_limb64(value: &U256) -> [U256; 4] {
    let mask = U256::from(u64::MAX);
    [
        *value & mask,
        (*value >> 64) & mask,
        (*value >> 128) & mask,
        (*value >> 192) & mask,
    ]
}

pub trait ToU256 {
    fn to_u256(&self) -> U256;
}

impl ToU256 for Integer {
    fn to_u256(&self) -> U256 {
        match self {
            Integer::U8(v) => U256::from(*v),
            Integer::U16(v) => U256::from(*v),
            Integer::U32(v) => U256::from(*v),
            Integer::U64(v) => U256::from(*v),
            Integer::U128(v) => U256::from(*v),
            Integer::U256(v) => *v,
        }
    }
}

#[cfg(test)]
mod tests {
    use move_core_types::u256::U256;

    #[test]
    fn test_overflowing_sub() {
        let a = U256::from(0u8);
        let b = U256::max_value();
        let c = U256::from(1u8);
        assert_eq!(U256::wrapping_sub(a, b), c);

        let a = U256::from(0u8);
        let b = U256::from(1u8);
        let c = U256::max_value();
        assert_eq!(U256::wrapping_sub(a, b), c);
    }
}
