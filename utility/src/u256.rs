// Copyright (c) zkMove Authors

pub use move_core_types::u256;
pub use move_core_types::u256::U256;

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
