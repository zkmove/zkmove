pub mod zkhash {
    use move_core_types::u256::U256;

    /// FIXME: This is a fake hash function for testing purposes.
    pub fn fake_hash(arg1: u128, arg2: u128) -> U256 {
        let mut hash_vec = [0u8; 32];
        hash_vec[0..16].copy_from_slice(&arg1.to_le_bytes());
        hash_vec[16..32].copy_from_slice(&arg2.to_le_bytes());
        let hash_val = U256::from_le_bytes(&hash_vec);
        hash_val
    }
}
