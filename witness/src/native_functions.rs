pub mod zkhash {
    use halo2curves::bn256::Fr;
    use halo2curves::ff::PrimeField;
    use move_core_types::u256::U256;
    pub const DOMAIN_SPEC: u64 = 1; // Domain spec for Poseidon hash

    /// FIXME: This is a fake hash function for testing purposes.
    pub fn poseidon_hash(arg1: u128, arg2: u128) -> U256 {
        let hash_result = poseidon_base::Hashable::hash_with_domain(
            [Fr::from_u128(arg1), Fr::from_u128(arg2)],
            Fr::from(DOMAIN_SPEC),
        );
        let hash_val = U256::from_le_bytes(&hash_result.to_repr().as_ref().try_into().unwrap());
        hash_val
    }
}
