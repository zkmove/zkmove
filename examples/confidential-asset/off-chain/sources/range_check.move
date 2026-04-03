module confidential_asset::range_check {
    use std::zkhash;

    const E_INVALID_ENCRYPTION: u64 = 0;
    const E_INVALID_INPUT: u64 = 1;

    // public input: min, max, encrypted_value
    public entry fun check_range(
        value: u128,
        min: u128,
        max: u128,
        encrypted_value: u256,
        nonce: u128
    ) {
        assert!(value >= min && value <= max, E_INVALID_INPUT);
        assert!(zkhash::hash(value, nonce) == encrypted_value, E_INVALID_ENCRYPTION);
    }
}