module confidential_asset::off_chain {
    use std::zkhash;

    const E_INVALID_ENCRYPTION: u64 = 0;
    const E_INVALID_INPUT: u64 = 1;

    public entry fun encrypt(value: u128, encrypted: u256) {
        assert!(zkhash::hash(value, 0u128) == encrypted, E_INVALID_ENCRYPTION);
    }

    public entry fun check_sum(x: u128, y: u128, sum: u128, encrypted_x: u256, encrypted_y: u256, encrypted_sum: u256) {
        assert!(x + y == sum, E_INVALID_INPUT);
        assert!(zkhash::hash(x, 0u128) == encrypted_x, E_INVALID_ENCRYPTION);
        assert!(zkhash::hash(y, 0u128) == encrypted_y, E_INVALID_ENCRYPTION);
        assert!(zkhash::hash(sum, 0u128) == encrypted_sum, E_INVALID_ENCRYPTION);
    }
}
