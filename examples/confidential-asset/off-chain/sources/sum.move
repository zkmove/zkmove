module confidential_asset::sum {
    use std::zkhash;

    const E_INVALID_ENCRYPTION: u64 = 0;
    const E_INVALID_INPUT: u64 = 1;

    // public input: encrypted_x, encrypted_y, encrypted_sum
    public entry fun check_sum(
        x: u128,
        y: u128,
        sum: u128,
        encrypted_x: u256,
        encrypted_y: u256,
        encrypted_sum: u256,
        nonce_x: u128,
        nonce_y: u128,
        nonce_sum: u128
    ) {
        assert!(x + y == sum, E_INVALID_INPUT);
        assert!(zkhash::hash(x, nonce_x) == encrypted_x, E_INVALID_ENCRYPTION);
        assert!(zkhash::hash(y, nonce_y) == encrypted_y, E_INVALID_ENCRYPTION);
        assert!(zkhash::hash(sum, nonce_sum) == encrypted_sum, E_INVALID_ENCRYPTION);
    }
}
