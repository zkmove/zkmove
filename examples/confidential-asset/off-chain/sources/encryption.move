module confidential_asset::encryption {
    use std::zkhash;

    const E_INVALID_ENCRYPTION: u64 = 0;

    // public input: encrypted_value
    public entry fun encrypt(value: u128, encrypted_value: u256, nonce: u128) {
        assert!(zkhash::hash(value, nonce) == encrypted_value, E_INVALID_ENCRYPTION);
    }
}
