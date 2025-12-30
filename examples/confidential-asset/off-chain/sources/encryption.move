module confidential_asset::encryption {
    use std::zkhash;

    const E_INVALID_ENCRYPTION: u64 = 0;

    // public input: value, encrypted
    public entry fun encrypt(value: u128, encrypted: u256, nonce: u128) {
        assert!(zkhash::hash(value, nonce) == encrypted, E_INVALID_ENCRYPTION);
    }
}
