module dark_forest::coords_hash {
    use std::zkhash;

    const E_INVALID_COORDINATES: u64 = 0;

    /// Verify that the given coordinates hash to the given hash
    /// pi: hash
    public entry fun check_coords_hash(x: u128, y: u128, hash: u256) {
        assert!(zkhash::hash(x, y) == hash, E_INVALID_COORDINATES);
    }
}