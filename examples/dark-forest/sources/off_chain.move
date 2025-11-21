module dark_forest::off_chain {
    use std::zkhash;

    const E_INVALID_COORDINATES: u64 = 0;

    /// Verify that the given coordinates hash to the given hash
    /// pi: hash
    public entry fun coord_hash(x: u128, y: u128, hash: u256) {
        assert!(zkhash::hash(x, y) == hash, E_INVALID_COORDINATES);
    }

    /// Euclidean distance squared (no sqrt needed)
    /// pi: hash_1, hash_2, expected_dist_sq
    public entry fun euclidean_distance(x1: u128, y1: u128, x2: u128, y2: u128, hash_1: u256, hash_2: u256, distance_squared: u128) {
        assert!(zkhash::hash(x1, y1) == hash_1, E_INVALID_COORDINATES);
        assert!(zkhash::hash(x2, y2) == hash_2, E_INVALID_COORDINATES);
        let dx = if x1 > x2 { x1 - x2 } else { x2 - x1 };
        let dy = if y1 > y2 { y1 - y2 } else { y2 - y1 };
        let expected_distance_squared = dx * dx + dy * dy;
        assert!( distance_squared == expected_distance_squared, E_INVALID_COORDINATES);
    }
}
