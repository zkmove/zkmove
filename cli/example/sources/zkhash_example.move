module 0x1::zkhash_example {
    use std::zkhash;

    public entry fun fake_hash_example() {
        // This function uses the zkhash module to compute a hash
        // of two u128 values and returns a u256 result.
        let arg1 = 123u128;
        let arg2 = 45u128;
        let expected_output = 15312706511442230855851857334429569515643u256;
        let fake_result = zkhash::fake_hash(arg1, arg2);
        assert!(fake_result == expected_output, 0);
    }
}