module cases::test_hash {
    public entry fun test_hash() {
        // This function uses the zkhash module to compute a hash
        // of two u128 values and returns a u256 result.
        let arg1 = 123u128;
        let arg2 = 45u128;
        let expected_output = 5396936627018144388256392133700981730161373533767880136248396757995540825894u256;
        let result = std::zkhash::hash(arg1, arg2);
        assert!(result == expected_output, 0);
    }
}
