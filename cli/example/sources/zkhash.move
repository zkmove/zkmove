module 0x1::zkhash_example {
    use std::zkhash;

    public entry fun hash() {
        let arg1 = 123u128;
        let arg2 = 45u128;
        let expected_output = 5396936627018144388256392133700981730161373533767880136248396757995540825894u256;
        let result = zkhash::hash(arg1, arg2);
        assert!(result == expected_output, 0);
    }
}