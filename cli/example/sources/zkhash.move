module 0x1::zkhash_example {
    use std::zkhash;

    public entry fun hash() {
        let arg1 = 123u128;
        let arg2 = 45u128;
        let expected_output = 0xbee8ed1516c551209fea89c0699dbba6315e0af2eadf48004456c21afe1c726;
        let result = zkhash::hash(arg1, arg2);
        assert!(result == expected_output, 0);
    }
}