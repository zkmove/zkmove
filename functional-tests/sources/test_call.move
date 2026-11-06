module cases::test_call {
    public entry fun test_call() {
        test_call_(2);
    }

    public fun test_call_(i: u8) {
        if (i > 0) {
            test_call_(i - 1);
        };
    }
}
