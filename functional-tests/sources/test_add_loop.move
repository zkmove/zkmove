module cases::test_add_loop {
    public entry fun test_add_loop() {
        let i = 10u64;
        let t = 0;
        loop {
            t = t + i;
            if (i == 0) {
                break
            };
            i = i - 1;
        }
    }
}
