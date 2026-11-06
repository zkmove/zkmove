module cases::test_abort {
    public entry fun test_abort() {
        assert!(3 == 3, 101);
        assert!(3 == 4, 102);
    }
}
