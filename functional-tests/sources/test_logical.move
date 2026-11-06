module cases::test_logical {
    public entry fun test_logical(a: bool, b: bool) {
        if (a != b) {
            a;
        };
        let c = a && b;
        assert!(c == false, 101);
        let d = a || b;
        assert!(d == true, 102);
        let e = !a;
        assert!(e == false, 103);
    }
}
