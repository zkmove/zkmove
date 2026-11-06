module cases::test_comp {
    public entry fun test_comp(a: u64, b: u64, c: u64, d: u64, e: u256) {
        let m = a >= b;
        assert!(m == false, 101);
        let n = b > a;
        assert!(n == true, 102);
        let o = d < c;
        assert!(o == false, 103);
        let p = d <= c;
        assert!(p == true, 104);

        assert!(e >= 3u256, 105);
        assert!(e > 3u256, 106);
        assert!(3u256 < e, 107);
        assert!(3u256 <= e, 108);
    }
}
